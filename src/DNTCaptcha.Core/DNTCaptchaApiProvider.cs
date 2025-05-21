using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Dynamic.Core.Tokenizer;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Phaa.AzmoonOnline.App;
using static System.FormattableString;

namespace DNTCaptcha.Core;

/// <summary>
///     DNTCaptcha Api
/// </summary>
/// <remarks>
///     DNTCaptcha Api
/// </remarks>
public class DNTCaptchaApiProvider(
    ICaptchaCryptoProvider captchaProtectionProvider,
    IRandomNumberProvider randomNumberProvider,
    Func<DisplayMode, ICaptchaTextProvider> captchaTextProvider,
    ICaptchaStorageProvider captchaStorageProvider,
    ISerializationProvider serializationProvider,
    IHttpContextAccessor httpContextAccessor,
    IUrlHelper urlHelper,
    IDistributedCache distributedCache, //mmm
    DntCaptchaSettings dntCaptchaSettings, //mmm
    IOptions<DNTCaptchaOptions> options) : IDNTCaptchaApiProvider
{
    private readonly DNTCaptchaOptions _captchaOptions =
        options == null ? throw new ArgumentNullException(nameof(options)) : options.Value;

    private readonly ICaptchaCryptoProvider _captchaProtectionProvider = captchaProtectionProvider ??
                                                                         throw new ArgumentNullException(
                                                                             nameof(captchaProtectionProvider));

    private readonly ICaptchaStorageProvider _captchaStorageProvider =
        captchaStorageProvider ?? throw new ArgumentNullException(nameof(captchaStorageProvider));

    private readonly Func<DisplayMode, ICaptchaTextProvider> _captchaTextProvider =
        captchaTextProvider ?? throw new ArgumentNullException(nameof(captchaTextProvider));

    private readonly IHttpContextAccessor _httpContextAccessor =
        httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));

    private readonly IRandomNumberProvider _randomNumberProvider =
        randomNumberProvider ?? throw new ArgumentNullException(nameof(randomNumberProvider));

    private readonly ISerializationProvider _serializationProvider =
        serializationProvider ?? throw new ArgumentNullException(nameof(serializationProvider));

    private readonly IUrlHelper _urlHelper = urlHelper ?? throw new ArgumentNullException(nameof(urlHelper));

    //mmm
    private const string SecretCacheKeyPrefix = ".CaptchaSecret:";
    private readonly IDistributedCache _distributedCache =
        distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
    private readonly DntCaptchaSettings _dntCaptchaSettings =
        dntCaptchaSettings ?? throw new ArgumentNullException(nameof(dntCaptchaSettings));
    private static Random Rnd = new Random();

    /// <summary>
    ///     Creates DNTCaptcha
    /// </summary>
    /// <param name="captchaAttributes">captcha attributes</param>
    public DNTCaptchaApiResponse CreateDNTCaptcha(DNTCaptchaTagHelperHtmlAttributes captchaAttributes)
    {
        using var span = Diag.Span("CreateDNTCaptcha", "captcha");

        if (captchaAttributes == null)
        {
            throw new ArgumentNullException(nameof(captchaAttributes));
        }

        if (_httpContextAccessor.HttpContext == null)
        {
            throw new InvalidOperationException(message: "`_httpContextAccessor.HttpContext` is null.");
        }

        var png = _dntCaptchaSettings.PngPercent > 0 && Rnd.Next(100) < _dntCaptchaSettings.PngPercent; //mmm

        var number = _randomNumberProvider.NextNumber(captchaAttributes.Min, captchaAttributes.Max);

        var randomText = _captchaTextProvider(captchaAttributes.DisplayMode)
            .GetText(number, captchaAttributes.Language);

        var encryptedText = _captchaProtectionProvider.Encrypt(randomText);
        var pngEncryptedText = png ? _captchaProtectionProvider.Encrypt(randomText, png) : encryptedText;
        var captchaImageUrl = GetCaptchaImageUrl(captchaAttributes, pngEncryptedText, png);

        var captchaDivId =
            Invariant(
                $"{_captchaOptions.CaptchaClass}{Guid.NewGuid():N}{_randomNumberProvider.NextNumber(captchaAttributes.Min, captchaAttributes.Max)}");

        var cookieToken = $".{captchaDivId}";
        var hiddenInputToken = _captchaProtectionProvider.Encrypt(cookieToken);

        var value = number.ToString(CultureInfo.InvariantCulture);
        var encryptedValue = _captchaProtectionProvider.Encrypt(value);
        _captchaStorageProvider.Add(_httpContextAccessor.HttpContext, cookieToken, value);

        return new DNTCaptchaApiResponse
        {
            DntCaptchaImgUrl = captchaImageUrl,
            DntCaptchaId = captchaDivId,
            DntCaptchaTextValue = encryptedValue,
            DntCaptchaTokenValue = hiddenInputToken
        };
    }

    private string GetCaptchaImageUrl(DNTCaptchaTagHelperHtmlAttributes captchaAttributes, string encryptedText, bool png)
    {
        using var span = Diag.Span("GetCaptchaImageUrl", "captcha");

        if (_httpContextAccessor.HttpContext == null)
        {
            throw new InvalidOperationException(message: "`_httpContextAccessor.HttpContext` is null.");
        }

        var values = new CaptchaImageParams
        {
            Text = encryptedText,
            RndDate = GetRndDate(captchaAttributes, png),
            ForeColor = captchaAttributes.ForeColor,
            BackColor = captchaAttributes.BackColor,
            FontSize = captchaAttributes.FontSize,
            FontName = captchaAttributes.FontName
        };

        var encryptSerializedValues = _captchaProtectionProvider.Encrypt(_serializationProvider.Serialize(values), png);

        var controllerName = nameof(DNTCaptchaImageController)
            .Replace(oldValue: "Controller", string.Empty, StringComparison.Ordinal);

        if (!string.IsNullOrEmpty(_captchaOptions.CaptchaImageControllerNameTemplate))
        {
            controllerName = _captchaOptions.CaptchaImageControllerNameTemplate;
        }

        var actionUrl = captchaAttributes.UseRelativeUrls
            ? _urlHelper.Action(nameof(DNTCaptchaImageController.Show), controllerName, new
            {
                data = encryptSerializedValues,
                area = ""
            })
            : _urlHelper.Action(nameof(DNTCaptchaImageController.Show), controllerName, new
            {
                data = encryptSerializedValues,
                area = ""
            }, _httpContextAccessor.HttpContext.Request.Scheme);

        if (string.IsNullOrWhiteSpace(actionUrl))
        {
            throw new InvalidOperationException(
                message:
                "It's not possible to determine the URL of the `DNTCaptchaImageController.Show` method. Please register the `services.AddControllers()` and `endpoints.MapControllerRoute(...)`.");
        }
        if (png) actionUrl += ".png";
        return actionUrl;
    }

    private string GetRndDate(DNTCaptchaTagHelperHtmlAttributes captchaAttributes, bool png)
    {
        if (!png)
            return DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture);

        if (_dntCaptchaSettings.PngMultiplier < 1) _dntCaptchaSettings.PngMultiplier = 1;

        var index = Rnd.Next(_dntCaptchaSettings.PngMultiplier);
        var secretCacheKey = $"{SecretCacheKeyPrefix}{index}";

        var secretValueBytes = _distributedCache.Get(secretCacheKey);
        if (secretValueBytes == null)
        {
            var b = new byte[16];
            RandomNumberGenerator.Fill(b);
            secretValueBytes = b;
            _distributedCache.Set(secretCacheKey, secretValueBytes);
        }

        return Encoding.UTF8.GetString(secretValueBytes);
    }
}