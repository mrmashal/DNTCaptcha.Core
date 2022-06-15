using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using static System.FormattableString;

namespace DNTCaptcha.Core
{
    /// <summary>
    /// DNTCaptcha Api
    /// </summary>
    public class DNTCaptchaApiProvider : IDNTCaptchaApiProvider
    {
        private static Random _rnd = new Random();
        private static List<string> _secrets = null;

        private readonly ICaptchaCryptoProvider _captchaProtectionProvider;
        private readonly ICaptchaStorageProvider _captchaStorageProvider;
        private readonly Func<DisplayMode, ICaptchaTextProvider> _captchaTextProvider;
        private readonly IRandomNumberProvider _randomNumberProvider;
        private readonly ISerializationProvider _serializationProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IUrlHelper _urlHelper;
        private readonly DNTCaptchaOptions _captchaOptions;

        /// <summary>
        /// DNTCaptcha Api
        /// </summary>
        public DNTCaptchaApiProvider(
            ICaptchaCryptoProvider captchaProtectionProvider,
            IRandomNumberProvider randomNumberProvider,
            Func<DisplayMode, ICaptchaTextProvider> captchaTextProvider,
            ICaptchaStorageProvider captchaStorageProvider,
            ISerializationProvider serializationProvider,
            IHttpContextAccessor httpContextAccessor,
            IUrlHelper urlHelper,
            IOptions<DNTCaptchaOptions> options)
        {
            _captchaProtectionProvider = captchaProtectionProvider ?? throw new ArgumentNullException(nameof(captchaProtectionProvider));
            _randomNumberProvider = randomNumberProvider ?? throw new ArgumentNullException(nameof(randomNumberProvider));
            _captchaTextProvider = captchaTextProvider ?? throw new ArgumentNullException(nameof(captchaTextProvider));
            _captchaStorageProvider = captchaStorageProvider ?? throw new ArgumentNullException(nameof(captchaStorageProvider));
            _serializationProvider = serializationProvider ?? throw new ArgumentNullException(nameof(serializationProvider));
            _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
            _urlHelper = urlHelper ?? throw new ArgumentNullException(nameof(urlHelper));
            _captchaOptions = options == null ? throw new ArgumentNullException(nameof(options)) : options.Value;
        }

        /// <summary>
        /// Creates DNTCaptcha
        /// </summary>
        /// <param name="captchaAttributes">captcha attributes</param>
        public DNTCaptchaApiResponse CreateDNTCaptcha(DNTCaptchaTagHelperHtmlAttributes captchaAttributes)
        {
            if (captchaAttributes == null)
            {
                throw new ArgumentNullException(nameof(captchaAttributes));
            }

            if (_httpContextAccessor.HttpContext == null)
            {
                throw new InvalidOperationException("`_httpContextAccessor.HttpContext` is null.");
            }

            var png = captchaAttributes.PngPercent > 0 && _rnd.Next(100) < captchaAttributes.PngPercent; //mmm
            var number = _randomNumberProvider.NextNumber(captchaAttributes.Min, captchaAttributes.Max);
            var randomText = _captchaTextProvider(captchaAttributes.DisplayMode).GetText(number, captchaAttributes.Language);
            var encryptedText = _captchaProtectionProvider.Encrypt(randomText);
            var pngEncryptedText = png ? _captchaProtectionProvider.Encrypt(randomText, png) : encryptedText;
            var captchaImageUrl = getCaptchaImageUrl(captchaAttributes, pngEncryptedText, png);
            var captchaDivId = Invariant($"{_captchaOptions.CaptchaClass}{Guid.NewGuid():N}{_randomNumberProvider.NextNumber(captchaAttributes.Min, captchaAttributes.Max)}");
            var cookieToken = $".{captchaDivId}";
            var hiddenInputToken = _captchaProtectionProvider.Encrypt(cookieToken);

            _captchaStorageProvider.Add(_httpContextAccessor.HttpContext, cookieToken, randomText);

            return new DNTCaptchaApiResponse
            {
                DntCaptchaImgUrl = captchaImageUrl,
                DntCaptchaId = captchaDivId,
                DntCaptchaTextValue = encryptedText,
                DntCaptchaTokenValue = hiddenInputToken
            };
        }

        private string getCaptchaImageUrl(DNTCaptchaTagHelperHtmlAttributes captchaAttributes, string encryptedText, bool png)
        {
            if (_httpContextAccessor.HttpContext == null)
            {
                throw new InvalidOperationException("`_httpContextAccessor.HttpContext` is null.");
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
            var actionUrl = captchaAttributes.UseRelativeUrls ?
                _urlHelper.Action(action: nameof(DNTCaptchaImageController.Show),
                            controller: nameof(DNTCaptchaImageController).Replace("Controller", string.Empty, StringComparison.Ordinal),
                            values: new { data = encryptSerializedValues, area = "" }) :
                _urlHelper.Action(action: nameof(DNTCaptchaImageController.Show),
                            controller: nameof(DNTCaptchaImageController).Replace("Controller", string.Empty, StringComparison.Ordinal),
                            values: new { data = encryptSerializedValues, area = "" },
                            protocol: _httpContextAccessor.HttpContext.Request.Scheme);
            
            if (string.IsNullOrWhiteSpace(actionUrl))
            {
                throw new InvalidOperationException("It's not possible to determine the URL of the `DNTCaptchaImageController.Show` method. Please register the `services.AddControllers()` and `endpoints.MapControllerRoute(...)`.");
            }
            if (png) actionUrl += ".png";
            return actionUrl;
        }

        private string GetRndDate(DNTCaptchaTagHelperHtmlAttributes captchaAttributes, bool png)
        {
            if (!png)
                return DateTime.Now.Ticks.ToString(CultureInfo.InvariantCulture);

            if (captchaAttributes.Multiplier < 1) captchaAttributes.Multiplier = 1;

            if (_secrets == null)
                _secrets = new(new string[captchaAttributes.Multiplier]);

            var index = _rnd.Next(captchaAttributes.Multiplier);

            if (_secrets[index] == null)
            {
                var b = new byte[16];
                RandomNumberGenerator.Fill(b);
                _secrets[index] = Encoding.UTF8.GetString(b);
            }

            return _secrets[index];
        }
    }
}