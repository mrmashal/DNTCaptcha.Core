using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Abp.Auditing;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Caching.Distributed;
using Phaa.AzmoonOnline.App;
using Microsoft.EntityFrameworkCore.Metadata.Internal;



#if NET7_0 || NET8_0 || NET9_0
using Microsoft.AspNetCore.RateLimiting;
#endif

namespace DNTCaptcha.Core;

/// <summary>
///     DNTCaptcha Image Controller
/// </summary>
/// <remarks>
///     DNTCaptcha Image Controller
/// </remarks>
[DisableAuditing]
[AllowAnonymous]
#if NET7_0 || NET8_0 || NET9_0
[EnableRateLimiting(DNTCaptchaRateLimiterPolicy.Name)]
#endif
public class DNTCaptchaImageController(
    ICaptchaImageProvider captchaImageProvider,
    ICaptchaCryptoProvider captchaProtectionProvider,
    ITempDataProvider tempDataProvider,
    ICaptchaStorageProvider captchaStorageProvider,
    ILogger<DNTCaptchaImageController> logger,
    ISerializationProvider serializationProvider,
    Func<DisplayMode, ICaptchaTextProvider> captchaTextProvider, //mmm
    IDistributedCache distributedCache, //mmm
    DntCaptchaSettings dntCaptchaSettings, //mmm
    IOptions<DNTCaptchaOptions> options) : Controller
{
    private const string TheReceivedDataIsNullOrEmpty = "The received data is null or empty.";

    private const string CouldntDecryptTheReceivedData =
        "Couldn't decrypt the received data. Probably it's malformed or changed/destroyed.";

    private const string IsYourNetworkDistributed =
        "Couldn't deserialize the model. Are you on a distributed environment? If yes, please read the `How to choose a correct storage mode` in the readme file.";

    private const string TurnOnTheLogDebugLevel =
        "Turn on the `LogDebug` level, to see the actual details of the exception, in the logs.";

    private readonly ICaptchaImageProvider _captchaImageProvider =
        captchaImageProvider ?? throw new ArgumentNullException(nameof(captchaImageProvider));

    private readonly ICaptchaCryptoProvider _captchaProtectionProvider = captchaProtectionProvider ??
                                                                         throw new ArgumentNullException(
                                                                             nameof(captchaProtectionProvider));

    private readonly ICaptchaStorageProvider _captchaStorageProvider =
        captchaStorageProvider ?? throw new ArgumentNullException(nameof(captchaStorageProvider));

    private readonly ILogger<DNTCaptchaImageController> _logger =
        logger ?? throw new ArgumentNullException(nameof(logger));

    private readonly DNTCaptchaOptions _options =
        options == null ? throw new ArgumentNullException(nameof(options)) : options.Value;

    private readonly ISerializationProvider _serializationProvider =
        serializationProvider ?? throw new ArgumentNullException(nameof(serializationProvider));

    private readonly ITempDataProvider _tempDataProvider =
        tempDataProvider ?? throw new ArgumentNullException(nameof(tempDataProvider));

    //mmm
    private const string ImageCacheKeyPrefix = ".Cimg:";
    private readonly Func<DisplayMode, ICaptchaTextProvider> _captchaTextProvider =
        captchaTextProvider ?? throw new ArgumentNullException(nameof(captchaTextProvider));
    private readonly IDistributedCache _distributedCache =
        distributedCache ?? throw new ArgumentNullException(nameof(distributedCache));
    private readonly DntCaptchaSettings _dntCaptchaSettings =
        dntCaptchaSettings ?? throw new ArgumentNullException(nameof(dntCaptchaSettings));
    private static Random Rnd = new Random();

    /// <summary>
    ///     The ViewContext Provider
    /// </summary>
    [ViewContext]
    public ViewContext? ViewContext { get; set; }

    /// <summary>
    ///     Refresh the captcha
    /// </summary>
    [ResponseCache(Location = ResponseCacheLocation.None, NoStore = true, Duration = 0)]
    [HttpGet]
    [HttpPost]
    public IActionResult Refresh(string data)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                return BadRequest(TheReceivedDataIsNullOrEmpty);
            }

            var png = false;
            if (data.Length > 4 && data.EndsWith(".png"))
            {
                data = data.Substring(0, data.Length - 4);
                png = true;
            }

            var decryptedModel = _captchaProtectionProvider.Decrypt(data, png);

            if (decryptedModel == null)
            {
                return BadRequest(CouldntDecryptTheReceivedData);
            }

            var model = _serializationProvider.Deserialize<DNTCaptchaTagHelperHtmlAttributes>(decryptedModel);

            if (model == null)
            {
                return BadRequest(IsYourNetworkDistributed);
            }

            InvalidateToken(model);

            var tagHelper = HttpContext.RequestServices.GetRequiredService<DNTCaptchaTagHelper>();
            tagHelper.BackColor = model.BackColor;
            tagHelper.FontName = model.FontName;
            tagHelper.FontSize = model.FontSize;
            tagHelper.ForeColor = model.ForeColor;
            tagHelper.Language = model.Language;
            tagHelper.Max = model.Max;
            tagHelper.Min = model.Min;
            tagHelper.Placeholder = model.Placeholder;
            tagHelper.TextBoxClass = model.TextBoxClass;
            tagHelper.TextBoxTemplate = model.TextBoxTemplate;
            tagHelper.ValidationErrorMessage = model.ValidationErrorMessage;
            tagHelper.TooManyRequestsErrorMessage = model.TooManyRequestsErrorMessage;
            tagHelper.ValidationMessageClass = model.ValidationMessageClass;
            tagHelper.RefreshButtonClass = model.RefreshButtonClass;
            tagHelper.DisplayMode = model.DisplayMode;
            tagHelper.UseRelativeUrls = model.UseRelativeUrls;
            tagHelper.ShowRefreshButton = model.ShowRefreshButton;

            var tagHelperContext = new TagHelperContext(new TagHelperAttributeList(), new Dictionary<object, object>
            {
                {
                    typeof(IUrlHelper), Url
                }
            }, Guid.NewGuid().ToString(format: "N"));

            var tagHelperOutput = new TagHelperOutput(tagName: "div", new TagHelperAttributeList(), (useCachedResult, encoder) =>
            {
                var tagHelperContent = new DefaultTagHelperContent();
                tagHelperContent.SetContent(string.Empty);

                return Task.FromResult<TagHelperContent>(tagHelperContent);
            });

            tagHelper.ViewContext = ViewContext ?? new ViewContext(
                new ActionContext(HttpContext, HttpContext.GetRouteData(), ControllerContext.ActionDescriptor),
                new FakeView(), new ViewDataDictionary(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    Model = null
                }, new TempDataDictionary(HttpContext, _tempDataProvider), TextWriter.Null, new HtmlHelperOptions());

            tagHelper.Process(tagHelperContext, tagHelperOutput);

            var attrs = new StringBuilder();

            foreach (var attr in tagHelperOutput.Attributes)
            {
                attrs.Append(value: ' ').Append(attr.Name).Append(value: "='").Append(attr.Value).Append(value: '\'');
            }

            var content = $"<div {attrs}>{tagHelperOutput.Content.GetContent()}</div>";

            return Content(content);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, message: "Failed to refresh the captcha image.");

            return _options.ShowExceptions ? BadRequest(ex.ToString()) : BadRequest(TurnOnTheLogDebugLevel);
        }
    }

    private void InvalidateToken(DNTCaptchaTagHelperHtmlAttributes model)
        => _captchaStorageProvider.Remove(HttpContext, model.CaptchaToken);

    /// <summary>
    ///     Creates the captcha image.
    /// </summary>
    //[ResponseCache(Location = ResponseCacheLocation.None, NoStore = true, Duration = 0)]
    //[HttpGet(template: "[action]")]
    //[HttpPost(template: "[action]")]
    [HttpGet("{data}")]
    [HttpPost("{data}")]
    public IActionResult Show(string data)
    {
        using var span = Diag.Span("DNTCaptchaImageShow", "api");

        try
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                return BadRequest(TheReceivedDataIsNullOrEmpty);
            }

            var png = false;
            if (data.Length > 4 && data.EndsWith(".png"))
            {
                data = data.Substring(0, data.Length - 4);
                png = true;
            }

            var decryptedModel = _captchaProtectionProvider.Decrypt(data, png);

            if (decryptedModel == null)
            {
                return BadRequest(CouldntDecryptTheReceivedData);
            }

            var model = _serializationProvider.Deserialize<CaptchaImageParams>(decryptedModel);

            if (model == null)
            {
                return BadRequest(IsYourNetworkDistributed);
            }

            var decryptedText = _captchaProtectionProvider.Decrypt(model.Text, png);

            if (decryptedText == null)
            {
                return BadRequest(error: "Couldn't decrypt the text.");
            }

            var image = GetImage(decryptedText, model); //mmm

            return new FileContentResult(image, contentType: "image/png");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, message: "Failed to show the captcha image.");

            return _options.ShowExceptions ? BadRequest(ex.ToString()) : BadRequest(TurnOnTheLogDebugLevel);
        }
    }

    //mmm
    [HttpGet("{number}")]
    [HttpPost("{number}")]
    public IActionResult ShowForLoadTest(int number)
    {
        using var span = Diag.Span("DNTCaptchaImageShowForLoadTest", "api");

        try
        {
            var model = new CaptchaImageParams
            {
                BackColor = "#f7f3f3",
                FontName = "Vazir",
                FontSize = 36,
                ForeColor = "#111111",
            };
            var decryptedText = _captchaTextProvider(DisplayMode.NumberToWord)
                .GetText(number, Language.Persian);



            var image = GetImage(decryptedText, model);

            return new FileContentResult(image, contentType: "image/png");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, message: "Failed to show the captcha image.");

            return _options.ShowExceptions ? BadRequest(ex.ToString()) : BadRequest(TurnOnTheLogDebugLevel);
        }
    }

    //mmm
    /// <summary>
    /// Gets the captcha image from cache, or draws a new captcha image on cache miss.
    /// </summary>
    private byte[] GetImage(string decryptedText, CaptchaImageParams model)
    {
        var useCache = _dntCaptchaSettings.CachePercent > 0 && Rnd.Next(100) < _dntCaptchaSettings.CachePercent;

        string imageCacheKey = null;
        if (useCache)
        {
            var index = Rnd.Next(_dntCaptchaSettings.CacheMultiplier);
            imageCacheKey = $"{ImageCacheKeyPrefix}{decryptedText}:{index}";
            var cachedValueBytes = _distributedCache.Get(imageCacheKey);
            if (cachedValueBytes != null)
            {
                return cachedValueBytes;
            }
        }

        var image = _captchaImageProvider.DrawCaptcha(decryptedText, model.ForeColor, model.BackColor,
                        model.FontSize, model.FontName);

        if (useCache)
            _distributedCache.Set(imageCacheKey, image);

        return image;
    }
}