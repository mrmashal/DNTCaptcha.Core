namespace DNTCaptcha.Core;

/// <summary>
///     Validates the input number.
/// </summary>
public interface IDNTCaptchaValidatorService
{
    /// <summary>
    ///     Validates the input number using current request form values.
    /// </summary>
    bool HasRequestValidCaptchaEntry();

    /// <summary>
    /// Validates the input number.
    /// </summary>
    /// <param name="captchaText">Encrypted captcha text</param>
    /// <param name="inputText">User captcha input</param>
    /// <param name="cookieToken">Cookie token</param>
    /// <param name="decryptedText">Decrypted captcha text</param>
    bool ValidateCaptcha(
        string captchaText, string inputText, string cookieToken,
        out string decryptedText);
}