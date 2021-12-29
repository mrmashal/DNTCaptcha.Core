namespace DNTCaptcha.Core
{
    /// <summary>
    /// Validates the input number.
    /// </summary>
    public interface IDNTCaptchaValidatorService
    {
        /// <summary>
        /// Validates the input number using current request form values.
        /// </summary>
        /// <param name="captchaGeneratorLanguage">The Number to word language.</param>
        /// <param name="captchaGeneratorDisplayMode">Display mode of the captcha's text.</param>
        bool HasRequestValidCaptchaEntry(Language captchaGeneratorLanguage, DisplayMode captchaGeneratorDisplayMode);

        /// <summary>
        /// Validates the input number.
        /// </summary>
        /// <param name="captchaText">Encrypted captcha text</param>
        /// <param name="inputText">User captcha input</param>
        /// <param name="cookieToken">Cookie token</param>
        /// <param name="captchaGeneratorLanguage">The Number to word language.</param>
        /// <param name="captchaGeneratorDisplayMode">Display mode of the captcha's text.</param>
        /// <param name="decryptedText">Decrypted captcha text</param>
        bool ValidateCaptcha(
            string captchaText, string inputText, string cookieToken,
            Language captchaGeneratorLanguage, DisplayMode captchaGeneratorDisplayMode,
            out string decryptedText);
    }
}