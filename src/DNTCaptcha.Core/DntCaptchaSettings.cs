namespace DNTCaptcha.Core;

//mmm
public class DntCaptchaSettings
{
    public int AbsoluteExpirationMinutes { get; set; }
    public DisplayMode DisplayMode { get; set; }
    public int Min { get; set; }
    public int Max { get; set; }
    public int PngPercent { get; set; }
    public int PngMultiplier { get; set; }
    public int CachePercent { get; set; }
    public int CacheMultiplier { get; set; }
}