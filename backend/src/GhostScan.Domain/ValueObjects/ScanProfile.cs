using GhostScan.Domain.Common;

namespace GhostScan.Domain.ValueObjects;

public sealed class ScanProfile : ValueObject
{
    public static readonly ScanProfile Stealth = new(
        "stealth", intensity: "passive", threads: 5,
        rateLimit: 2.0, wordlistSize: "small",
        enableXss: false, enableSqli: false, enableBrute: false,
        enableParallel: false, enableWafBypass: false);

    public static readonly ScanProfile Standard = new(
        "standard", intensity: "normal", threads: 20,
        rateLimit: 0.1, wordlistSize: "medium",
        enableXss: true, enableSqli: true, enableBrute: false,
        enableParallel: false, enableWafBypass: false);

    public static readonly ScanProfile Aggressive = new(
        "aggressive", intensity: "aggressive", threads: 50,
        rateLimit: 0.05, wordlistSize: "large",
        enableXss: true, enableSqli: true, enableBrute: true,
        enableParallel: true, enableWafBypass: true);

    public string Name { get; }
    public string Intensity { get; }
    public int Threads { get; }
    public double RateLimit { get; }
    public string WordlistSize { get; }
    public bool EnableXss { get; }
    public bool EnableSqli { get; }
    public bool EnableBrute { get; }
    public bool EnableParallel { get; }
    public bool EnableWafBypass { get; }

    private ScanProfile(string name, string intensity, int threads, double rateLimit,
        string wordlistSize, bool enableXss, bool enableSqli, bool enableBrute,
        bool enableParallel, bool enableWafBypass)
    {
        Name = name;
        Intensity = intensity;
        Threads = threads;
        RateLimit = rateLimit;
        WordlistSize = wordlistSize;
        EnableXss = enableXss;
        EnableSqli = enableSqli;
        EnableBrute = enableBrute;
        EnableParallel = enableParallel;
        EnableWafBypass = enableWafBypass;
    }

    public static Result<ScanProfile> FromString(string name) => name.ToLowerInvariant() switch
    {
        "stealth" => Result<ScanProfile>.Success(Stealth),
        "standard" => Result<ScanProfile>.Success(Standard),
        "aggressive" => Result<ScanProfile>.Success(Aggressive),
        _ => Result<ScanProfile>.Failure($"Unknown profile: '{name}'. Use stealth, standard, or aggressive.")
    };

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Name;
    }

    public override string ToString() => Name;
}
