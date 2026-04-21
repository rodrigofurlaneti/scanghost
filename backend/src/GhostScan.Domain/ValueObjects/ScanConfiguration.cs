using GhostScan.Domain.Common;

namespace GhostScan.Domain.ValueObjects;

public sealed class ScanConfiguration : ValueObject
{
    public ScanProfile Profile { get; }
    public bool RunRecon { get; }
    public bool RunWeb { get; }
    public bool RunVuln { get; }
    public bool EnableBrowser { get; }
    public bool EnableScreenshots { get; }
    public bool EnableParallel { get; }
    public bool StrictScope { get; }
    public bool NoSsrfProtect { get; }
    public bool NoSubdomains { get; }
    public bool NoCve { get; }
    public bool NoPlugins { get; }
    public bool EnableTor { get; }
    public string? ProxyUrl { get; }
    public string? WafProfile { get; }
    public Severity MinSeverity { get; }
    public IReadOnlyList<string> Ports { get; }
    public int CrawlDepth { get; }
    public int RequestTimeout { get; }
    public string ReportFormat { get; }
    public string? UserAgent { get; }

    private static readonly string[] DefaultPorts =
        ["21", "22", "23", "25", "53", "80", "110", "111", "135", "139",
         "143", "443", "445", "993", "995", "1433", "1521", "3306", "3389",
         "5432", "5900", "6379", "8080", "8443", "8888", "9090", "9200", "27017"];

    private ScanConfiguration(
        ScanProfile profile, bool runRecon, bool runWeb, bool runVuln,
        bool enableBrowser, bool enableScreenshots, bool enableParallel,
        bool strictScope, bool noSsrfProtect, bool noSubdomains,
        bool noCve, bool noPlugins, bool enableTor, string? proxyUrl,
        string? wafProfile, Severity minSeverity, IReadOnlyList<string> ports,
        int crawlDepth, int requestTimeout, string reportFormat, string? userAgent)
    {
        Profile = profile;
        RunRecon = runRecon;
        RunWeb = runWeb;
        RunVuln = runVuln;
        EnableBrowser = enableBrowser;
        EnableScreenshots = enableScreenshots;
        EnableParallel = enableParallel;
        StrictScope = strictScope;
        NoSsrfProtect = noSsrfProtect;
        NoSubdomains = noSubdomains;
        NoCve = noCve;
        NoPlugins = noPlugins;
        EnableTor = enableTor;
        ProxyUrl = proxyUrl;
        WafProfile = wafProfile;
        MinSeverity = minSeverity;
        Ports = ports;
        CrawlDepth = crawlDepth;
        RequestTimeout = requestTimeout;
        ReportFormat = reportFormat;
        UserAgent = userAgent;
    }

    public static ScanConfiguration CreateDefault(ScanProfile? profile = null)
    {
        var selectedProfile = profile ?? ScanProfile.Standard;
        return new ScanConfiguration(
            selectedProfile,
            runRecon: true, runWeb: true, runVuln: true,
            enableBrowser: false, enableScreenshots: false,
            enableParallel: selectedProfile.EnableParallel,
            strictScope: false, noSsrfProtect: false,
            noSubdomains: false, noCve: false,
            noPlugins: false, enableTor: false,
            proxyUrl: null, wafProfile: null,
            minSeverity: Severity.Info,
            ports: DefaultPorts,
            crawlDepth: 3, requestTimeout: 10,
            reportFormat: "json",
            userAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0");
    }

    public static ScanConfiguration Create(
        ScanProfile profile, bool runRecon = true, bool runWeb = true, bool runVuln = true,
        bool enableBrowser = false, bool enableScreenshots = false, bool enableParallel = false,
        bool strictScope = false, bool noSsrfProtect = false, bool noSubdomains = false,
        bool noCve = false, bool noPlugins = false, bool enableTor = false,
        string? proxyUrl = null, string? wafProfile = null, Severity? minSeverity = null,
        string[]? ports = null, int crawlDepth = 3, int requestTimeout = 10,
        string reportFormat = "json", string? userAgent = null)
    {
        return new ScanConfiguration(
            profile, runRecon, runWeb, runVuln,
            enableBrowser, enableScreenshots,
            enableParallel || profile.EnableParallel,
            strictScope, noSsrfProtect, noSubdomains,
            noCve, noPlugins, enableTor, proxyUrl, wafProfile,
            minSeverity ?? Severity.Info,
            (ports ?? DefaultPorts).ToList().AsReadOnly(),
            crawlDepth, requestTimeout, reportFormat,
            userAgent ?? "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0");
    }

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Profile;
        yield return RunRecon;
        yield return RunWeb;
        yield return RunVuln;
    }
}
