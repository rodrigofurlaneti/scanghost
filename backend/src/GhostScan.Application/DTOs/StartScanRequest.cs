namespace GhostScan.Application.DTOs;

public sealed class StartScanRequest
{
    /// <summary>Target: domain, IP, or CIDR. E.g.: example.com, 192.168.1.1, 10.0.0.0/24</summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>Scan profile: stealth, standard (default), aggressive</summary>
    public string Profile { get; init; } = "standard";

    /// <summary>Run recon module (DNS, subdomains, port scan)</summary>
    public bool RunRecon { get; init; } = true;

    /// <summary>Run web analysis module (crawl, dir brute-force, WAF detection, JS analysis)</summary>
    public bool RunWeb { get; init; } = true;

    /// <summary>Run vulnerability detection module (headers, XSS, SQLi, CVE)</summary>
    public bool RunVuln { get; init; } = true;

    /// <summary>Enable headless browser for DOM XSS scanning</summary>
    public bool EnableBrowser { get; init; } = false;

    /// <summary>Enable WAF bypass engine</summary>
    public bool EnableWafBypass { get; init; } = false;

    /// <summary>Specific WAF profile: cloudflare, akamai, aws-waf, f5, imperva, modsecurity, generic</summary>
    public string? WafProfile { get; init; }

    /// <summary>Enable XSS probing</summary>
    public bool EnableXss { get; init; } = true;

    /// <summary>Enable SQL injection testing</summary>
    public bool EnableSqli { get; init; } = true;

    /// <summary>Enable brute-force attacks</summary>
    public bool EnableBrute { get; init; } = false;

    /// <summary>Enable parallel recon (simultaneous tools)</summary>
    public bool EnableParallel { get; init; } = false;

    /// <summary>Skip subdomain enumeration</summary>
    public bool NoSubdomains { get; init; } = false;

    /// <summary>Skip CVE correlation</summary>
    public bool NoCve { get; init; } = false;

    /// <summary>Disable plugin system</summary>
    public bool NoPlugins { get; init; } = false;

    /// <summary>Minimum severity to include in report: critical, high, medium, low, info</summary>
    public string MinSeverity { get; init; } = "info";

    /// <summary>Web crawl depth (default: 3)</summary>
    public int CrawlDepth { get; init; } = 3;

    /// <summary>Request timeout in seconds</summary>
    public int RequestTimeout { get; init; } = 10;

    /// <summary>Proxy URL (e.g. http://127.0.0.1:8080)</summary>
    public string? ProxyUrl { get; init; }

    /// <summary>Additional HTTP headers as key:value pairs</summary>
    public Dictionary<string, string>? CustomHeaders { get; init; }

    /// <summary>Custom ports to scan (comma-separated)</summary>
    public string? Ports { get; init; }
}
