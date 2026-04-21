using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using GhostScan.Infrastructure.Tools;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

public sealed class VulnDetectionScanModule : IScanModule
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ExternalToolRunner _toolRunner;
    private readonly ILogger<VulnDetectionScanModule> _logger;

    private static readonly string[] BuiltinXssPayloads =
    [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "';alert(1)//",
        "<details open ontoggle=alert(1)>",
        "\" onmouseover=\"alert(1)",
    ];

    private static readonly string[] BuiltinSqliPayloads =
    [
        "'",
        "''",
        "' OR '1'='1",
        "1 OR 1=1",
        "1' ORDER BY 1--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--",
        "admin'--",
        "' OR 1=1--",
    ];

    private static readonly Regex[] SqliErrorPatterns =
    [
        new(@"SQL syntax.*MySQL", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"Warning.*mysql_", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"PostgreSQL.*ERROR", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"ORA-\d{5}", RegexOptions.Compiled),
        new(@"Microsoft SQL Server", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"Incorrect syntax near", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"sqlite3\.OperationalError", RegexOptions.Compiled),
        new(@"You have an error in your SQL syntax", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"Unclosed quotation mark", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    private static readonly Dictionary<string, CveEntry> CveDatabase = BuildCveDatabase();

    public string Name => "VulnDetection";

    public VulnDetectionScanModule(
        IHttpClientFactory httpClientFactory,
        ExternalToolRunner toolRunner,
        ILogger<VulnDetectionScanModule> logger)
    {
        _httpClientFactory = httpClientFactory;
        _toolRunner = toolRunner;
        _logger = logger;
    }

    public async Task<ScanModuleResult> ExecuteAsync(
        ScanTarget target,
        ScanConfiguration configuration,
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();
        var data = new Dictionary<string, object>();

        try
        {
            var httpClient = CreateHttpClient(configuration);
            var baseUrls = context.GetBaseUrls().ToList();
            var baseUrl = baseUrls.FirstOrDefault() ?? target.ToBaseUrl();
            var endpoints = context.GetEndpoints().ToList();
            var injectableEndpoints = BuildInjectableEndpoints(endpoints);

            // 1. SQL Injection
            if (configuration.Profile.EnableSqli)
            {
                _logger.LogInformation("[Vuln] SQL injection testing");
                var sqliFindings = await TestSqliAsync(baseUrl, injectableEndpoints, configuration, httpClient, cancellationToken);
                findings.AddRange(sqliFindings);
                data["sqli_findings"] = sqliFindings.Count;
            }

            // 2. XSS
            if (configuration.Profile.EnableXss)
            {
                _logger.LogInformation("[Vuln] XSS probing");
                var xssFindings = await TestXssAsync(baseUrl, injectableEndpoints, httpClient, cancellationToken);
                findings.AddRange(xssFindings);
                data["xss_findings"] = xssFindings.Count;
            }

            // 3. CVE Correlation
            if (!configuration.NoCve)
            {
                _logger.LogInformation("[Vuln] CVE correlation");
                var cveFindings = CorrelateCves(context);
                findings.AddRange(cveFindings);
                data["cve_findings"] = cveFindings.Count;
            }

            // 4. SSL/TLS Analysis
            if (baseUrl.StartsWith("https://"))
            {
                _logger.LogInformation("[Vuln] SSL/TLS analysis");
                var sslFindings = await AnalyzeSslAsync(baseUrl, configuration, cancellationToken);
                findings.AddRange(sslFindings);
            }

            // 5. Open Redirect Testing
            _logger.LogInformation("[Vuln] Open redirect testing");
            var redirectFindings = await TestOpenRedirectsAsync(baseUrl, injectableEndpoints, httpClient, cancellationToken);
            findings.AddRange(redirectFindings);

            // 6. Brute-force (if enabled)
            if (configuration.Profile.EnableBrute)
            {
                _logger.LogInformation("[Vuln] Authentication brute-force");
                var bruteFindings = await RunBruteForceAsync(target.Value, context, configuration, cancellationToken);
                findings.AddRange(bruteFindings);
            }

            return ScanModuleResult.Succeeded(findings, data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Vuln] Error in vulnerability detection for {Target}", target.Value);
            return ScanModuleResult.Failed($"Vulnerability detection error: {ex.Message}");
        }
    }

    private async Task<List<Finding>> TestSqliAsync(
        string baseUrl, List<(string Url, Dictionary<string, string> Params)> targets,
        ScanConfiguration configuration, HttpClient httpClient, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        // Try sqlmap if available
        if (_toolRunner.IsAvailable("sqlmap"))
        {
            foreach (var (url, parameters) in targets.Take(5))
            {
                var paramStr = string.Join(",", parameters.Keys);
                var testUrl = parameters.Count > 0
                    ? $"{url}?{string.Join("&", parameters.Select(p => $"{p.Key}={p.Value}"))}"
                    : url;

                var level = configuration.Profile.Intensity == "aggressive" ? 5 : 3;
                var risk = configuration.Profile.Intensity == "aggressive" ? 3 : 2;
                var args = $"-u \"{testUrl}\" --level={level} --risk={risk} --batch --no-cast --output-dir=/tmp/sqlmap_{Guid.NewGuid():N}";

                var (_, stdout, _) = await _toolRunner.RunAsync("sqlmap", args, 180, cancellationToken);

                if (stdout.Contains("is vulnerable") || stdout.Contains("SQL injection"))
                {
                    var paramMatch = Regex.Match(stdout, @"Parameter: (\w+)");
                    var injectionType = Regex.Match(stdout, @"Type: ([^\n]+)");
                    var paramName = paramMatch.Success ? paramMatch.Groups[1].Value : "parameter";
                    var typeName = injectionType.Success ? injectionType.Groups[1].Value.Trim() : "unknown";

                    findings.Add(Finding.Create(
                        Severity.Critical, FindingCategory.SQLi,
                        $"SQL Injection: {paramName} ({typeName})",
                        url: testUrl,
                        detail: $"SQLmap confirmed SQLi in parameter '{paramName}'. Type: {typeName}",
                        remediation: "Use prepared statements / parameterized queries throughout.",
                        impact: 10.0, confidence: 0.95,
                        vulnType: "sqli", isConfirmed: true));
                }
            }
            return findings;
        }

        // Fallback: built-in error-based + boolean detection
        foreach (var (url, parameters) in targets.Take(5))
        {
            if (parameters.Count == 0) continue;

            string? baseline = null;
            try
            {
                baseline = await httpClient.GetStringAsync(
                    $"{url}?{string.Join("&", parameters.Select(p => $"{p.Key}={p.Value}"))}",
                    cancellationToken);
            }
            catch { continue; }

            foreach (var payload in BuiltinSqliPayloads.Take(8))
            {
                try
                {
                    var injected = parameters.ToDictionary(p => p.Key, p => p.Value + payload);
                    var testUrl = $"{url}?{string.Join("&", injected.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"))}";
                    var response = await httpClient.GetStringAsync(testUrl, cancellationToken);

                    foreach (var pattern in SqliErrorPatterns)
                    {
                        var match = pattern.Match(response);
                        if (match.Success)
                        {
                            findings.Add(Finding.Create(
                                Severity.Critical, FindingCategory.SQLi,
                                $"SQL error detected at {url}",
                                evidence: $"Error pattern: {match.Value[..Math.Min(80, match.Value.Length)]}",
                                url: testUrl,
                                remediation: "Use parameterized queries. Never concatenate user input in SQL.",
                                impact: 10.0, confidence: 0.90,
                                vulnType: "sqli"));
                            goto NextEndpoint;
                        }
                    }
                }
                catch { }
                await Task.Delay((int)(configuration.Profile.RateLimit * 1000), cancellationToken);
            }
            NextEndpoint:;
        }

        return findings;
    }

    private async Task<List<Finding>> TestXssAsync(
        string baseUrl, List<(string Url, Dictionary<string, string> Params)> targets,
        HttpClient httpClient, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        foreach (var (url, parameters) in targets.Take(10))
        {
            foreach (var payload in BuiltinXssPayloads)
            {
                try
                {
                    var injected = parameters.ToDictionary(p => p.Key, _ => payload);
                    var testUrl = $"{url}?{string.Join("&", injected.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"))}";
                    var response = await httpClient.GetStringAsync(testUrl, cancellationToken);

                    if (response.Contains(payload) &&
                        Regex.IsMatch(response, @"<script|onerror|onload|javascript:", RegexOptions.IgnoreCase))
                    {
                        findings.Add(Finding.Create(
                            Severity.High, FindingCategory.XSS,
                            $"Reflected XSS at {url}",
                            evidence: $"Payload reflected: {payload[..Math.Min(60, payload.Length)]}",
                            url: testUrl,
                            remediation: "Encode output. Implement strict Content-Security-Policy.",
                            impact: 6.0, confidence: 0.60,
                            vulnType: "xss_reflected"));
                        goto NextXssEndpoint;
                    }
                }
                catch { }
            }
            NextXssEndpoint:;
        }

        return findings;
    }

    private List<Finding> CorrelateCves(ScanContext context)
    {
        var findings = new List<Finding>();
        var technologies = context.Get<Dictionary<string, object>>("technologies") ?? [];
        var fingerprints = new List<string>();

        // Collect all fingerprints
        foreach (var items in technologies.Values)
        {
            if (items is List<string> list) fingerprints.AddRange(list);
            else if (items is string s) fingerprints.Add(s);
        }

        var seen = new HashSet<string>();
        foreach (var fingerprint in fingerprints)
        {
            foreach (var (cveId, cve) in CveDatabase)
            {
                if (seen.Contains(cveId)) continue;
                if (!cve.Keywords.Any(kw => fingerprint.Contains(kw, StringComparison.OrdinalIgnoreCase))) continue;

                seen.Add(cveId);
                var severity = Severity.FromString(cve.Severity).Value ?? Severity.High;

                findings.Add(Finding.Create(
                    severity, FindingCategory.CVE,
                    $"{cveId}: {cve.Title} (matched: {fingerprint[..Math.Min(50, fingerprint.Length)]})",
                    detail: cve.Description,
                    remediation: cve.Fix,
                    impact: cve.Severity == "CRITICAL" ? 10.0 : 7.0,
                    confidence: 0.80,
                    vulnType: "cve_critical",
                    attackPath: $"searchsploit {cveId} && exploit"));
            }
        }

        return findings;
    }

    private async Task<List<Finding>> AnalyzeSslAsync(
        string baseUrl, ScanConfiguration configuration, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var host = new Uri(baseUrl).Host;

        if (_toolRunner.IsAvailable("testssl.sh"))
        {
            var (_, stdout, _) = await _toolRunner.RunAsync(
                "testssl.sh", $"--quiet --severity LOW {host}:443", 120, cancellationToken);

            foreach (var line in stdout.Split('\n'))
            {
                if (line.Contains("CRITICAL") || line.Contains("HIGH"))
                {
                    var severity = line.Contains("CRITICAL") ? Severity.Critical : Severity.High;
                    findings.Add(Finding.Create(
                        severity, FindingCategory.SSL,
                        $"SSL/TLS issue: {line.Trim()[..Math.Min(100, line.Trim().Length)]}",
                        url: baseUrl,
                        impact: 5.0, confidence: 0.90,
                        vulnType: "ssl_weak"));
                }
            }
        }
        else
        {
            // Basic SSL check via HttpClient
            try
            {
                var httpClientWithValidation = _httpClientFactory.CreateClient("scanner_strict");
                await httpClientWithValidation.GetAsync(baseUrl, cancellationToken);
            }
            catch (Exception ex) when (ex.Message.Contains("SSL") || ex.Message.Contains("certificate"))
            {
                findings.Add(Finding.Create(
                    Severity.High, FindingCategory.SSL,
                    $"SSL/TLS certificate error: {ex.Message[..Math.Min(100, ex.Message.Length)]}",
                    url: baseUrl,
                    remediation: "Obtain a valid SSL certificate from a trusted CA.",
                    impact: 5.0, confidence: 0.99,
                    vulnType: "ssl_weak"));
            }
        }

        return findings;
    }

    private async Task<List<Finding>> TestOpenRedirectsAsync(
        string baseUrl, List<(string Url, Dictionary<string, string> Params)> targets,
        HttpClient httpClient, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        var redirectPayloads = new[]
        {
            "https://evil.com",
            "//evil.com",
            "https://evil.com%2F%2F",
        };

        var redirectParams = new[] { "url", "redirect", "next", "return", "returnUrl", "callback", "goto" };

        foreach (var (url, parameters) in targets.Take(5))
        {
            foreach (var paramName in parameters.Keys.Where(k =>
                redirectParams.Any(rp => k.Equals(rp, StringComparison.OrdinalIgnoreCase))))
            {
                foreach (var payload in redirectPayloads)
                {
                    try
                    {
                        var testUrl = $"{url}?{paramName}={Uri.EscapeDataString(payload)}";
                        var response = await httpClient.GetAsync(testUrl, cancellationToken);
                        var location = response.Headers.Location?.ToString() ?? "";

                        if (location.Contains("evil.com") || location.StartsWith("//"))
                        {
                            findings.Add(Finding.Create(
                                Severity.Medium, FindingCategory.Web,
                                $"Open Redirect via '{paramName}' parameter",
                                url: testUrl,
                                evidence: $"Redirects to: {location}",
                                remediation: "Validate redirect targets against an allowlist.",
                                impact: 4.0, confidence: 0.85,
                                vulnType: "open_redirect", isConfirmed: true));
                            goto NextRedirectParam;
                        }
                    }
                    catch { }
                }
                NextRedirectParam:;
            }
        }

        return findings;
    }

    private async Task<List<Finding>> RunBruteForceAsync(
        string target, ScanContext context, ScanConfiguration configuration,
        CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        if (!_toolRunner.IsAvailable("hydra")) return findings;

        var openPorts = context.GetOpenPorts();
        var serviceMap = new Dictionary<int, string>
        {
            [22] = "ssh", [21] = "ftp", [23] = "telnet",
            [3306] = "mysql", [5432] = "postgres", [1433] = "mssql"
        };

        foreach (var (host, _) in openPorts)
        {
            foreach (var (port, service) in serviceMap)
            {
                var (_, stdout, _) = await _toolRunner.RunAsync(
                    "hydra",
                    $"-L /usr/share/seclists/Usernames/top-usernames-shortlist.txt " +
                    $"-P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt " +
                    $"-t 4 {host} {service} -s {port} -f",
                    120, cancellationToken);

                if (stdout.Contains("[{port}]") || stdout.Contains("[SUCCESS]"))
                {
                    var credMatch = Regex.Match(stdout, @"login: (\S+)\s+password: (\S+)");
                    if (credMatch.Success)
                    {
                        findings.Add(Finding.Create(
                            Severity.Critical, FindingCategory.BruteForce,
                            $"Valid credentials found on {host}:{port} ({service}): {credMatch.Groups[1].Value}",
                            remediation: "Change credentials immediately. Implement account lockout and MFA.",
                            impact: 9.0, confidence: 0.98,
                            vulnType: "default_creds", isConfirmed: true));
                    }
                }
            }
        }

        return findings;
    }

    private static List<(string Url, Dictionary<string, string> Params)> BuildInjectableEndpoints(
        List<string> endpoints)
    {
        var result = new List<(string, Dictionary<string, string>)>();

        foreach (var endpoint in endpoints)
        {
            if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)) continue;
            if (string.IsNullOrEmpty(uri.Query)) continue;

            var clean = $"{uri.Scheme}://{uri.Host}{uri.AbsolutePath}";
            var parameters = ParseQueryString(uri.Query);
            if (parameters.Count == 0) continue;

            result.Add((clean, parameters));
        }

        // Add default injectable params if none found
        if (result.Count == 0)
        {
            result.Add(($"https://placeholder", new Dictionary<string, string> { ["id"] = "1", ["q"] = "test" }));
        }

        return result.Take(20).ToList();
    }

    private static Dictionary<string, string> ParseQueryString(string query)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var q = query.TrimStart('?');
        foreach (var pair in q.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0]);
            var value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : "1";
            result.TryAdd(key, value);
        }
        return result;
    }

    private HttpClient CreateHttpClient(ScanConfiguration configuration)
    {
        var client = _httpClientFactory.CreateClient("scanner");
        client.DefaultRequestHeaders.Add("User-Agent",
            configuration.UserAgent ?? "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0");
        client.Timeout = TimeSpan.FromSeconds(configuration.RequestTimeout);
        return client;
    }

    private static Dictionary<string, CveEntry> BuildCveDatabase() => new()
    {
        ["CVE-2021-44228"] = new("Log4Shell — Apache Log4j2 RCE", "CRITICAL",
            ["log4j", "log4j2", "apache log4"],
            "JNDI injection allows unauthenticated RCE via log messages.",
            "Upgrade Log4j2 to 2.17.1+."),
        ["CVE-2021-26855"] = new("ProxyLogon — Microsoft Exchange SSRF → RCE", "CRITICAL",
            ["Microsoft Exchange", "OWA", "Exchange Server"],
            "SSRF in Exchange leads to pre-auth RCE.",
            "Apply Microsoft security updates immediately."),
        ["CVE-2022-22965"] = new("Spring4Shell — Spring Framework RCE", "CRITICAL",
            ["Spring Framework", "Spring MVC", "Spring Boot"],
            "ClassLoader manipulation leads to RCE.",
            "Upgrade Spring Framework to 5.3.18+ or 5.2.20+."),
        ["CVE-2019-0708"] = new("BlueKeep — Windows RDP Pre-auth RCE", "CRITICAL",
            ["rdp", "remote desktop", "windows"],
            "Wormable pre-auth RCE via RDP.",
            "Apply KB4499175. Disable NLA if not needed."),
        ["CVE-2017-0144"] = new("EternalBlue — SMBv1 RCE", "CRITICAL",
            ["smb", "samba", "microsoft-ds"],
            "NSA exploit used by WannaCry/NotPetya.",
            "Disable SMBv1. Apply MS17-010."),
        ["CVE-2020-1472"] = new("Zerologon — Netlogon Domain Takeover", "CRITICAL",
            ["netlogon", "active directory", "domain controller"],
            "Unauthenticated attacker can become domain admin.",
            "Apply KB4557222."),
        ["CVE-2023-44487"] = new("HTTP/2 Rapid Reset DDoS", "HIGH",
            ["nginx", "apache", "http/2"],
            "HTTP/2 rapid reset allows amplified DDoS.",
            "Update web server and limit stream concurrency."),
        ["CVE-2021-41773"] = new("Apache 2.4.49 Path Traversal/RCE", "CRITICAL",
            ["Apache/2.4.49", "Apache HTTP Server 2.4.49"],
            "Path traversal in CGI allows RCE.",
            "Upgrade Apache to 2.4.51+."),
        ["CVE-2022-0778"] = new("OpenSSL Infinite Loop DoS", "HIGH",
            ["OpenSSL", "openssl"],
            "BN_mod_sqrt() infinite loop causes DoS.",
            "Upgrade OpenSSL to 1.0.2zd / 1.1.1n / 3.0.2."),
        ["CVE-2021-22205"] = new("GitLab CE/EE RCE via ExifTool", "CRITICAL",
            ["gitlab", "GitLab"],
            "Unauthenticated RCE via image upload.",
            "Upgrade GitLab to 13.10.3+."),
        ["CVE-2023-34362"] = new("MOVEit Transfer SQL Injection", "CRITICAL",
            ["MOVEit", "moveit"],
            "SQLi → RCE in MOVEit Transfer.",
            "Apply MOVEit security patch immediately."),
        ["CVE-2024-3400"] = new("PAN-OS GlobalProtect Command Injection", "CRITICAL",
            ["PAN-OS", "GlobalProtect", "Palo Alto"],
            "Unauthenticated command injection → root RCE.",
            "Apply PAN-OS security update."),
    };
}

internal sealed record CveEntry(
    string Title,
    string Severity,
    string[] Keywords,
    string Description,
    string Fix);
