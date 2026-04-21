using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using GhostScan.Infrastructure.Tools;
using HtmlAgilityPack;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

public sealed class WebAnalysisScanModule : IScanModule
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ExternalToolRunner _toolRunner;
    private readonly ILogger<WebAnalysisScanModule> _logger;

    private static readonly string[] InterestingPaths =
    [
        "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
        "/robots.txt", "/sitemap.xml", "/wp-config.php", "/wp-login.php", "/wp-admin/",
        "/phpinfo.php", "/info.php", "/.htaccess", "/.htpasswd", "/server-status",
        "/backup.zip", "/backup.sql", "/dump.sql", "/db.sql",
        "/admin/", "/administrator/", "/manage/", "/dashboard/", "/panel/",
        "/api/", "/api/v1/", "/api/v2/", "/swagger.json", "/swagger-ui.html",
        "/openapi.json", "/api-docs", "/actuator/health", "/actuator/env",
        "/graphql", "/graphiql", "/h2-console", "/adminer.php", "/phpmyadmin/",
        "/config.php", "/config.json", "/appsettings.json", "/web.config",
        "/.DS_Store", "/crossdomain.xml", "/security.txt", "/.well-known/security.txt",
        "/trace", "/console", "/debug", "/jolokia/", "/metrics", "/health",
        "/login", "/signin", "/auth/login", "/user/login",
    ];

    private static readonly Dictionary<string, Regex> SecretPatterns = new()
    {
        ["AWS Access Key"]   = new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled),
        ["Generic API Key"]  = new Regex(@"(?i)(api[_-]?key|apikey)\s*[:=]\s*['""][a-zA-Z0-9_\-]{20,}['""]", RegexOptions.Compiled),
        ["Bearer Token"]     = new Regex(@"(?i)bearer\s+[a-zA-Z0-9\-_=]{20,}", RegexOptions.Compiled),
        ["Private Key"]      = new Regex(@"-----BEGIN (RSA |EC )?PRIVATE KEY-----", RegexOptions.Compiled),
        ["Password in Code"] = new Regex(@"(?i)(password|passwd|pwd)\s*[:=]\s*['""][^'""]{6,}['""]", RegexOptions.Compiled),
        ["JWT Token"]        = new Regex(@"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", RegexOptions.Compiled),
        ["Google API Key"]   = new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.Compiled),
        ["GitHub Token"]     = new Regex(@"ghp_[0-9a-zA-Z]{36}", RegexOptions.Compiled),
        ["Database DSN"]     = new Regex(@"(?i)(mysql|postgres|mongodb|redis)://[^\s'""]+", RegexOptions.Compiled),
    };

    private static readonly Dictionary<string, string[]> SecurityHeaders = new()
    {
        ["Strict-Transport-Security"] = ["HIGH",   "HSTS not set. Downgrade attacks possible.",   "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"],
        ["Content-Security-Policy"]   = ["HIGH",   "No CSP. XSS attacks lack browser mitigation.", "Implement a strict Content-Security-Policy."],
        ["X-Frame-Options"]           = ["MEDIUM", "Clickjacking possible.",                        "X-Frame-Options: DENY"],
        ["X-Content-Type-Options"]    = ["MEDIUM", "MIME sniffing attacks possible.",               "X-Content-Type-Options: nosniff"],
        ["Referrer-Policy"]           = ["LOW",    "Referrer leaks internal URLs.",                 "Referrer-Policy: strict-origin-when-cross-origin"],
        ["Permissions-Policy"]        = ["LOW",    "Browser permissions unconstrained.",            "Permissions-Policy: camera=(), microphone=(), geolocation=()"],
    };

    private static readonly string[] DangerousHeaders =
        ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"];

    public string Name => "WebAnalysis";

    public WebAnalysisScanModule(
        IHttpClientFactory httpClientFactory,
        ExternalToolRunner toolRunner,
        ILogger<WebAnalysisScanModule> logger)
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
            var baseUrls = BuildBaseUrls(target);
            data["base_urls"] = baseUrls;
            context.Set("base_urls", baseUrls);

            var httpClient = CreateHttpClient(configuration);

            // 1. WAF Detection
            _logger.LogInformation("[Web] WAF detection for {Target}", target.Value);
            var wafResult = await DetectWafAsync(baseUrls.First(), httpClient, cancellationToken);
            data["waf"] = wafResult;

            // 2. Interesting path probing
            _logger.LogInformation("[Web] Probing {Count} interesting paths", InterestingPaths.Length);
            var (discoveredEndpoints, pathFindings) = await ProbeInterestingPathsAsync(
                baseUrls.First(), httpClient, cancellationToken);
            findings.AddRange(pathFindings);
            data["endpoints"] = discoveredEndpoints;
            context.Set("endpoints", discoveredEndpoints);

            // 3. Web crawling for endpoints + forms
            _logger.LogInformation("[Web] Crawling {Url}", baseUrls.First());
            var (crawledEndpoints, forms) = await CrawlAsync(
                baseUrls.First(), httpClient, configuration.CrawlDepth, cancellationToken);
            foreach (var ep in crawledEndpoints)
            {
                if (!discoveredEndpoints.Contains(ep))
                    discoveredEndpoints.Add(ep);
            }
            data["forms"] = forms;
            context.Set("forms", forms);

            // 4. Security header audit
            _logger.LogInformation("[Web] Security header audit");
            var headerFindings = await AuditSecurityHeadersAsync(
                baseUrls.First(), httpClient, cancellationToken);
            findings.AddRange(headerFindings);

            // 5. JS secret scanning
            _logger.LogInformation("[Web] Scanning JavaScript files for secrets");
            var (jsSecrets, secretFindings) = await ScanJavaScriptSecretsAsync(
                discoveredEndpoints, httpClient, target.Value, cancellationToken);
            findings.AddRange(secretFindings);
            data["js_secrets"] = jsSecrets;
            context.Set("js_secrets", jsSecrets);

            // 6. Technology detection (whatweb)
            if (_toolRunner.IsAvailable("whatweb"))
            {
                var technologies = await RunWhatWebAsync(baseUrls.First(), cancellationToken);
                data["technologies"] = technologies;
                context.Set("technologies", technologies);
            }

            // 7. Dir brute-force (gobuster / ffuf)
            var dirBrute = await RunDirectoryBruteAsync(baseUrls.First(), configuration, cancellationToken);
            data["dir_brute"] = dirBrute;

            return ScanModuleResult.Succeeded(findings, data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Web] Error analyzing {Target}", target.Value);
            return ScanModuleResult.Failed($"Web analysis error: {ex.Message}");
        }
    }

    private async Task<(Dictionary<string, object> WafInfo, bool Detected)> DetectWafAsync(
        string baseUrl, HttpClient httpClient, CancellationToken cancellationToken)
    {
        var wafInfo = new Dictionary<string, object> { ["detected"] = false, ["name"] = "" };

        if (_toolRunner.IsAvailable("wafw00f"))
        {
            var (_, stdout, _) = await _toolRunner.RunAsync("wafw00f", $"-a {baseUrl} -o -", 60, cancellationToken);
            if (stdout.Contains("is behind", StringComparison.OrdinalIgnoreCase) ||
                stdout.Contains("WAF detected", StringComparison.OrdinalIgnoreCase))
            {
                wafInfo["detected"] = true;
                var wafMatch = Regex.Match(stdout, @"is behind (.+?) WAF", RegexOptions.IgnoreCase);
                if (wafMatch.Success)
                    wafInfo["name"] = wafMatch.Groups[1].Value.Trim();
            }
            return (wafInfo, (bool)wafInfo["detected"]);
        }

        // Fallback: header-based detection
        try
        {
            var response = await httpClient.GetAsync(baseUrl, cancellationToken);
            var headers = response.Headers.Concat(response.Content.Headers);
            var headerString = string.Join(" ", headers.Select(h => $"{h.Key}: {string.Join(",", h.Value)}"));

            var wafSignatures = new Dictionary<string, string[]>
            {
                ["Cloudflare"] = ["cf-ray", "cf-cache-status", "__cfduid"],
                ["Akamai"]     = ["x-akamai", "akamai-origin-hop"],
                ["AWS WAF"]    = ["x-amzn-requestid", "x-amz-cf-id"],
                ["Imperva"]    = ["x-iinfo", "visid_incap"],
                ["F5 BIG-IP"]  = ["x-wa-info", "x-cnection"],
            };

            foreach (var (wafName, signatures) in wafSignatures)
            {
                if (signatures.Any(sig => headerString.Contains(sig, StringComparison.OrdinalIgnoreCase)))
                {
                    wafInfo["detected"] = true;
                    wafInfo["name"] = wafName;
                    return (wafInfo, true);
                }
            }
        }
        catch { }

        return (wafInfo, false);
    }

    private async Task<(List<string> Endpoints, List<Finding> Findings)> ProbeInterestingPathsAsync(
        string baseUrl, HttpClient httpClient, CancellationToken cancellationToken)
    {
        var endpoints = new List<string>();
        var findings = new List<Finding>();
        var semaphore = new SemaphoreSlim(20);

        var tasks = InterestingPaths.Select(async path =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                var url = $"{baseUrl.TrimEnd('/')}{path}";
                var response = await httpClient.GetAsync(url, cancellationToken);

                if (response.IsSuccessStatusCode)
                {
                    endpoints.Add(url);
                    var finding = CreateFindingForSensitivePath(path, url, (int)response.StatusCode);
                    if (finding is not null)
                        return (url, finding);
                }
                else if ((int)response.StatusCode == 403)
                {
                    // 403 means it exists but is protected — still interesting
                    endpoints.Add(url);
                }
            }
            catch { }
            finally
            {
                semaphore.Release();
            }
            return ((string?)null, (Finding?)null);
        });

        var results = await Task.WhenAll(tasks);
        foreach (var (url, finding) in results.Where(r => r.Item1 is not null))
        {
            if (finding is not null)
                findings.Add(finding);
        }

        return (endpoints, findings);
    }

    private static Finding? CreateFindingForSensitivePath(string path, string url, int statusCode)
    {
        var criticalPaths = new[] { "/.env", "/.git/config", "/wp-config.php", "/.htpasswd",
                                    "/dump.sql", "/backup.sql", "/.git/HEAD" };
        var highPaths = new[] { "/phpinfo.php", "/server-status", "/adminer.php",
                                "/phpmyadmin/", "/h2-console", "/actuator/env" };
        var mediumPaths = new[] { "/swagger.json", "/openapi.json", "/api-docs",
                                   "/graphiql", "/swagger-ui.html" };

        if (criticalPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            return Finding.Create(
                Severity.Critical, FindingCategory.Web,
                $"Sensitive file exposed: {path}",
                detail: $"HTTP {statusCode} — critical file accessible.",
                url: url,
                remediation: $"Block access to {path} via web server configuration.",
                impact: 10.0, confidence: 0.99,
                vulnType: path.Contains(".env") ? "env_exposed" : "git_exposed",
                isConfirmed: true);
        }

        if (highPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            return Finding.Create(
                Severity.High, FindingCategory.Web,
                $"Admin/debug interface exposed: {path}",
                detail: $"HTTP {statusCode} — admin interface accessible without authentication.",
                url: url,
                remediation: $"Restrict access to {path} to trusted IPs only.",
                impact: 8.0, confidence: 0.95);
        }

        if (mediumPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
        {
            return Finding.Create(
                Severity.Medium, FindingCategory.Web,
                $"API specification exposed: {path}",
                detail: $"HTTP {statusCode} — API documentation publicly accessible.",
                url: url,
                remediation: $"Restrict {path} access. API specs aid attackers.",
                impact: 5.0, confidence: 0.99);
        }

        return null;
    }

    private async Task<(List<string> Endpoints, List<Dictionary<string, string>> Forms)> CrawlAsync(
        string baseUrl, HttpClient httpClient, int depth, CancellationToken cancellationToken)
    {
        var visited = new HashSet<string>();
        var endpoints = new List<string>();
        var forms = new List<Dictionary<string, string>>();
        var queue = new Queue<(string Url, int Depth)>();

        queue.Enqueue((baseUrl, 0));
        visited.Add(baseUrl);

        while (queue.Count > 0 && !cancellationToken.IsCancellationRequested)
        {
            var (url, currentDepth) = queue.Dequeue();
            if (currentDepth > depth) continue;

            try
            {
                var response = await httpClient.GetAsync(url, cancellationToken);
                if (!response.IsSuccessStatusCode) continue;

                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                var contentType = response.Content.Headers.ContentType?.MediaType ?? "";

                if (!contentType.Contains("html")) continue;

                endpoints.Add(url);

                var doc = new HtmlDocument();
                doc.LoadHtml(content);

                // Extract links
                var linkNodes = doc.DocumentNode.SelectNodes("//a[@href]");
                foreach (var node in linkNodes ?? Enumerable.Empty<HtmlNode>())
                {
                    var href = node.GetAttributeValue("href", "");
                    var absoluteUrl = ResolveUrl(baseUrl, href);
                    if (absoluteUrl is not null && IsInScope(absoluteUrl, baseUrl) && visited.Add(absoluteUrl))
                        queue.Enqueue((absoluteUrl, currentDepth + 1));
                }

                // Extract forms
                var formNodes = doc.DocumentNode.SelectNodes("//form");
                foreach (var formNode in formNodes ?? Enumerable.Empty<HtmlNode>())
                {
                    var action = formNode.GetAttributeValue("action", url);
                    var method = formNode.GetAttributeValue("method", "GET").ToUpperInvariant();
                    var absAction = ResolveUrl(baseUrl, action) ?? action;

                    var form = new Dictionary<string, string>
                    {
                        ["action"] = absAction,
                        ["method"] = method,
                    };
                    forms.Add(form);
                }
            }
            catch { }
        }

        return (endpoints, forms);
    }

    private async Task<List<Finding>> AuditSecurityHeadersAsync(
        string baseUrl, HttpClient httpClient, CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();
        try
        {
            var response = await httpClient.GetAsync(baseUrl, cancellationToken);
            var headers = response.Headers.ToDictionary(
                h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);

            foreach (var (headerName, info) in SecurityHeaders)
            {
                if (!headers.ContainsKey(headerName))
                {
                    var severity = Severity.FromString(info[0]).Value ?? Severity.Medium;
                    findings.Add(Finding.Create(
                        severity, FindingCategory.Headers,
                        $"Missing security header: {headerName}",
                        detail: info[1],
                        url: baseUrl,
                        remediation: info[2],
                        impact: severity == Severity.High ? 5.0 : 3.0,
                        confidence: 0.99,
                        vulnType: headerName.Contains("CSP") ? "missing_csp"
                               : headerName.Contains("Transport") ? "missing_hsts"
                               : "info_disclosure"));
                }
            }

            foreach (var dangerousHeader in DangerousHeaders)
            {
                if (headers.TryGetValue(dangerousHeader, out var value))
                {
                    findings.Add(Finding.Create(
                        Severity.Low, FindingCategory.Headers,
                        $"Information disclosure via {dangerousHeader}: {value}",
                        detail: $"Server version/technology exposed in {dangerousHeader} header.",
                        url: baseUrl,
                        remediation: $"Remove or sanitize the {dangerousHeader} header.",
                        impact: 2.0, confidence: 0.99,
                        vulnType: "info_disclosure"));
                }
            }

            // Check CORS
            if (headers.TryGetValue("Access-Control-Allow-Origin", out var acao) &&
                headers.TryGetValue("Access-Control-Allow-Credentials", out var acac))
            {
                if (acao == "*" && acac.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(Finding.Create(
                        Severity.High, FindingCategory.Cors,
                        "CORS misconfiguration: wildcard origin with credentials",
                        detail: "ACAO=* combined with Allow-Credentials=true allows credential theft.",
                        url: baseUrl,
                        remediation: "Never combine wildcard ACAO with Allow-Credentials: true.",
                        impact: 7.0, confidence: 0.95,
                        vulnType: "default"));
                }
            }

            // Check cookies
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var cookie in cookies)
                {
                    var issues = new List<string>();
                    if (!cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase))
                        issues.Add("missing Secure flag");
                    if (!cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
                        issues.Add("missing HttpOnly flag");
                    if (!cookie.Contains("SameSite", StringComparison.OrdinalIgnoreCase))
                        issues.Add("missing SameSite attribute");

                    if (issues.Count > 0)
                    {
                        var cookieName = cookie.Split('=')[0].Trim();
                        findings.Add(Finding.Create(
                            Severity.Medium, FindingCategory.Cookie,
                            $"Insecure cookie '{cookieName}': {string.Join(", ", issues)}",
                            url: baseUrl,
                            remediation: "Set Secure; HttpOnly; SameSite=Strict on all session cookies.",
                            impact: 3.0, confidence: 0.95,
                            vulnType: "cookie_insecure"));
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Web] Header audit failed for {Url}", baseUrl);
        }

        return findings;
    }

    private async Task<(List<Dictionary<string, string>> Secrets, List<Finding> Findings)> ScanJavaScriptSecretsAsync(
        List<string> endpoints, HttpClient httpClient, string target, CancellationToken cancellationToken)
    {
        var secrets = new List<Dictionary<string, string>>();
        var findings = new List<Finding>();

        var jsUrls = endpoints
            .Where(e => e.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
            .Take(30)
            .ToList();

        foreach (var jsUrl in jsUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, cancellationToken);

                foreach (var (secretType, pattern) in SecretPatterns)
                {
                    var match = pattern.Match(content);
                    if (!match.Success) continue;

                    var secretValue = match.Value;
                    if (secretValue.Length > 100) secretValue = secretValue[..100] + "...";

                    secrets.Add(new Dictionary<string, string>
                    {
                        ["type"] = secretType,
                        ["value"] = secretValue,
                        ["url"] = jsUrl,
                    });

                    findings.Add(Finding.Create(
                        Severity.Critical, FindingCategory.Web,
                        $"{secretType} found in JavaScript: {jsUrl}",
                        detail: $"Secret type '{secretType}' hardcoded in client-side JS.",
                        url: jsUrl,
                        evidence: secretValue.Length > 50 ? secretValue[..50] + "..." : secretValue,
                        remediation: "Remove ALL secrets from client-side code. Rotate exposed keys IMMEDIATELY.",
                        impact: 10.0, confidence: 0.95,
                        vulnType: secretType.Contains("AWS") ? "aws_key" : "env_exposed",
                        isConfirmed: true));
                }
            }
            catch { }
        }

        return (secrets, findings);
    }

    private async Task<Dictionary<string, object>> RunWhatWebAsync(
        string baseUrl, CancellationToken cancellationToken)
    {
        var tech = new Dictionary<string, object> { ["server"] = new List<string>(), ["cms"] = new List<string>() };

        var (_, stdout, _) = await _toolRunner.RunAsync(
            "whatweb", $"--no-errors -a 1 {baseUrl}", 60, cancellationToken);

        // Parse whatweb output for technology identification
        var matches = Regex.Matches(stdout, @"\[([^\]]+)\]");
        var serverList = (List<string>)tech["server"];
        var cmsList = (List<string>)tech["cms"];

        foreach (Match m in matches)
        {
            var techName = m.Groups[1].Value;
            if (techName.Contains("WordPress") || techName.Contains("Drupal") || techName.Contains("Joomla"))
                cmsList.Add(techName);
            else if (techName.Contains("Apache") || techName.Contains("nginx") || techName.Contains("IIS"))
                serverList.Add(techName);
        }

        return tech;
    }

    private async Task<List<Dictionary<string, object>>> RunDirectoryBruteAsync(
        string baseUrl, ScanConfiguration configuration, CancellationToken cancellationToken)
    {
        var results = new List<Dictionary<string, object>>();

        if (_toolRunner.IsAvailable("gobuster"))
        {
            var wordlist = GetWordlistPath(configuration.Profile.WordlistSize);
            if (wordlist is not null)
            {
                var (_, stdout, _) = await _toolRunner.RunAsync(
                    "gobuster", $"dir -u {baseUrl} -w {wordlist} -q --no-error -t 20",
                    300, cancellationToken);

                foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                {
                    var match = Regex.Match(line, @"(/[^\s]+)\s+\(Status: (\d+)\)");
                    if (match.Success)
                    {
                        results.Add(new Dictionary<string, object>
                        {
                            ["path"] = match.Groups[1].Value,
                            ["status"] = int.Parse(match.Groups[2].Value),
                        });
                    }
                }
            }
        }
        else if (_toolRunner.IsAvailable("ffuf"))
        {
            var wordlist = GetWordlistPath(configuration.Profile.WordlistSize);
            if (wordlist is not null)
            {
                var (_, stdout, _) = await _toolRunner.RunAsync(
                    "ffuf", $"-u {baseUrl}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -of json",
                    300, cancellationToken);
                // Parse ffuf JSON output
                // ... (simplified)
            }
        }

        return results;
    }

    private static string? GetWordlistPath(string size) => size switch
    {
        "small"     => FindWordlist("/usr/share/wordlists/dirb/small.txt", "/usr/share/seclists/Discovery/Web-Content/big.txt"),
        "large"     => FindWordlist("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt"),
        _ =>            FindWordlist("/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
                                     "/usr/share/wordlists/dirb/common.txt"),
    };

    private static string? FindWordlist(params string[] paths) =>
        paths.FirstOrDefault(File.Exists);

    private HttpClient CreateHttpClient(ScanConfiguration configuration)
    {
        var client = _httpClientFactory.CreateClient("scanner");
        client.DefaultRequestHeaders.Add("User-Agent",
            configuration.UserAgent ?? "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0");
        client.Timeout = TimeSpan.FromSeconds(configuration.RequestTimeout);
        return client;
    }

    private static List<string> BuildBaseUrls(ScanTarget target)
    {
        if (target.IsIpAddress || target.IsCidr)
            return [$"http://{target.Value}", $"https://{target.Value}"];

        return [$"https://{target.Value}", $"http://{target.Value}"];
    }

    private static string? ResolveUrl(string baseUrl, string href)
    {
        if (string.IsNullOrWhiteSpace(href) || href.StartsWith('#') || href.StartsWith("javascript:"))
            return null;

        if (Uri.TryCreate(href, UriKind.Absolute, out var absolute))
            return absolute.ToString();

        if (Uri.TryCreate(new Uri(baseUrl), href, out var resolved))
            return resolved.ToString();

        return null;
    }

    private static bool IsInScope(string url, string baseUrl)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return false;
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)) return false;
        return uri.Host.Equals(baseUri.Host, StringComparison.OrdinalIgnoreCase);
    }
}
