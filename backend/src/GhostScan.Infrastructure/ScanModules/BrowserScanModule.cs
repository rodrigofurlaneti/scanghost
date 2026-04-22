using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using GhostScan.Infrastructure.Tools;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

/// <summary>
/// Headless browser module — mirrors browser.py from the Python POC.
/// Performs DOM XSS detection, WebSocket discovery, storage secret analysis,
/// source map exposure checks, and dangling JS detection.
///
/// Uses the 'playwright' CLI tool when available; falls back to static HTTP
/// analysis when it is not installed.
/// </summary>
public sealed class BrowserScanModule : IScanModule
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ExternalToolRunner _toolRunner;
    private readonly ILogger<BrowserScanModule> _logger;

    // DOM XSS sinks — dangerous JS sinks where user-controlled data lands
    private static readonly string[] DomXssSinks =
    [
        "innerHTML", "outerHTML", "insertAdjacentHTML",
        "document.write", "document.writeln",
        "eval(", "setTimeout(", "setInterval(",
        "Function(", "location.href", "location.assign", "location.replace",
        "window.open(", "document.domain", "document.cookie",
        ".html(", "jQuery.html(",
    ];

    // DOM XSS sources — user-controllable data
    private static readonly string[] DomXssSources =
    [
        "location.search", "location.hash", "location.href",
        "document.referrer", "document.URL",
        "window.name", "localStorage", "sessionStorage",
        "URLSearchParams", "document.cookie",
    ];

    // Source map url patterns
    private static readonly Regex SourceMapPattern = new(
        @"(?://# sourceMappingURL=|//@ sourceMappingURL=)(\S+\.map)", RegexOptions.Compiled);

    // WebSocket URL patterns in JS source
    private static readonly Regex WsPattern = new(
        @"new\s+WebSocket\s*\(\s*['""`](wss?://[^'""` ]+)['""`]", RegexOptions.Compiled);

    // localStorage/sessionStorage sensitive key patterns
    private static readonly Regex[] StorageSecretPatterns =
    [
        new(@"(?:localStorage|sessionStorage)\.setItem\s*\(['""]([^'""]*(?:token|key|secret|password|jwt|auth|credential)[^'""]*)['""]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
        new(@"(?:localStorage|sessionStorage)\.getItem\s*\(['""]([^'""]*(?:token|key|secret|password|jwt|auth)[^'""]*)['""]", RegexOptions.IgnoreCase | RegexOptions.Compiled),
    ];

    // Dangling/unclaimed JS includes — paths that look external
    private static readonly Regex ExternalScriptPattern = new(
        @"<script[^>]+src=['""]?(https?://[^'""> ]+\.js)['""]?", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public string Name => "Browser";

    public BrowserScanModule(
        IHttpClientFactory httpClientFactory,
        ExternalToolRunner toolRunner,
        ILogger<BrowserScanModule> logger)
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

        var baseUrls = context.Get<List<string>>("base_urls")
            ?? [$"https://{target.Value}", $"http://{target.Value}"];
        var baseUrl = baseUrls.First();
        var endpoints = context.Get<List<string>>("endpoints") ?? [];

        try
        {
            var httpClient = CreateHttpClient(configuration);

            // Collect all JS URLs from known endpoints
            var jsUrls = endpoints
                .Where(e => e.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
                .Distinct()
                .Take(40)
                .ToList();

            // 1. Static DOM XSS sink/source analysis
            _logger.LogInformation("[Browser] Static DOM XSS analysis ({Count} JS files)", jsUrls.Count);
            var domXssFindings = await AnalyseDomXssStaticAsync(jsUrls, baseUrl, httpClient, cancellationToken);
            findings.AddRange(domXssFindings);
            data["dom_xss"] = domXssFindings.Count;

            // 2. WebSocket discovery
            _logger.LogInformation("[Browser] WebSocket endpoint discovery");
            var wsEndpoints = await DiscoverWebSocketsAsync(jsUrls, baseUrl, httpClient, cancellationToken);
            data["websockets"] = wsEndpoints;
            if (wsEndpoints.Count > 0)
            {
                context.Set("websockets", wsEndpoints);
                findings.Add(Finding.Create(
                    Severity.Info, FindingCategory.Web,
                    $"WebSocket endpoint(s) discovered: {wsEndpoints.Count}",
                    detail: $"Endpoints: {string.Join(", ", wsEndpoints.Take(3))}. "
                          + "Test for authentication, injection, and message tampering.",
                    url: wsEndpoints[0],
                    remediation: "Ensure WebSocket endpoints enforce authentication and input validation.",
                    impact: 3.0, confidence: 0.90));
            }

            // 3. Client-side storage secret analysis
            _logger.LogInformation("[Browser] Client-side storage analysis");
            var storageFindings = await AnalyseClientStorageAsync(jsUrls, baseUrl, httpClient, cancellationToken);
            findings.AddRange(storageFindings);
            data["storage_issues"] = storageFindings.Count;

            // 4. Source map exposure
            _logger.LogInformation("[Browser] Source map exposure check");
            var sourceMapFindings = await CheckSourceMapsAsync(jsUrls, baseUrl, httpClient, cancellationToken);
            findings.AddRange(sourceMapFindings);
            data["source_maps"] = sourceMapFindings.Count;

            // 5. Dangling JS detection
            _logger.LogInformation("[Browser] Dangling/external JS detection");
            var danglingFindings = await DetectDanglingJsAsync(endpoints, baseUrl, httpClient, cancellationToken);
            findings.AddRange(danglingFindings);
            data["dangling_js"] = danglingFindings.Count;

            // 6. Playwright dynamic analysis (if available)
            if (_toolRunner.IsAvailable("playwright") || _toolRunner.IsAvailable("npx"))
            {
                _logger.LogInformation("[Browser] Playwright dynamic analysis");
                var playwrightFindings = await RunPlaywrightAnalysisAsync(
                    baseUrl, configuration, cancellationToken);
                findings.AddRange(playwrightFindings);
                data["playwright_available"] = true;
            }
            else
            {
                _logger.LogDebug("[Browser] Playwright not available — static analysis only");
                data["playwright_available"] = false;
            }

            context.Set("browser_dom_xss", domXssFindings.Count);
            return ScanModuleResult.Succeeded(findings, data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Browser] Error in browser analysis for {Target}", target.Value);
            return ScanModuleResult.Failed($"Browser analysis error: {ex.Message}");
        }
    }

    // ── Static DOM XSS Analysis ───────────────────────────────────────────────

    private async Task<List<Finding>> AnalyseDomXssStaticAsync(
        List<string> jsUrls, string baseUrl, HttpClient httpClient, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var seen = new HashSet<string>();

        foreach (var jsUrl in jsUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);

                // Find sink+source co-occurrence in same script block (within 500 chars)
                foreach (var sink in DomXssSinks)
                {
                    var sinkIdx = content.IndexOf(sink, StringComparison.Ordinal);
                    if (sinkIdx < 0) continue;

                    var windowStart = Math.Max(0, sinkIdx - 500);
                    var windowEnd   = Math.Min(content.Length, sinkIdx + 500);
                    var window      = content[windowStart..windowEnd];

                    foreach (var source in DomXssSources)
                    {
                        if (!window.Contains(source, StringComparison.Ordinal)) continue;

                        var key = $"{sink}|{source}";
                        if (!seen.Add(key)) continue;

                        var snippet = window[..Math.Min(window.Length, 200)].ReplaceLineEndings(" ");

                        findings.Add(Finding.Create(
                            Severity.High, FindingCategory.XSS,
                            $"DOM XSS pattern: {sink} ← {source}",
                            detail: $"User-controlled source '{source}' flows into dangerous sink '{sink}'. "
                                  + $"File: {jsUrl}",
                            evidence: snippet,
                            url: jsUrl,
                            remediation: "Sanitize user-controlled sources before passing to dangerous sinks. "
                                       + "Use DOMPurify or framework-level sanitization.",
                            impact: 7.0, confidence: 0.55,
                            vulnType: "dom_xss",
                            attackPath: "URL parameter → JS variable → innerHTML → XSS"));
                        break; // one finding per sink per file
                    }
                }
            }
            catch { }
        }

        _logger.LogInformation("[Browser] DOM XSS static: {Count} patterns found", findings.Count);
        return findings;
    }

    // ── WebSocket Discovery ───────────────────────────────────────────────────

    private async Task<List<string>> DiscoverWebSocketsAsync(
        List<string> jsUrls, string baseUrl, HttpClient httpClient, CancellationToken ct)
    {
        var wsEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var jsUrl in jsUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);
                foreach (Match m in WsPattern.Matches(content))
                    wsEndpoints.Add(m.Groups[1].Value);
            }
            catch { }
        }

        // Also probe common WS paths
        var commonWsPaths = new[] { "/ws", "/websocket", "/socket.io", "/events", "/live", "/stream" };
        foreach (var path in commonWsPaths)
        {
            var wsUrl = baseUrl
                .Replace("https://", "wss://", StringComparison.OrdinalIgnoreCase)
                .Replace("http://",  "ws://",  StringComparison.OrdinalIgnoreCase)
                .TrimEnd('/') + path;
            wsEndpoints.Add(wsUrl);
        }

        return wsEndpoints.Take(10).ToList();
    }

    // ── Client-Side Storage Analysis ──────────────────────────────────────────

    private async Task<List<Finding>> AnalyseClientStorageAsync(
        List<string> jsUrls, string baseUrl, HttpClient httpClient, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var seen = new HashSet<string>();

        foreach (var jsUrl in jsUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);

                foreach (var pattern in StorageSecretPatterns)
                {
                    foreach (Match m in pattern.Matches(content))
                    {
                        var keyName = m.Groups[1].Value;
                        if (!seen.Add(keyName)) continue;

                        findings.Add(Finding.Create(
                            Severity.High, FindingCategory.Web,
                            $"Sensitive data key stored in browser storage: '{keyName}'",
                            detail: $"Client-side code stores sensitive data (key: '{keyName}') "
                                  + "in localStorage/sessionStorage. Accessible to any JavaScript on the page.",
                            url: jsUrl,
                            remediation: "Avoid storing tokens/secrets in localStorage. Use HttpOnly cookies "
                                       + "or in-memory state. Apply strict CSP to limit XSS.",
                            impact: 6.0, confidence: 0.65,
                            vulnType: "insecure_storage"));
                    }
                }
            }
            catch { }
        }

        return findings;
    }

    // ── Source Map Exposure ───────────────────────────────────────────────────

    private async Task<List<Finding>> CheckSourceMapsAsync(
        List<string> jsUrls, string baseUrl, HttpClient httpClient, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var checked_ = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var jsUrl in jsUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);
                var match = SourceMapPattern.Match(content);
                if (!match.Success) continue;

                var mapPath = match.Groups[1].Value;
                string mapUrl;
                if (mapPath.StartsWith("http")) mapUrl = mapPath;
                else if (Uri.TryCreate(new Uri(jsUrl), mapPath, out var resolved)) mapUrl = resolved.ToString();
                else continue;

                if (!checked_.Add(mapUrl)) continue;

                // Check if the map file is actually accessible
                var headResp = await httpClient.GetAsync(mapUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!headResp.IsSuccessStatusCode) continue;

                findings.Add(Finding.Create(
                    Severity.High, FindingCategory.Web,
                    $"Source map exposed: {mapUrl}",
                    detail: "The .map file exposes the original un-minified source code, "
                          + "including comments, variable names, and internal logic.",
                    url: mapUrl,
                    remediation: "Remove source maps from production builds or restrict access "
                               + "to trusted IPs. Set 'devtool: false' in webpack config.",
                    impact: 5.0, confidence: 0.99,
                    vulnType: "source_map_exposure"));
            }
            catch { }
        }

        return findings;
    }

    // ── Dangling JS Detection ─────────────────────────────────────────────────

    private async Task<List<Finding>> DetectDanglingJsAsync(
        List<string> endpoints, string baseUrl, HttpClient httpClient, CancellationToken ct)
    {
        var findings = new List<Finding>();
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var baseUri)) return findings;

        // Fetch main page and look for external script tags
        try
        {
            var html = await httpClient.GetStringAsync(baseUrl, ct);

            foreach (Match m in ExternalScriptPattern.Matches(html))
            {
                var scriptUrl = m.Groups[1].Value;
                if (!Uri.TryCreate(scriptUrl, UriKind.Absolute, out var scriptUri)) continue;

                // If domain is different from base — check if it's reachable
                if (scriptUri.Host.Equals(baseUri.Host, StringComparison.OrdinalIgnoreCase)) continue;

                try
                {
                    var resp = await httpClient.GetAsync(scriptUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                    if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                    {
                        findings.Add(Finding.Create(
                            Severity.High, FindingCategory.Web,
                            $"Dangling JS include: {scriptUrl}",
                            detail: "Script URL returns 404. If the external domain is unclaimed, "
                                  + "an attacker can register it and serve malicious JS.",
                            url: scriptUrl,
                            remediation: "Remove dangling script references. Host all JS locally.",
                            impact: 8.0, confidence: 0.90,
                            vulnType: "dangling_js",
                            attackPath: "Register unclaimed domain → serve malicious JS → XSS all visitors"));
                    }
                }
                catch { }
            }
        }
        catch { }

        return findings;
    }

    // ── Playwright Dynamic Analysis ───────────────────────────────────────────

    private async Task<List<Finding>> RunPlaywrightAnalysisAsync(
        string baseUrl, ScanConfiguration configuration, CancellationToken ct)
    {
        var findings = new List<Finding>();

        // Run playwright via npx or direct CLI — output JSON to stdout
        var tool = _toolRunner.IsAvailable("playwright") ? "playwright" : "npx";
        var args = tool == "playwright"
            ? $"chromium --no-sandbox --ignore-https-errors {baseUrl}"
            : $"playwright chromium {baseUrl}";

        // Use a small inline Node script via npx playwright
        var script = $$"""
            const { chromium } = require('playwright');
            (async () => {
              const browser = await chromium.launch({ args: ['--no-sandbox', '--ignore-certificate-errors'] });
              const ctx = await browser.newContext({ ignoreHTTPSErrors: true, bypassCSP: true });
              const page = await ctx.newPage();
              const ws = [];
              ctx.on('request', req => { if (req.url().startsWith('ws')) ws.push(req.url()); });
              try { await page.goto('{{baseUrl}}', { timeout: 15000, waitUntil: 'networkidle' }); } catch {}
              const storage = await page.evaluate(() => ({
                local: Object.keys(localStorage).filter(k => /token|auth|key|secret|jwt/i.test(k)),
                session: Object.keys(sessionStorage).filter(k => /token|auth|key|secret|jwt/i.test(k)),
              }));
              const cookies = (await ctx.cookies()).filter(c => !c.httpOnly || !c.secure);
              console.log(JSON.stringify({ ws, storage, cookies: cookies.map(c => c.name) }));
              await browser.close();
            })();
            """;

        // Write the script to a temp file and run it
        var scriptPath = $"/tmp/ghostscan_browser_{Guid.NewGuid():N}.js";
        await File.WriteAllTextAsync(scriptPath, script, ct);

        try
        {
            var (exitCode, stdout, _) = await _toolRunner.RunAsync(
                "node", scriptPath, 30, ct);

            if (exitCode == 0 && !string.IsNullOrWhiteSpace(stdout))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(stdout);
                    var root = doc.RootElement;

                    // WebSocket findings
                    if (root.TryGetProperty("ws", out var wsArr))
                    {
                        foreach (var ws in wsArr.EnumerateArray())
                        {
                            findings.Add(Finding.Create(
                                Severity.Info, FindingCategory.Web,
                                $"WebSocket discovered (dynamic): {ws.GetString()}",
                                url: ws.GetString() ?? "",
                                impact: 2.0, confidence: 0.99));
                        }
                    }

                    // Storage with sensitive keys
                    if (root.TryGetProperty("storage", out var storageEl))
                    {
                        var localKeys = storageEl.TryGetProperty("local", out var lk)
                            ? lk.EnumerateArray().Select(k => k.GetString() ?? "").ToList() : [];
                        var sessionKeys = storageEl.TryGetProperty("session", out var sk)
                            ? sk.EnumerateArray().Select(k => k.GetString() ?? "").ToList() : [];

                        if (localKeys.Count > 0 || sessionKeys.Count > 0)
                        {
                            findings.Add(Finding.Create(
                                Severity.High, FindingCategory.Web,
                                "Sensitive keys detected in browser storage (dynamic)",
                                detail: $"localStorage keys: [{string.Join(", ", localKeys)}]. "
                                      + $"sessionStorage keys: [{string.Join(", ", sessionKeys)}].",
                                url: baseUrl,
                                remediation: "Store auth tokens in HttpOnly cookies only.",
                                impact: 6.0, confidence: 0.90, vulnType: "insecure_storage"));
                        }
                    }

                    // Insecure cookies
                    if (root.TryGetProperty("cookies", out var cookieArr))
                    {
                        var insecureCookies = cookieArr.EnumerateArray()
                            .Select(c => c.GetString() ?? "").ToList();
                        if (insecureCookies.Count > 0)
                        {
                            findings.Add(Finding.Create(
                                Severity.Medium, FindingCategory.Cookie,
                                $"Cookies missing HttpOnly/Secure: {string.Join(", ", insecureCookies)}",
                                url: baseUrl,
                                remediation: "Set HttpOnly; Secure; SameSite=Strict on all session cookies.",
                                impact: 3.0, confidence: 0.90, vulnType: "cookie_insecure"));
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
        finally
        {
            try { File.Delete(scriptPath); } catch { }
        }

        return findings;
    }

    private HttpClient CreateHttpClient(ScanConfiguration configuration)
    {
        var client = _httpClientFactory.CreateClient("scanner");
        client.DefaultRequestHeaders.Add("User-Agent",
            configuration.UserAgent ?? "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0");
        client.Timeout = TimeSpan.FromSeconds(configuration.RequestTimeout);
        return client;
    }
}
