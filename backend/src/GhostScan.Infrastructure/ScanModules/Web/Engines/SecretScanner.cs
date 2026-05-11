using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class SecretScanner(ILogger<SecretScanner> logger) : ISecretScanner
{
    private static readonly Dictionary<string, Regex> SecretPatterns = new()
    {
        ["AWS Access Key"] = new Regex(@"AKIA[0-9A-Z]{16}", RegexOptions.Compiled),
        ["Generic API Key"] = new Regex(@"(?i)(api[_-]?key|apikey)\s*[:=]\s*['""][a-zA-Z0-9_\-]{20,}['""]", RegexOptions.Compiled),
        ["Bearer Token"] = new Regex(@"(?i)bearer\s+[a-zA-Z0-9\-_=]{20,}", RegexOptions.Compiled),
        ["Private Key"] = new Regex(@"-----BEGIN (RSA |EC )?PRIVATE KEY-----", RegexOptions.Compiled),
        ["Password in Code"] = new Regex(@"(?i)(password|passwd|pwd)\s*[:=]\s*['""][^'""]{6,}['""]", RegexOptions.Compiled),
        ["JWT Token"] = new Regex(@"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", RegexOptions.Compiled),
        ["Google API Key"] = new Regex(@"AIza[0-9A-Za-z\-_]{35}", RegexOptions.Compiled),
        ["GitHub Token"] = new Regex(@"ghp_[0-9a-zA-Z]{36}", RegexOptions.Compiled),
        ["Database DSN"] = new Regex(@"(?i)(mysql|postgres|mongodb|redis)://[^\s'""]+", RegexOptions.Compiled),
    };

    private static readonly Regex[] ApiExtractPatterns =
    [
        new Regex(@"fetch\s*\(\s*['""`]([/][^'""` ]+)['""`]", RegexOptions.Compiled),
        new Regex(@"axios\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['""`]([/][^'""` ]+)['""`]", RegexOptions.Compiled),
        new Regex(@"(?i)(?:url|endpoint|path|api)\s*[:=]\s*['""`]([/][a-zA-Z0-9_/\-\.]{3,})['""`]", RegexOptions.Compiled),
        new Regex(@"XMLHttpRequest[^;]+open\s*\([^,]+,\s*['""`]([/][^'""` ]+)['""`]", RegexOptions.Compiled),
        new Regex(@"\$\.(?:get|post|ajax)\s*\(\s*['""`]([/][^'""` ]+)['""`]", RegexOptions.Compiled),
    ];

    public async Task<(List<Dictionary<string, string>> Secrets, List<Finding> Findings)> ScanAsync(
        List<string> endpoints, HttpClient httpClient, string target, CancellationToken ct)
    {
        var secrets = new List<Dictionary<string, string>>();
        var findings = new List<Finding>();

        var jsUrls = endpoints
            .Where(e => e.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
            .Take(30)
            .ToList();

        foreach (var jsUrl in jsUrls)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);

                foreach (var (secretType, pattern) in SecretPatterns)
                {
                    var match = pattern.Match(content);
                    if (!match.Success) continue;

                    var secretValue = match.Value;

                    secrets.Add(new Dictionary<string, string>
                    {
                        ["type"] = secretType,
                        ["value"] = secretValue.Length > 100 ? secretValue[..100] + "..." : secretValue,
                        ["url"] = jsUrl,
                    });

                    findings.Add(Finding.Create(
                        Severity.Critical, FindingCategory.Web,
                        $"{secretType} found in JavaScript: {jsUrl}",
                        detail: $"Secret type '{secretType}' hardcoded in client-side JS.",
                        url: jsUrl,
                        evidence: secretValue.Length > 50 ? secretValue[..50] + "..." : secretValue,
                        remediation: "Remove ALL secrets from client-side code and rotate keys.",
                        impact: 10.0, confidence: 0.95,
                        vulnType: secretType.Contains("AWS") ? "aws_key" : "env_exposed",
                        isConfirmed: true));
                }
            }
            catch { /* Silently skip failed JS downloads */ }
        }

        return (secrets, findings);
    }

    public async Task<List<string>> ExtractApiEndpointsFromJsAsync(
        List<string> endpoints, HttpClient httpClient, string baseUrl, CancellationToken ct)
    {
        var apiEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var jsUrls = endpoints
            .Where(e => e.EndsWith(".js", StringComparison.OrdinalIgnoreCase))
            .Take(20)
            .ToList();

        foreach (var jsUrl in jsUrls)
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);

                foreach (var pattern in ApiExtractPatterns)
                {
                    foreach (Match m in pattern.Matches(content))
                    {
                        var rawPath = m.Groups[1].Value;
                        if (rawPath.Length > 100) continue;

                        if (Uri.TryCreate(new Uri(baseUrl), rawPath, out var resolved))
                        {
                            apiEndpoints.Add(resolved.ToString());
                        }
                    }
                }
            }
            catch { }
        }

        logger.LogInformation("[SecretScanner] Found {Count} API endpoints in JS files", apiEndpoints.Count);
        return apiEndpoints.ToList();
    }
}