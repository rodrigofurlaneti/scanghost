using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class SecretScanner : ISecretScanner
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

    public async Task<(List<Dictionary<string, string>> Secrets, List<Finding> Findings)> ScanAsync(List<string> endpoints, HttpClient httpClient, string target, CancellationToken ct)
    {
        var secrets = new List<Dictionary<string, string>>();
        var findings = new List<Finding>();
        var jsUrls = endpoints.Where(e => e.EndsWith(".js", StringComparison.OrdinalIgnoreCase)).Take(30).ToList();

        foreach (var jsUrl in jsUrls)
        {
            try
            {
                var content = await httpClient.GetStringAsync(jsUrl, ct);
                foreach (var (type, pattern) in SecretPatterns)
                {
                    var match = pattern.Match(content);
                    if (!match.Success) continue;
                    findings.Add(Finding.Create(Severity.Critical, FindingCategory.Web, $"{type} found in JS: {jsUrl}", evidence: match.Value, url: jsUrl, isConfirmed: true));
                }
            }
            catch { }
        }
        return (secrets, findings);
    }

    public async Task<List<string>> ExtractApiEndpointsFromJsAsync(List<string> endpoints, HttpClient client, string baseUrl, CancellationToken ct) { return new List<string>(); }
}