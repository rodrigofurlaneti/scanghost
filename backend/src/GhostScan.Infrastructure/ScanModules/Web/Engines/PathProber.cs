using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class PathProber : IPathProber
{
    private static readonly string[] InterestingPaths = [
        "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/robots.txt", "/wp-config.php", "/wp-login.php",
        "/phpinfo.php", "/.htaccess", "/backup.zip", "/backup.sql", "/db.sql", "/swagger.json", "/appsettings.json", "/web.config"
    ];

    public async Task<(List<string> Endpoints, List<Finding> Findings)> ProbeAsync(string baseUrl, HttpClient client, int maxConcurrency, CancellationToken ct)
    {
        var discovered = new List<string>();
        var findings = new List<Finding>();
        var (rootBody, rootLength) = await FetchRootFingerprint(baseUrl, client, ct);
        var semaphore = new SemaphoreSlim(maxConcurrency);

        var tasks = InterestingPaths.Select(async path => {
            await semaphore.WaitAsync(ct);
            try
            {
                var url = $"{baseUrl.TrimEnd('/')}{path}";
                var response = await client.GetAsync(url, ct);
                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync(ct);
                    if (IsSpaFallback(body, rootBody, rootLength) || !IsContentVerified(path, body)) return;

                    discovered.Add(url);
                    findings.Add(Finding.Create(Severity.High, FindingCategory.Web, $"Sensitive file exposed: {path}", url: url, isConfirmed: true));
                }
            }
            finally { semaphore.Release(); }
        });

        await Task.WhenAll(tasks);
        return (discovered, findings);
    }

    private bool IsSpaFallback(string body, string rootBody, int rootLength) => body == rootBody || (rootLength > 0 && Math.Abs(body.Length - rootLength) < rootLength * 0.02);

    private bool IsContentVerified(string path, string body)
    {
        var lower = path.ToLower();
        if (lower.Contains(".env")) return body.Contains("=");
        if (lower.Contains(".git")) return body.Contains("[core]") || body.Contains("ref:");
        if (lower.Contains(".sql")) return body.Contains("CREATE TABLE") || body.Contains("INSERT INTO");
        return true;
    }

    private async Task<(string Body, int Length)> FetchRootFingerprint(string url, HttpClient client, CancellationToken ct)
    {
        try { var res = await client.GetAsync(url.TrimEnd('/') + "/", ct); var b = await res.Content.ReadAsStringAsync(ct); return (b, b.Length); }
        catch { return ("", 0); }
    }
}