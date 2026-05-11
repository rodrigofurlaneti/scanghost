using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class PathProber : IPathProber
{
    private static readonly string[] InterestingPaths = [
        "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/robots.txt", "/wp-config.php", "/wp-login.php",
        "/phpinfo.php", "/.htaccess", "/backup.zip", "/backup.sql", "/db.sql", "/swagger.json", "/appsettings.json"
    ];

    public async Task<(List<string> Endpoints, List<Finding> Findings)> ProbeAsync(string baseUrl, HttpClient httpClient, int maxConcurrency, CancellationToken ct)
    {
        var discovered = new List<string>();
        var findings = new List<Finding>();
        var (rootBody, rootLength) = await FetchRootFingerprint(baseUrl, httpClient, ct);
        var semaphore = new SemaphoreSlim(maxConcurrency);

        var tasks = InterestingPaths.Select(async path => {
            await semaphore.WaitAsync(ct);
            try
            {
                var url = $"{baseUrl.TrimEnd('/')}{path}";
                var response = await httpClient.GetAsync(url, ct);
                if (response.IsSuccessStatusCode)
                {
                    var body = await response.Content.ReadAsStringAsync(ct);
                    if (IsSpaFallback(body, rootBody, rootLength) || !IsContentVerified(path, body)) return;
                    discovered.Add(url);
                    findings.Add(Finding.Create(Severity.High, FindingCategory.Web, $"Sensitive path exposed: {path}", url: url));
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
        if (path.Contains(".env")) return body.Contains("=");
        if (path.Contains(".git")) return body.Contains("[core]") || body.Contains("ref:");
        return true;
    }

    private async Task<(string, int)> FetchRootFingerprint(string url, HttpClient client, CancellationToken ct)
    {
        try { var res = await client.GetAsync(url, ct); var b = await res.Content.ReadAsStringAsync(ct); return (b, b.Length); }
        catch { return ("", 0); }
    }
}