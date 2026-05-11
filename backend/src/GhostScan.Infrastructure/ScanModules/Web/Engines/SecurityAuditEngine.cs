using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class SecurityAuditEngine : ISecurityAuditEngine
{
    private static readonly Dictionary<string, string[]> SecurityHeaders = new()
    {
        ["Strict-Transport-Security"] = ["HIGH", "HSTS not set.", "Strict-Transport-Security: max-age=31536000"],
        ["Content-Security-Policy"] = ["HIGH", "No CSP implemented.", "Implement a strict CSP."],
        ["X-Frame-Options"] = ["MEDIUM", "Clickjacking possible.", "X-Frame-Options: DENY"],
        ["X-Content-Type-Options"] = ["MEDIUM", "MIME sniffing possible.", "X-Content-Type-Options: nosniff"]
    };

    public async Task<List<Finding>> AuditAsync(string baseUrl, HttpClient client, CancellationToken ct)
    {
        var findings = new List<Finding>();
        try
        {
            var response = await client.GetAsync(baseUrl, ct);
            var h = response.Headers.ToDictionary(x => x.Key, x => string.Join(",", x.Value), StringComparer.OrdinalIgnoreCase);

            foreach (var (name, info) in SecurityHeaders)
            {
                if (!h.ContainsKey(name))
                    findings.Add(Finding.Create(Severity.Medium, FindingCategory.Headers, $"Missing: {name}", detail: info[1], url: baseUrl, remediation: info[2]));
            }

            // Cookie Check
            if (response.Headers.TryGetValues("Set-Cookie", out var cookies))
            {
                foreach (var c in cookies)
                {
                    if (!c.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase))
                        findings.Add(Finding.Create(Severity.Medium, FindingCategory.Cookie, "Cookie missing HttpOnly flag", url: baseUrl));
                }
            }
        }
        catch { }
        return findings;
    }
}