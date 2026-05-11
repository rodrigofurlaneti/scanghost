using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class SecurityAuditEngine : ISecurityAuditEngine
{
    private static readonly Dictionary<string, string[]> SecurityHeaders = new()
    {
        ["Strict-Transport-Security"] = ["HIGH", "HSTS not set. Downgrade attacks possible.", "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"],
        ["Content-Security-Policy"] = ["HIGH", "No CSP. XSS attacks lack browser mitigation.", "Implement a strict Content-Security-Policy."],
        ["X-Frame-Options"] = ["MEDIUM", "Clickjacking possible.", "X-Frame-Options: DENY"],
        ["X-Content-Type-Options"] = ["MEDIUM", "MIME sniffing attacks possible.", "X-Content-Type-Options: nosniff"],
        ["Referrer-Policy"] = ["LOW", "Referrer leaks internal URLs.", "Referrer-Policy: strict-origin-when-cross-origin"],
        ["Permissions-Policy"] = ["LOW", "Browser permissions unconstrained.", "Permissions-Policy: camera=(), microphone=(), geolocation=()"],
    };

    private static readonly string[] DangerousHeaders = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"];

    public async Task<List<Finding>> AuditAsync(string baseUrl, HttpClient client, CancellationToken ct)
    {
        var findings = new List<Finding>();
        try
        {
            var response = await client.GetAsync(baseUrl, ct);
            var headers = response.Headers.ToDictionary(h => h.Key, h => string.Join(", ", h.Value), StringComparer.OrdinalIgnoreCase);

            foreach (var (headerName, info) in SecurityHeaders)
            {
                if (!headers.ContainsKey(headerName))
                {
                    var severity = Severity.FromString(info[0]).Value ?? Severity.Medium;
                    findings.Add(Finding.Create(severity, FindingCategory.Headers, $"Missing: {headerName}", detail: info[1], url: baseUrl, remediation: info[2], impact: severity == Severity.High ? 5.0 : 3.0, confidence: 0.99));
                }
            }

            foreach (var dangerous in DangerousHeaders)
            {
                if (headers.TryGetValue(dangerous, out var value))
                {
                    findings.Add(Finding.Create(Severity.Low, FindingCategory.Headers, $"Information disclosure via {dangerous}: {value}", detail: $"Server version exposed in {dangerous} header.", url: baseUrl, remediation: $"Remove or sanitize the {dangerous} header.", impact: 2.0, confidence: 0.99));
                }
            }
        }
        catch { }
        return findings;
    }
}