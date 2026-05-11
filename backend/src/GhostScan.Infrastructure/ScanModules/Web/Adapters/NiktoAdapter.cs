using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.Tools;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace GhostScan.Infrastructure.ScanModules.Web.Adapters
{
    public class NiktoAdapter(ExternalToolRunner runner) : IToolAdapter
    {
        public async Task<List<Finding>> ExecuteAsync(string url, CancellationToken ct)
        {
            if (!runner.IsAvailable("nikto")) return [];
            var findings = new List<Finding>();
            var (_, stdout, _) = await runner.RunAsync("nikto", $"-h {url} -Format json -nointeractive", 300, ct);
            try
            {
                using var doc = JsonDocument.Parse(stdout);
                if (doc.RootElement.TryGetProperty("vulnerabilities", out var vulns))
                    foreach (var v in vulns.EnumerateArray())
                        findings.Add(Finding.Create(Severity.Medium, FindingCategory.Web, $"Nikto: {v.GetProperty("msg").GetString()}", url: url));
            }
            catch { }
            return findings;
        }
    }
}
