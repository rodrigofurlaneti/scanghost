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
    public class NucleiAdapter(ExternalToolRunner runner) : IToolAdapter
    {
        public async Task<List<Finding>> ExecuteAsync(string url, CancellationToken ct)
        {
            if (!runner.IsAvailable("nuclei")) return [];
            var findings = new List<Finding>();
            var (_, stdout, _) = await runner.RunAsync("nuclei", $"-u {url} -severity critical,high -json -silent", 600, ct);
            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    var sev = Severity.FromString(root.GetProperty("info").GetProperty("severity").GetString() ?? "medium").Value ?? Severity.Medium;
                    findings.Add(Finding.Create(sev, FindingCategory.Web, $"Nuclei: {root.GetProperty("info").GetProperty("name").GetString()}", url: url));
                }
                catch { }
            }
            return findings;
        }
    }
}
