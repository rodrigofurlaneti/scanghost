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
                    var info = JsonDocument.Parse(line).RootElement.GetProperty("info");
                    findings.Add(Finding.Create(Severity.High, FindingCategory.Web, $"Nuclei: {info.GetProperty("name").GetString()}", url: url));
                }
                catch { }
            }
            return findings;
        }
    }
}
