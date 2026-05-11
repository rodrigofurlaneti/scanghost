using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public class ApiFuzzerEngine : IApiFuzzerEngine
    {
        public async Task<List<Finding>> FuzzAsync(List<string> endpoints, HttpClient client, CancellationToken ct)
        {
            var findings = new List<Finding>();
            var swaggerUrl = endpoints.FirstOrDefault(e => e.EndsWith("swagger.json") || e.EndsWith("openapi.json"));

            if (string.IsNullOrEmpty(swaggerUrl)) return findings;

            try
            {
                var content = await client.GetStringAsync(swaggerUrl, ct);
                using var doc = JsonDocument.Parse(content);

                if (doc.RootElement.TryGetProperty("paths", out var paths))
                {
                    foreach (var path in paths.EnumerateObject())
                    {
                        // Teste básico de IDOR / Injeção em parâmetros
                        if (path.Name.Contains("{id}") || path.Name.Contains("{uuid}"))
                        {
                            findings.Add(Finding.Create(Severity.Medium, FindingCategory.Web,
                                $"Potential IDOR candidate: {path.Name}",
                                url: swaggerUrl,
                                detail: "API endpoint uses direct object references. Verify authorization logic."));
                        }
                    }
                }
            }
            catch { }
            return findings;
        }
    }
}
