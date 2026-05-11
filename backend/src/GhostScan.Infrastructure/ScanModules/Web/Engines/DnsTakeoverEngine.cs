using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public class DnsTakeoverEngine : IDnsTakeoverEngine
    {
        private static readonly Dictionary<string, string> TakeoverSignatures = new()
        {
            ["Amazon S3"] = "The specified bucket does not exist",
            ["GitHub Pages"] = "There isn't a GitHub Pages site here",
            ["Heroku"] = "No such app",
            ["Azure"] = "404 Not Found"
        };

        public async Task<List<Finding>> CheckTakeoverAsync(string host, CancellationToken ct)
        {
            var findings = new List<Finding>();
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(host, ct);
                if (addresses.Length == 0) return findings;

                using var client = new HttpClient();
                client.Timeout = TimeSpan.FromSeconds(5);
                var response = await client.GetStringAsync($"http://{host}", ct);

                foreach (var sig in TakeoverSignatures)
                {
                    if (response.Contains(sig.Value))
                    {
                        findings.Add(Finding.Create(Severity.Critical, FindingCategory.Infrastructure,
                            $"Subdomain Takeover detected: {sig.Key}",
                            url: host,
                            detail: $"Host points to a decommissioned {sig.Key} service."));
                    }
                }
            }
            catch { }
            return findings;
        }
    }
}
