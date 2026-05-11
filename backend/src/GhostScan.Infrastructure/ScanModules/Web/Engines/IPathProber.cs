using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface IPathProber
    {
        Task<(List<string> Endpoints, List<Finding> Findings)> ProbeAsync(string baseUrl, HttpClient httpClient, int maxConcurrency, CancellationToken ct);
    }
}
