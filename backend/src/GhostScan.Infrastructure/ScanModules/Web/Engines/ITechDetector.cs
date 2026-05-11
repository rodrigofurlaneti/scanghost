using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface ITechDetector
    {
        Task<Dictionary<string, object>> DetectAsync(string baseUrl, HttpClient httpClient, CancellationToken ct);
        Task<(Dictionary<string, object> WafInfo, bool Detected)> DetectWafAsync(string baseUrl, HttpClient httpClient, CancellationToken ct);
    }
}