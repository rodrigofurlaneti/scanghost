using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface ISecretScanner
    {
        Task<(List<Dictionary<string, string>> Secrets, List<Finding> Findings)> ScanAsync(List<string> endpoints, HttpClient httpClient, string target, CancellationToken ct);
        Task<List<string>> ExtractApiEndpointsFromJsAsync(List<string> endpoints, HttpClient httpClient, string baseUrl, CancellationToken ct);
    }
}
