using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface ICrawlerEngine
    {
        Task<(List<string> Endpoints, List<Dictionary<string, string>> Forms)> CrawlAsync(string baseUrl, HttpClient httpClient, int depth, CancellationToken ct);
    }
}