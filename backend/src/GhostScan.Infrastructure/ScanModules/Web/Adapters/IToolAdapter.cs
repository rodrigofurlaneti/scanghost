using GhostScan.Domain.Entities;
namespace GhostScan.Infrastructure.ScanModules.Web.Adapters
{
    public interface IToolAdapter
    {
        Task<List<Finding>> ExecuteAsync(string url, CancellationToken ct);
    }
}