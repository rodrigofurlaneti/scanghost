using GhostScan.Domain.Entities;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface IDnsTakeoverEngine 
    { 
        Task<List<Finding>> CheckTakeoverAsync(string host, CancellationToken ct); 
    }
}
