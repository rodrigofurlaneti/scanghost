using GhostScan.Domain.Aggregates.Scans;

namespace GhostScan.Domain.Services;

public interface IScanOrchestrator
{
    Task ExecuteAsync(Scan scan, CancellationToken cancellationToken = default);
}
