using GhostScan.Domain.Aggregates.Scans;

namespace GhostScan.Domain.Repositories;

public interface IScanRepository
{
    Task<Scan?> GetByIdAsync(Guid scanId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<Scan>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<Scan>> GetByTargetAsync(string target, CancellationToken cancellationToken = default);
    Task SaveAsync(Scan scan, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(Guid scanId, CancellationToken cancellationToken = default);
}
