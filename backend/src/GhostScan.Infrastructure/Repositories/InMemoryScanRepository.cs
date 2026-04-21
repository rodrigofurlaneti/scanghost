using System.Collections.Concurrent;
using GhostScan.Domain.Aggregates.Scans;
using GhostScan.Domain.Repositories;

namespace GhostScan.Infrastructure.Repositories;

public sealed class InMemoryScanRepository : IScanRepository
{
    private readonly ConcurrentDictionary<Guid, Scan> _store = new();

    public Task<Scan?> GetByIdAsync(Guid scanId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_store.GetValueOrDefault(scanId));

    public Task<IReadOnlyList<Scan>> GetAllAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<Scan>>(_store.Values.ToList().AsReadOnly());

    public Task<IReadOnlyList<Scan>> GetByTargetAsync(string target, CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<Scan>>(
            _store.Values
                .Where(s => s.Target.Value.Equals(target, StringComparison.OrdinalIgnoreCase))
                .ToList()
                .AsReadOnly());

    public Task SaveAsync(Scan scan, CancellationToken cancellationToken = default)
    {
        _store[scan.Id] = scan;
        return Task.CompletedTask;
    }

    public Task<bool> ExistsAsync(Guid scanId, CancellationToken cancellationToken = default) =>
        Task.FromResult(_store.ContainsKey(scanId));
}
