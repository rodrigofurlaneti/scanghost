using GhostScan.Domain.Common;

namespace GhostScan.Domain.Events;

public sealed record ScanProgressUpdatedEvent(
    Guid ScanId,
    int PercentComplete,
    string Phase,
    string Activity,
    int FindingsCount) : IDomainEvent
{
    public DateTime OccurredAt { get; } = DateTime.UtcNow;
}
