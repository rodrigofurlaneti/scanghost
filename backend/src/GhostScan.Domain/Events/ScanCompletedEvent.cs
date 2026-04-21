using GhostScan.Domain.Common;

namespace GhostScan.Domain.Events;

public sealed record ScanCompletedEvent(
    Guid ScanId,
    string Target,
    int TotalFindings,
    TimeSpan Duration) : IDomainEvent
{
    public DateTime OccurredAt { get; } = DateTime.UtcNow;
}
