using GhostScan.Domain.Common;

namespace GhostScan.Domain.Events;

public sealed record FindingDiscoveredEvent(
    Guid ScanId,
    Guid FindingId,
    string Severity,
    string Title) : IDomainEvent
{
    public DateTime OccurredAt { get; } = DateTime.UtcNow;
}
