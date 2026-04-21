using GhostScan.Domain.Common;

namespace GhostScan.Domain.Events;

public sealed record ScanStartedEvent(Guid ScanId, string Target, DateTime StartedAt) : IDomainEvent
{
    public DateTime OccurredAt { get; } = DateTime.UtcNow;
}
