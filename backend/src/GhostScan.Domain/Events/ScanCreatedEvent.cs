using GhostScan.Domain.Common;

namespace GhostScan.Domain.Events;

public sealed record ScanCreatedEvent(Guid ScanId, string Target) : IDomainEvent
{
    public DateTime OccurredAt { get; } = DateTime.UtcNow;
}
