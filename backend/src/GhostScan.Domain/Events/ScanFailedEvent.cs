using GhostScan.Domain.Common;

namespace GhostScan.Domain.Events;

public sealed record ScanFailedEvent(Guid ScanId, string Target, string ErrorMessage) : IDomainEvent
{
    public DateTime OccurredAt { get; } = DateTime.UtcNow;
}
