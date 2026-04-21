namespace GhostScan.Domain.Common;

public interface IDomainEvent
{
    DateTime OccurredAt { get; }
}
