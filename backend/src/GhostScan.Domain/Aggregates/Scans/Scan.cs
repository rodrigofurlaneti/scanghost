using GhostScan.Domain.Common;
using GhostScan.Domain.Entities;
using GhostScan.Domain.Events;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Domain.Aggregates.Scans;

public sealed class Scan : AggregateRoot
{
    private readonly FindingCollection _findings = new();

    public ScanTarget Target { get; }
    public ScanConfiguration Configuration { get; }
    public ScanStatus Status { get; private set; }
    public ScanProgress Progress { get; private set; }
    public DateTime StartedAt { get; private set; }
    public DateTime? CompletedAt { get; private set; }
    public string? ErrorMessage { get; private set; }
    public IReadOnlyList<Finding> Findings => _findings.Items;
    public int FindingsCount => _findings.Count;
    public TimeSpan? Duration => CompletedAt.HasValue ? CompletedAt - StartedAt : null;

    private Scan(Guid id, ScanTarget target, ScanConfiguration configuration) : base(id)
    {
        Target = target;
        Configuration = configuration;
        Status = ScanStatus.Pending;
        Progress = ScanProgress.Initial();
    }

    public static Scan Create(ScanTarget target, ScanConfiguration configuration)
    {
        var scan = new Scan(Guid.NewGuid(), target, configuration);
        scan.RaiseDomainEvent(new ScanCreatedEvent(scan.Id, target.Value));
        return scan;
    }

    public Result Start()
    {
        if (!Status.CanTransitionTo(ScanStatus.Running))
            return Result.Failure($"Cannot start scan in status '{Status}'.");

        Status = ScanStatus.Running;
        StartedAt = DateTime.UtcNow;
        Progress = ScanProgress.Create(1, "Starting", "Initializing scan engine...", 0);
        RaiseDomainEvent(new ScanStartedEvent(Id, Target.Value, DateTime.UtcNow));
        return Result.Success();
    }

    public Result UpdateProgress(int percentComplete, string phase, string activity)
    {
        if (!Status.IsActive)
            return Result.Failure($"Cannot update progress for scan in status '{Status}'.");

        Progress = ScanProgress.Create(percentComplete, phase, activity, _findings.Count);
        RaiseDomainEvent(new ScanProgressUpdatedEvent(Id, percentComplete, phase, activity, _findings.Count));
        return Result.Success();
    }

    public Result AddFinding(Finding finding)
    {
        if (!Status.IsActive)
            return Result.Failure($"Cannot add findings to scan in status '{Status}'.");

        _findings.Add(finding);
        RaiseDomainEvent(new FindingDiscoveredEvent(Id, finding.Id, finding.Severity.Name, finding.Title));
        return Result.Success();
    }

    public Result AddFindings(IEnumerable<Finding> findings)
    {
        foreach (var finding in findings)
        {
            var result = AddFinding(finding);
            if (result.IsFailure) return result;
        }
        return Result.Success();
    }

    public Result Complete()
    {
        if (!Status.CanTransitionTo(ScanStatus.Completed))
            return Result.Failure($"Cannot complete scan in status '{Status}'.");

        Status = ScanStatus.Completed;
        CompletedAt = DateTime.UtcNow;
        Progress = ScanProgress.Completed(_findings.Count);
        RaiseDomainEvent(new ScanCompletedEvent(Id, Target.Value, _findings.Count, Duration ?? TimeSpan.Zero));
        return Result.Success();
    }

    public Result Fail(string errorMessage)
    {
        if (!Status.CanTransitionTo(ScanStatus.Failed))
            return Result.Failure($"Cannot fail scan in status '{Status}'.");

        Status = ScanStatus.Failed;
        CompletedAt = DateTime.UtcNow;
        ErrorMessage = errorMessage;
        RaiseDomainEvent(new ScanFailedEvent(Id, Target.Value, errorMessage));
        return Result.Success();
    }

    public Result Cancel()
    {
        if (!Status.CanTransitionTo(ScanStatus.Cancelled))
            return Result.Failure($"Cannot cancel scan in status '{Status}'.");

        Status = ScanStatus.Cancelled;
        CompletedAt = DateTime.UtcNow;
        RaiseDomainEvent(new ScanCancelledEvent(Id, Target.Value));
        return Result.Success();
    }

    public FindingCollection GetFindingsFiltered(Severity minimumSeverity) =>
        _findings.FilterBySeverity(minimumSeverity);

    public FindingCollection GetDeduplicatedFindings() =>
        _findings.Deduplicated();

    public IReadOnlyDictionary<string, int> GetFindingCountsBySeverity() =>
        _findings.CountBySeverity();

    public bool HasCriticalFindings() => _findings.CountCritical() > 0;
    public bool HasHighOrAboveFindings() => _findings.CountHighAndAbove() > 0;

    public bool IsComplete() => Status.IsTerminal;
    public bool IsRunning() => Status.IsActive;
}
