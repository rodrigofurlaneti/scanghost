using GhostScan.Domain.Common;

namespace GhostScan.Domain.Aggregates.Scans;

public sealed class ScanProgress : ValueObject
{
    public int PercentComplete { get; }
    public string CurrentPhase { get; }
    public string CurrentActivity { get; }
    public int FindingsCount { get; }

    private ScanProgress(int percentComplete, string currentPhase,
        string currentActivity, int findingsCount)
    {
        PercentComplete = Math.Clamp(percentComplete, 0, 100);
        CurrentPhase = currentPhase;
        CurrentActivity = currentActivity;
        FindingsCount = findingsCount;
    }

    public static ScanProgress Initial() => new(0, "Initializing", "Starting scan...", 0);

    public static ScanProgress Create(
        int percentComplete, string currentPhase,
        string currentActivity, int findingsCount) =>
        new(percentComplete, currentPhase, currentActivity, findingsCount);

    public static ScanProgress Completed(int totalFindings) =>
        new(100, "Completed", "Scan finished.", totalFindings);

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return PercentComplete;
        yield return CurrentPhase;
    }

    public override string ToString() =>
        $"{PercentComplete}% — {CurrentPhase}: {CurrentActivity}";
}
