using GhostScan.Domain.Common;

namespace GhostScan.Domain.Aggregates.Scans;

public sealed class ScanStatus : ValueObject
{
    public static readonly ScanStatus Pending = new("Pending");
    public static readonly ScanStatus Running = new("Running");
    public static readonly ScanStatus Completed = new("Completed");
    public static readonly ScanStatus Failed = new("Failed");
    public static readonly ScanStatus Cancelled = new("Cancelled");

    public string Name { get; }

    private ScanStatus(string name) => Name = name;

    public bool IsTerminal => this == Completed || this == Failed || this == Cancelled;
    public bool IsActive => this == Running;
    public bool CanTransitionTo(ScanStatus next) => (Name, next.Name) switch
    {
        ("Pending",  "Running")   => true,
        ("Pending",  "Cancelled") => true,
        ("Running",  "Completed") => true,
        ("Running",  "Failed")    => true,
        ("Running",  "Cancelled") => true,
        _ => false
    };

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Name;
    }

    public override string ToString() => Name;
}
