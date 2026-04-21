using GhostScan.Domain.Common;

namespace GhostScan.Domain.ValueObjects;

public sealed class Severity : ValueObject
{
    public static readonly Severity Critical = new("CRITICAL", 100, 5);
    public static readonly Severity High = new("HIGH", 75, 4);
    public static readonly Severity Medium = new("MEDIUM", 50, 3);
    public static readonly Severity Low = new("LOW", 25, 2);
    public static readonly Severity Info = new("INFO", 10, 1);

    private static readonly IReadOnlyDictionary<string, Severity> Registry = new Dictionary<string, Severity>
    {
        ["CRITICAL"] = Critical,
        ["HIGH"] = High,
        ["MEDIUM"] = Medium,
        ["LOW"] = Low,
        ["INFO"] = Info,
    };

    public string Name { get; }
    public int Score { get; }
    public int Rank { get; }

    private Severity(string name, int score, int rank)
    {
        Name = name;
        Score = score;
        Rank = rank;
    }

    public static Result<Severity> FromString(string name)
    {
        var key = name.Trim().ToUpperInvariant();
        return Registry.TryGetValue(key, out var severity)
            ? Result<Severity>.Success(severity)
            : Result<Severity>.Failure($"Unknown severity: '{name}'.");
    }

    public static Severity FromScore(double score) => score switch
    {
        >= 9.0 => Critical,
        >= 7.0 => High,
        >= 5.0 => Medium,
        >= 3.0 => Low,
        _ => Info,
    };

    public bool IsAtLeast(Severity minimum) => Rank >= minimum.Rank;
    public bool IsCritical => this == Critical;
    public bool IsHighOrAbove => Rank >= High.Rank;

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Name;
    }

    public override string ToString() => Name;
}
