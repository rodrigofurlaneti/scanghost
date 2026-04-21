using GhostScan.Domain.ValueObjects;

namespace GhostScan.Domain.Entities;

/// <summary>First-class collection for findings — OO Calisthenics rule #4.</summary>
public sealed class FindingCollection
{
    private readonly List<Finding> _items = new();

    public IReadOnlyList<Finding> Items => _items.AsReadOnly();
    public int Count => _items.Count;
    public bool IsEmpty => _items.Count == 0;

    public void Add(Finding finding) => _items.Add(finding);

    public void AddRange(IEnumerable<Finding> findings) => _items.AddRange(findings);

    public FindingCollection FilterBySeverity(Severity minimum) =>
        From(_items.Where(f => f.MeetsSeverityThreshold(minimum)));

    public FindingCollection FilterByCategory(FindingCategory category) =>
        From(_items.Where(f => f.Category == category));

    public IEnumerable<Finding> OrderedByScore() =>
        _items.OrderByDescending(f => f.FinalScore);

    public IReadOnlyDictionary<string, int> CountBySeverity() =>
        _items.GroupBy(f => f.Severity.Name)
              .ToDictionary(g => g.Key, g => g.Count());

    public int CountCritical() => _items.Count(f => f.Severity.IsCritical);
    public int CountHighAndAbove() => _items.Count(f => f.Severity.IsHighOrAbove);

    public FindingCollection Deduplicated()
    {
        var seen = new HashSet<string>();
        var unique = new List<Finding>();
        foreach (var finding in _items)
        {
            var key = $"{finding.Category}{finding.Title}{finding.Url ?? ""}".ToLowerInvariant().Trim();
            if (seen.Add(key))
                unique.Add(finding);
        }
        return From(unique);
    }

    private static FindingCollection From(IEnumerable<Finding> findings)
    {
        var collection = new FindingCollection();
        collection._items.AddRange(findings);
        return collection;
    }
}
