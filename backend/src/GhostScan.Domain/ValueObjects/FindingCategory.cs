using GhostScan.Domain.Common;

namespace GhostScan.Domain.ValueObjects;

public sealed class FindingCategory : ValueObject
{
    public static readonly FindingCategory Recon = new("Recon");
    public static readonly FindingCategory Web = new("Web");
    public static readonly FindingCategory Headers = new("Headers");
    public static readonly FindingCategory XSS = new("XSS");
    public static readonly FindingCategory SQLi = new("SQLi");
    public static readonly FindingCategory CVE = new("CVE");
    public static readonly FindingCategory SSL = new("SSL");
    public static readonly FindingCategory Cookie = new("Cookie");
    public static readonly FindingCategory Cors = new("CORS");
    public static readonly FindingCategory DNS = new("DNS");
    public static readonly FindingCategory Port = new("Port");
    public static readonly FindingCategory BruteForce = new("BruteForce");
    public static readonly FindingCategory Correlation = new("Correlation");
    public static readonly FindingCategory Plugin = new("Plugin");
    public static readonly FindingCategory CSP = new("CSP");
    public static readonly FindingCategory Intelligence = new("Intelligence");

    public string Name { get; }

    private FindingCategory(string name) => Name = name;

    public static FindingCategory FromString(string name)
    {
        var known = typeof(FindingCategory)
            .GetFields(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)
            .Where(f => f.FieldType == typeof(FindingCategory))
            .Select(f => (FindingCategory)f.GetValue(null)!)
            .FirstOrDefault(c => c.Name.Equals(name, StringComparison.OrdinalIgnoreCase));

        return known ?? new FindingCategory(name);
    }

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Name.ToUpperInvariant();
    }

    public override string ToString() => Name;
}
