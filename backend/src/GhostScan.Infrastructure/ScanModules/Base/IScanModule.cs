using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Base;

public interface IScanModule
{
    string Name { get; }
    Task<ScanModuleResult> ExecuteAsync(
        ScanTarget target,
        ScanConfiguration configuration,
        ScanContext context,
        CancellationToken cancellationToken = default);
}

public sealed class ScanModuleResult
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public IReadOnlyDictionary<string, object> Data { get; init; } = new Dictionary<string, object>();

    public static ScanModuleResult Succeeded(
        IEnumerable<Finding> findings,
        IReadOnlyDictionary<string, object>? data = null) => new()
    {
        Success = true,
        Findings = findings.ToList().AsReadOnly(),
        Data = data ?? new Dictionary<string, object>(),
    };

    public static ScanModuleResult Failed(string errorMessage) => new()
    {
        Success = false,
        ErrorMessage = errorMessage,
        Findings = [],
    };
}

/// <summary>Shared context passed between scan modules.</summary>
public sealed class ScanContext
{
    private readonly Dictionary<string, object> _data = new();

    public void Set<T>(string key, T value) where T : notnull => _data[key] = value;

    public T? Get<T>(string key) where T : class =>
        _data.TryGetValue(key, out var value) ? value as T : null;

    public bool Has(string key) => _data.ContainsKey(key);

    public IReadOnlyList<string> GetEndpoints() =>
        Get<List<string>>("endpoints") ?? [];

    public IReadOnlyList<string> GetBaseUrls() =>
        Get<List<string>>("base_urls") ?? [];

    public IReadOnlyDictionary<string, object> GetOpenPorts() =>
        Get<Dictionary<string, object>>("open_ports") ?? new Dictionary<string, object>();
}
