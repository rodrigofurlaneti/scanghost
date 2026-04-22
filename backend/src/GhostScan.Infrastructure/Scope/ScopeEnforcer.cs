using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.Scope;

/// <summary>
/// Hard scope gate — every tool call, URL fetch and domain check passes through here.
/// Mirrors the Python POC scope.py logic exactly.
/// </summary>
public sealed class ScopeEnforcer
{
    private readonly bool _strict;
    private bool _ssrfProtect;
    private readonly bool _primaryIsInternal;
    private readonly List<(IPNetwork Network, bool IsV6)> _allowedNets = new();
    private readonly HashSet<string> _allowedDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _allowedWildcards = new();
    private readonly List<IPNetwork> _deniedNets = new();
    private readonly HashSet<string> _deniedDomains = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _violations = new();
    private int _checked;
    private readonly ILogger<ScopeEnforcer> _logger;

    // RFC 1918 + reserved ranges — always blocked for SSRF protection
    private static readonly (string Cidr, bool IsV6)[] AlwaysBlocked =
    [
        ("0.0.0.0/8",       false),
        ("10.0.0.0/8",      false),
        ("100.64.0.0/10",   false),
        ("127.0.0.0/8",     false),
        ("169.254.0.0/16",  false),   // link-local / AWS metadata
        ("172.16.0.0/12",   false),
        ("192.168.0.0/16",  false),
        ("198.18.0.0/15",   false),
        ("224.0.0.0/4",     false),   // multicast
        ("240.0.0.0/4",     false),   // reserved
    ];

    private static readonly string[] SsrfKeywords =
        ["localhost", "metadata", "169.254", "internal", "intranet"];

    public ScopeEnforcer(
        string primary,
        ILogger<ScopeEnforcer> logger,
        IEnumerable<string>? extraScope = null,
        bool strict = true,
        bool ssrfProtect = true)
    {
        _logger = logger;
        _strict = strict;
        _ssrfProtect = ssrfProtect;
        _primaryIsInternal = DetectInternal(primary);

        if (_primaryIsInternal)
            _ssrfProtect = false;   // internal target — private ranges are in scope

        AddToScope(primary);
        foreach (var t in extraScope ?? [])
            AddToScope(t);
    }

    // ── PUBLIC ─────────────────────────────────────────────────────────────────

    /// <summary>Main gate. Call before every external interaction.</summary>
    public bool Check(string target, bool raiseOnFail = true)
    {
        _checked++;
        var host = ExtractHost(target);
        if (string.IsNullOrEmpty(host)) return true;

        if (IsDenied(host))
            return Fail(target, "explicitly denied", raiseOnFail);

        if (_ssrfProtect && IsAlwaysBlocked(host))
            return Fail(target,
                "private/reserved address (SSRF protection — use NoSsrfProtect for internal targets)",
                raiseOnFail);

        if (IsAllowed(host)) return true;

        if (_strict)
            return Fail(target, "not in declared scope", raiseOnFail);

        _logger.LogWarning("[Scope] Out-of-scope (non-strict mode): {Target}", target);
        return true;
    }

    public bool CheckUrl(string url, bool raiseOnFail = true)
    {
        var host = ExtractHost(url);
        return Check(host ?? url, raiseOnFail);
    }

    /// <summary>Validate tool command arguments before execution.</summary>
    public string[] WrapCmd(string[] cmd)
    {
        var hostPattern = new Regex(@"^(https?://|[\w\-\.]+\.[a-z]{2,}|[\d\.]+)$",
            RegexOptions.IgnoreCase);
        foreach (var arg in cmd)
        {
            if (hostPattern.IsMatch(arg))
                Check(arg);
        }
        return cmd;
    }

    public void AddScope(string target) => AddToScope(target);

    public void Deny(string target)
    {
        var host = ExtractHost(target);
        if (TryParseNetwork(host, out var net) && net.HasValue)
            _deniedNets.Add(net.Value);
        else
            _deniedDomains.Add(host.ToLowerInvariant());
    }

    public bool IsInScope(string target) => Check(target, raiseOnFail: false);

    public IReadOnlyList<string> FilterTargets(IEnumerable<string> targets) =>
        targets.Where(t => IsInScope(t)).ToList().AsReadOnly();

    public IReadOnlyList<string> Violations => _violations.AsReadOnly();

    public ScopeStats Stats => new()
    {
        Checks = _checked,
        Violations = _violations.Count,
        SsrfProtect = _ssrfProtect,
        Strict = _strict,
        AllowedDomains = _allowedDomains.OrderBy(d => d).ToList().AsReadOnly(),
        Wildcards = _allowedWildcards.AsReadOnly(),
    };

    // ── PRIVATE ────────────────────────────────────────────────────────────────

    private void AddToScope(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return;
        var clean = target.Trim().ToLowerInvariant();

        // CIDR or IP
        if (TryParseNetwork(clean, out var net) && net.HasValue)
        {
            _allowedNets.Add((net.Value, false));
            return;
        }

        // Wildcard *.example.com
        if (clean.StartsWith("*."))
        {
            var base_ = clean[2..];
            _allowedWildcards.Add(base_);
            _allowedDomains.Add(base_);
            return;
        }

        // URL — extract host
        if (clean.Contains("://"))
        {
            try { clean = new Uri(clean).Host; }
            catch { }
        }

        clean = clean.TrimEnd('/').Split(':')[0].Split('/')[0];
        if (string.IsNullOrEmpty(clean)) return;

        _allowedDomains.Add(clean);
        if (clean.StartsWith("www."))
            _allowedDomains.Add(clean[4..]);
        else
            _allowedDomains.Add($"www.{clean}");
    }

    private bool IsAllowed(string host)
    {
        var ip = ResolveIp(host);
        if (ip is not null)
        {
            foreach (var (net, _) in _allowedNets)
                if (net.Contains(ip))
                    return true;
        }

        var hl = host.ToLowerInvariant();
        if (_allowedDomains.Contains(hl)) return true;

        foreach (var wc in _allowedWildcards)
            if (hl.EndsWith($".{wc}") || hl == wc)
                return true;

        foreach (var dom in _allowedDomains)
            if (hl == dom || hl.EndsWith($".{dom}"))
                return true;

        return false;
    }

    private bool IsDenied(string host)
    {
        var ip = ResolveIp(host);
        if (ip is not null)
            foreach (var net in _deniedNets)
                if (net.Contains(ip))
                    return true;

        return _deniedDomains.Contains(host.ToLowerInvariant());
    }

    private bool IsAlwaysBlocked(string host)
    {
        var ip = ResolveIp(host);
        if (ip is null)
            return SsrfKeywords.Any(k => host.Contains(k, StringComparison.OrdinalIgnoreCase));

        foreach (var (cidr, _) in AlwaysBlocked)
        {
            try
            {
                if (TryParseNetwork(cidr, out var net) && net.HasValue && net.Value.Contains(ip))
                    return true;
            }
            catch { }
        }
        return false;
    }

    private bool DetectInternal(string target)
    {
        var host = ExtractHost(target);
        var ip = ResolveIp(host);
        if (ip is not null)
        {
            foreach (var (cidr, _) in AlwaysBlocked)
            {
                if (TryParseNetwork(cidr, out var net) && net.HasValue && net.Value.Contains(ip))
                    return true;
            }
        }
        var tldInternal = new[] { ".local", ".internal", ".corp", ".lan", ".home" };
        return tldInternal.Any(tld => host.EndsWith(tld, StringComparison.OrdinalIgnoreCase));
    }

    private static IPAddress? ResolveIp(string host)
    {
        if (IPAddress.TryParse(host, out var ip)) return ip;
        try
        {
            var addresses = Dns.GetHostAddresses(host);
            return addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                ?? addresses.FirstOrDefault();
        }
        catch { return null; }
    }

    private static string ExtractHost(string target)
    {
        if (string.IsNullOrWhiteSpace(target)) return string.Empty;
        target = target.Trim();
        if (target.Contains("://"))
        {
            try { return new Uri(target).Host; }
            catch { }
        }
        if (target.StartsWith('/')) return string.Empty;
        return target.Split(':')[0].Split('/')[0];
    }

    private static bool TryParseNetwork(string input, out IPNetwork? network)
    {
        network = null;
        try
        {
            if (input.Contains('/'))
            {
                network = IPNetwork.Parse(input);
                return true;
            }
            if (IPAddress.TryParse(input, out var singleIp))
            {
                var prefix = singleIp.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
                network = new IPNetwork(singleIp, prefix);
                return true;
            }
        }
        catch { }
        return false;
    }

    private bool Fail(string target, string reason, bool raiseOnFail)
    {
        var msg = $"SCOPE VIOLATION: {target} — {reason}";
        _violations.Add(msg);
        _logger.LogWarning("[Scope] 🚫 {Message}", msg);
        if (raiseOnFail) throw new ScopeViolationException(msg);
        return false;
    }
}

public sealed class ScopeViolationException(string message) : Exception(message);

public sealed class ScopeStats
{
    public int Checks { get; init; }
    public int Violations { get; init; }
    public bool SsrfProtect { get; init; }
    public bool Strict { get; init; }
    public IReadOnlyList<string> AllowedDomains { get; init; } = [];
    public IReadOnlyList<string> Wildcards { get; init; } = [];
}
