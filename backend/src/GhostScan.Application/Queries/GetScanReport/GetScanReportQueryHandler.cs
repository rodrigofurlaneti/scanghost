using System.Text.Json;
using GhostScan.Application.DTOs;
using GhostScan.Domain.Aggregates.Scans;
using GhostScan.Domain.Entities;
using GhostScan.Domain.Repositories;
using GhostScan.Domain.ValueObjects;
using MediatR;

namespace GhostScan.Application.Queries.GetScanReport;

public sealed class GetScanReportQueryHandler : IRequestHandler<GetScanReportQuery, VulnerabilityReportDto?>
{
    private readonly IScanRepository _scanRepository;

    public GetScanReportQueryHandler(IScanRepository scanRepository)
    {
        _scanRepository = scanRepository;
    }

    public async Task<VulnerabilityReportDto?> Handle(GetScanReportQuery query, CancellationToken cancellationToken)
    {
        var scan = await _scanRepository.GetByIdAsync(query.ScanId, cancellationToken);
        if (scan is null) return null;

        var minSeverity = query.MinSeverity is not null
            ? Severity.FromString(query.MinSeverity).Value ?? Severity.Info
            : Severity.Info;

        var allFindings = scan.GetDeduplicatedFindings()
            .FilterBySeverity(minSeverity)
            .OrderedByScore()
            .ToList();

        var bySeverity = allFindings
            .GroupBy(f => f.Severity.Name)
            .ToDictionary(g => g.Key, g => g.Count());

        return new VulnerabilityReportDto
        {
            ScanId      = scan.Id,
            Target      = scan.Target.Value,
            Profile     = scan.Configuration.Profile.Name,
            Status      = scan.Status.Name,
            StartedAt   = scan.StartedAt,
            CompletedAt = scan.CompletedAt,
            Duration    = scan.Duration,
            Summary = new SummaryDto
            {
                Total    = allFindings.Count,
                Critical = bySeverity.GetValueOrDefault("CRITICAL"),
                High     = bySeverity.GetValueOrDefault("HIGH"),
                Medium   = bySeverity.GetValueOrDefault("MEDIUM"),
                Low      = bySeverity.GetValueOrDefault("LOW"),
                Info     = bySeverity.GetValueOrDefault("INFO"),
                BySeverity = bySeverity,
            },
            Findings         = allFindings.Select(MapFinding).ToList().AsReadOnly(),
            Correlations     = BuildCorrelations(scan),
            RankedTargets    = BuildRankedTargets(scan),
            Recommendations  = BuildRecommendations(scan),
            ReconResults     = BuildReconResults(scan),
            WebResults       = BuildWebResults(scan),
            IntelligenceResults = BuildIntelligenceResults(scan, allFindings.Count),
        };
    }

    // ── Finding mapping ───────────────────────────────────────────────────────

    private static FindingDto MapFinding(Finding f) => new()
    {
        Id              = f.Id,
        Severity        = f.Severity.Name,
        Category        = f.Category.Name,
        Title           = f.Title,
        Detail          = f.Detail,
        Url             = f.Url,
        Evidence        = f.Evidence,
        Remediation     = f.Remediation,
        AttackPath      = f.AttackPath,
        FinalScore      = f.FinalScore,
        Impact          = f.Score.Impact,
        Confidence      = f.Score.Confidence,
        Exploitability  = f.Score.Exploitability,
        BusinessImpact  = f.Score.BusinessImpact,
        VulnType        = f.VulnType,
        IsConfirmed     = f.IsConfirmed,
        ContextBoost    = f.ContextBoost,
        DiscoveredAt    = f.DiscoveredAt,
    };

    // ── Module data helpers ───────────────────────────────────────────────────

    private static T? GetModuleData<T>(Scan scan, string key) where T : class
    {
        if (!scan.ModuleData.TryGetValue(key, out var raw)) return null;

        // Already the right type
        if (raw is T typed) return typed;

        // Deserialize from JsonElement (can happen with serialization roundtrips)
        if (raw is JsonElement je)
        {
            try { return je.Deserialize<T>(); } catch { return null; }
        }

        return null;
    }

    // ── Recon results ─────────────────────────────────────────────────────────

    private static ReconResultDto? BuildReconResults(Scan scan)
    {
        // Pull from module-level data stored by ReconScanModule
        var reconData = GetModuleData<Dictionary<string, object>>(scan, "Recon");

        var subdomains = GetContextList<string>(scan, "ctx:subdomains")
                      ?? GetNestedList<string>(reconData, "subdomains")
                      ?? [];

        var dnsRaw = GetContextDict<List<string>>(scan, "ctx:dns_records")
                  ?? GetNestedDict<List<string>>(reconData, "dns_records")
                  ?? new Dictionary<string, List<string>>();

        var dnsRecords = dnsRaw.ToDictionary(
            kv => kv.Key,
            kv => (IReadOnlyList<string>)kv.Value.AsReadOnly());

        var openPortsRaw = GetContextDict<object>(scan, "ctx:open_ports")
                        ?? new Dictionary<string, object>();

        var openPorts = openPortsRaw.ToDictionary(
            kv => kv.Key,
            kv => BuildPortInfoList(kv.Value));

        var emails = GetContextList<string>(scan, "ctx:emails")
                  ?? GetNestedList<string>(reconData, "emails")
                  ?? [];

        var zoneTransfer = scan.Findings.Any(f =>
            f.Category.Name.Equals("DNS", StringComparison.OrdinalIgnoreCase) &&
            f.Title.Contains("Zone transfer", StringComparison.OrdinalIgnoreCase));

        if (subdomains.Count == 0 && dnsRecords.Count == 0 &&
            openPorts.Count == 0 && emails.Count == 0 && !zoneTransfer)
            return null;

        return new ReconResultDto
        {
            Subdomains          = subdomains.AsReadOnly(),
            DnsRecords          = dnsRecords,
            OpenPorts           = openPorts,
            ZoneTransferSucceeded = zoneTransfer,
            Emails              = emails.AsReadOnly(),
        };
    }

    // ── Web results ───────────────────────────────────────────────────────────

    private static WebAnalysisResultDto? BuildWebResults(Scan scan)
    {
        var webData = GetModuleData<Dictionary<string, object>>(scan, "WebAnalysis");

        var endpoints = GetContextList<string>(scan, "ctx:endpoints")
                     ?? GetNestedList<string>(webData, "endpoints")
                     ?? [];

        var baseUrls = GetContextList<string>(scan, "ctx:base_urls")
                    ?? GetNestedList<string>(webData, "base_urls")
                    ?? [];

        var waf = BuildWafDto(GetContextDict<object>(scan, "ctx:waf")
               ?? GetNestedDict<object>(webData, "waf"));

        var techRaw = GetContextDict<object>(scan, "ctx:technologies")
                   ?? GetNestedDict<object>(webData, "technologies")
                   ?? new Dictionary<string, object>();

        var technologies = techRaw.ToDictionary(
            kv => kv.Key,
            kv => BuildStringList(kv.Value));

        var jsSecretsRaw = GetContextList<Dictionary<string, string>>(scan, "ctx:js_secrets")
                        ?? GetNestedList<Dictionary<string, string>>(webData, "js_secrets")
                        ?? [];

        var jsSecrets = jsSecretsRaw.Select(s => new JsSecretDto
        {
            Type    = s.GetValueOrDefault("type", ""),
            Pattern = s.GetValueOrDefault("pattern", ""),
            Url     = s.GetValueOrDefault("url"),
            Value   = s.GetValueOrDefault("value", ""),
        }).ToList();

        // Derive missing headers from findings (WebAnalysis sets ctx:missing_headers,
        // but also fall back to scanning findings in the "Headers" category)
        var missingHeaders = GetContextList<string>(scan, "ctx:missing_headers")
            ?? scan.Findings
                   .Where(f => f.Category.Name.Equals("Headers", StringComparison.OrdinalIgnoreCase)
                            && f.Title.StartsWith("Missing:", StringComparison.OrdinalIgnoreCase))
                   .Select(f => f.Title["Missing: ".Length..].Trim())
                   .ToList();

        var dangerousHeaders = scan.Findings
            .Where(f => f.Category.Name.Equals("Headers", StringComparison.OrdinalIgnoreCase)
                     && f.Title.StartsWith("Information disclosure", StringComparison.OrdinalIgnoreCase))
            .Select(f => f.Title)
            .ToList();

        var headerAudit = missingHeaders.Count > 0 || dangerousHeaders.Count > 0
            ? new HeaderAuditDto
            {
                MissingHeaders  = missingHeaders.AsReadOnly(),
                DangerousHeaders = dangerousHeaders.AsReadOnly(),
            }
            : null;

        if (endpoints.Count == 0 && baseUrls.Count == 0 && waf is null &&
            technologies.Count == 0 && jsSecrets.Count == 0)
            return null;

        return new WebAnalysisResultDto
        {
            Endpoints    = endpoints.AsReadOnly(),
            BaseUrls     = baseUrls.AsReadOnly(),
            Waf          = waf,
            Technologies = technologies,
            JsSecrets    = jsSecrets.AsReadOnly(),
            HeaderAudit  = headerAudit,
        };
    }

    // ── Intelligence results ──────────────────────────────────────────────────

    private static IntelligenceResultDto? BuildIntelligenceResults(Scan scan, int totalScored)
    {
        // Module name is "Intelligence" (IntelligenceEngineScanModule.Name = "Intelligence")
        var intData = GetModuleData<Dictionary<string, object>>(scan, "Intelligence");
        if (intData is null) return null;

        var correlations = intData.TryGetValue("correlations", out var c) && c is int ci ? ci : 0;

        return new IntelligenceResultDto
        {
            TotalRaw         = scan.Findings.Count,
            TotalScored      = totalScored,
            TotalCorrelations = correlations,
            AfterDedup       = totalScored,
            AfterFilter      = totalScored,
            AttackSurface    = GetContextList<string>(scan, "ctx:endpoints")?.Count ?? 0,
        };
    }

    // ── Correlations / RankedTargets / Recommendations ────────────────────────

    private static IReadOnlyList<CorrelationDto> BuildCorrelations(Scan scan)
    {
        // Intelligence module findings that are correlation-type go here
        var corrFindings = scan.Findings
            .Where(f => f.VulnType == "correlation" || f.AttackPath is not null)
            .Select(f => new CorrelationDto
            {
                Title       = f.Title,
                Severity    = f.Severity.Name,
                Score       = f.FinalScore,
                Description = f.Detail ?? "",
                AttackPath  = f.AttackPath,
                Remediation = f.Remediation,
                Multiplier  = 1.0,
            }).ToList();

        return corrFindings.AsReadOnly();
    }

    private static IReadOnlyList<RankedTargetDto> BuildRankedTargets(Scan scan)
    {
        var intData = GetModuleData<Dictionary<string, object>>(scan, "Intelligence");
        if (intData is null) return [];

        if (!intData.TryGetValue("ranked_targets", out var raw)) return [];

        if (raw is List<Dictionary<string, object>> list)
        {
            return list.Select(t => new RankedTargetDto
            {
                Url      = t.GetValueOrDefault("url")?.ToString() ?? "",
                Score    = t.TryGetValue("score", out var s) && s is double d ? d : 0,
                Priority = t.GetValueOrDefault("priority")?.ToString() ?? "",
                Reasons  = t.TryGetValue("reasons", out var r) && r is List<string> rs
                    ? rs.AsReadOnly() : new List<string>().AsReadOnly(),
            }).ToList().AsReadOnly();
        }

        return [];
    }

    private static IReadOnlyList<RecommendationDto> BuildRecommendations(Scan scan)
    {
        var intData = GetModuleData<Dictionary<string, object>>(scan, "Intelligence");
        if (intData is null) return [];

        if (!intData.TryGetValue("recommendations", out var raw)) return [];

        if (raw is List<Dictionary<string, object>> list)
        {
            return list.Select((t, i) => new RecommendationDto
            {
                Priority = i + 1,
                Severity = t.GetValueOrDefault("severity")?.ToString() ?? "",
                Action   = t.GetValueOrDefault("action")?.ToString() ?? "",
                Command  = t.GetValueOrDefault("command")?.ToString(),
            }).ToList().AsReadOnly();
        }

        return [];
    }

    // ── Utility helpers ───────────────────────────────────────────────────────

    private static List<T>? GetContextList<T>(Scan scan, string key)
    {
        if (!scan.ModuleData.TryGetValue(key, out var raw)) return null;
        if (raw is List<T> list) return list;
        if (raw is JsonElement je)
            try { return je.Deserialize<List<T>>(); } catch { }
        return null;
    }

    private static Dictionary<string, T>? GetContextDict<T>(Scan scan, string key)
    {
        if (!scan.ModuleData.TryGetValue(key, out var raw)) return null;
        if (raw is Dictionary<string, T> dict) return dict;
        if (raw is JsonElement je)
            try { return je.Deserialize<Dictionary<string, T>>(); } catch { }
        return null;
    }

    private static List<T>? GetNestedList<T>(Dictionary<string, object>? data, string key)
    {
        if (data is null || !data.TryGetValue(key, out var raw)) return null;
        if (raw is List<T> list) return list;
        if (raw is JsonElement je)
            try { return je.Deserialize<List<T>>(); } catch { }
        return null;
    }

    private static Dictionary<string, T>? GetNestedDict<T>(Dictionary<string, object>? data, string key)
    {
        if (data is null || !data.TryGetValue(key, out var raw)) return null;
        if (raw is Dictionary<string, T> dict) return dict;
        if (raw is JsonElement je)
            try { return je.Deserialize<Dictionary<string, T>>(); } catch { }
        return null;
    }

    private static IReadOnlyList<PortInfoDto> BuildPortInfoList(object raw)
    {
        if (raw is List<int> ports)
        {
            return ports.Select(p => new PortInfoDto { Port = p, State = "open", Service = "" })
                .ToList().AsReadOnly();
        }
        if (raw is JsonElement je)
        {
            try
            {
                var list = je.Deserialize<List<int>>();
                if (list is not null)
                    return list.Select(p => new PortInfoDto { Port = p, State = "open", Service = "" })
                        .ToList().AsReadOnly();
            }
            catch { }
        }
        return [];
    }

    private static WafDetectionDto? BuildWafDto(Dictionary<string, object>? raw)
    {
        if (raw is null || raw.Count == 0) return null;
        var detected = raw.TryGetValue("detected", out var d) && d is true;
        var name = raw.GetValueOrDefault("name")?.ToString();
        var conf = raw.TryGetValue("confidence", out var c) && c is double cd ? cd : 0;
        return new WafDetectionDto { Detected = detected, WafName = name, Confidence = conf };
    }

    private static IReadOnlyList<string> BuildStringList(object raw)
    {
        if (raw is List<string> list) return list.AsReadOnly();
        if (raw is JsonElement je)
            try { return je.Deserialize<List<string>>()?.AsReadOnly() ?? (IReadOnlyList<string>)[]; } catch { }
        return [];
    }
}
