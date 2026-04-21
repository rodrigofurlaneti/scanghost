using GhostScan.Application.DTOs;
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
            ScanId = scan.Id,
            Target = scan.Target.Value,
            Profile = scan.Configuration.Profile.Name,
            Status = scan.Status.Name,
            StartedAt = scan.StartedAt,
            CompletedAt = scan.CompletedAt,
            Duration = scan.Duration,
            Summary = new SummaryDto
            {
                Total = allFindings.Count,
                Critical = bySeverity.GetValueOrDefault("CRITICAL"),
                High = bySeverity.GetValueOrDefault("HIGH"),
                Medium = bySeverity.GetValueOrDefault("MEDIUM"),
                Low = bySeverity.GetValueOrDefault("LOW"),
                Info = bySeverity.GetValueOrDefault("INFO"),
                BySeverity = bySeverity,
            },
            Findings = allFindings.Select(MapFinding).ToList().AsReadOnly(),
        };
    }

    private static FindingDto MapFinding(Finding f) => new()
    {
        Id = f.Id,
        Severity = f.Severity.Name,
        Category = f.Category.Name,
        Title = f.Title,
        Detail = f.Detail,
        Url = f.Url,
        Evidence = f.Evidence,
        Remediation = f.Remediation,
        AttackPath = f.AttackPath,
        FinalScore = f.FinalScore,
        Impact = f.Score.Impact,
        Confidence = f.Score.Confidence,
        Exploitability = f.Score.Exploitability,
        BusinessImpact = f.Score.BusinessImpact,
        VulnType = f.VulnType,
        IsConfirmed = f.IsConfirmed,
        ContextBoost = f.ContextBoost,
        DiscoveredAt = f.DiscoveredAt,
    };
}
