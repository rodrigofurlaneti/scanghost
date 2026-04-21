using GhostScan.Application.DTOs;
using MediatR;

namespace GhostScan.Application.Queries.GetScanReport;

public sealed record GetScanReportQuery(Guid ScanId, string? MinSeverity = null) : IRequest<VulnerabilityReportDto?>;
