using GhostScan.Application.DTOs;
using MediatR;

namespace GhostScan.Application.Queries.GetScanHistory;

public sealed record GetScanHistoryQuery(int Page = 1, int PageSize = 20) : IRequest<IReadOnlyList<ScanStatusDto>>;
