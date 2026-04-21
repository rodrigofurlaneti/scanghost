using GhostScan.Application.DTOs;
using MediatR;

namespace GhostScan.Application.Queries.GetScanStatus;

public sealed record GetScanStatusQuery(Guid ScanId) : IRequest<ScanStatusDto?>;
