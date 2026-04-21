using MediatR;

namespace GhostScan.Application.Commands.CancelScan;

public sealed record CancelScanCommand(Guid ScanId) : IRequest<bool>;
