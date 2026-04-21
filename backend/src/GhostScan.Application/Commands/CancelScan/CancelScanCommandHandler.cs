using GhostScan.Domain.Repositories;
using MediatR;

namespace GhostScan.Application.Commands.CancelScan;

public sealed class CancelScanCommandHandler : IRequestHandler<CancelScanCommand, bool>
{
    private readonly IScanRepository _scanRepository;

    public CancelScanCommandHandler(IScanRepository scanRepository)
    {
        _scanRepository = scanRepository;
    }

    public async Task<bool> Handle(CancelScanCommand command, CancellationToken cancellationToken)
    {
        var scan = await _scanRepository.GetByIdAsync(command.ScanId, cancellationToken);
        if (scan is null) return false;

        var result = scan.Cancel();
        if (result.IsFailure) return false;

        await _scanRepository.SaveAsync(scan, cancellationToken);
        return true;
    }
}
