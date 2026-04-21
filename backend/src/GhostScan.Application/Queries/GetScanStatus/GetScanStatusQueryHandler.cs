using GhostScan.Application.DTOs;
using GhostScan.Domain.Repositories;
using MediatR;

namespace GhostScan.Application.Queries.GetScanStatus;

public sealed class GetScanStatusQueryHandler : IRequestHandler<GetScanStatusQuery, ScanStatusDto?>
{
    private readonly IScanRepository _scanRepository;

    public GetScanStatusQueryHandler(IScanRepository scanRepository)
    {
        _scanRepository = scanRepository;
    }

    public async Task<ScanStatusDto?> Handle(GetScanStatusQuery query, CancellationToken cancellationToken)
    {
        var scan = await _scanRepository.GetByIdAsync(query.ScanId, cancellationToken);
        if (scan is null) return null;

        return new ScanStatusDto
        {
            ScanId = scan.Id,
            Target = scan.Target.Value,
            Status = scan.Status.Name,
            PercentComplete = scan.Progress.PercentComplete,
            CurrentPhase = scan.Progress.CurrentPhase,
            CurrentActivity = scan.Progress.CurrentActivity,
            FindingsCount = scan.FindingsCount,
            StartedAt = scan.StartedAt == default ? null : scan.StartedAt,
            CompletedAt = scan.CompletedAt,
            ErrorMessage = scan.ErrorMessage,
            Duration = scan.Duration,
            ScanProfile = scan.Configuration.Profile.Name,
        };
    }
}
