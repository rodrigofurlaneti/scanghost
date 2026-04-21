using GhostScan.Application.DTOs;
using GhostScan.Domain.Repositories;
using MediatR;

namespace GhostScan.Application.Queries.GetScanHistory;

public sealed class GetScanHistoryQueryHandler
    : IRequestHandler<GetScanHistoryQuery, IReadOnlyList<ScanStatusDto>>
{
    private readonly IScanRepository _scanRepository;

    public GetScanHistoryQueryHandler(IScanRepository scanRepository)
    {
        _scanRepository = scanRepository;
    }

    public async Task<IReadOnlyList<ScanStatusDto>> Handle(
        GetScanHistoryQuery query, CancellationToken cancellationToken)
    {
        var scans = await _scanRepository.GetAllAsync(cancellationToken);

        return scans
            .OrderByDescending(s => s.StartedAt)
            .Skip((query.Page - 1) * query.PageSize)
            .Take(query.PageSize)
            .Select(scan => new ScanStatusDto
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
            })
            .ToList()
            .AsReadOnly();
    }
}
