namespace GhostScan.Domain.Services;

public interface IScanProgressNotifier
{
    Task NotifyProgressAsync(Guid scanId, int percentComplete, string phase,
        string activity, int findingsCount, CancellationToken cancellationToken = default);

    Task NotifyCompletedAsync(Guid scanId, int totalFindings,
        CancellationToken cancellationToken = default);

    Task NotifyFailedAsync(Guid scanId, string errorMessage,
        CancellationToken cancellationToken = default);
}
