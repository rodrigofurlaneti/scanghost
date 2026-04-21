using GhostScan.Domain.Services;
using Microsoft.AspNetCore.SignalR;

namespace GhostScan.Api.Hubs;

public sealed class ScanProgressHub : Hub
{
    public async Task SubscribeToScan(string scanId)
    {
        await Groups.AddToGroupAsync(Context.ConnectionId, $"scan_{scanId}");
    }

    public async Task UnsubscribeFromScan(string scanId)
    {
        await Groups.RemoveFromGroupAsync(Context.ConnectionId, $"scan_{scanId}");
    }
}

/// <summary>
/// SignalR-based implementation of IScanProgressNotifier.
/// Broadcasts scan progress to connected clients subscribed to a scan group.
/// </summary>
public sealed class SignalRScanProgressNotifier : IScanProgressNotifier
{
    private readonly IHubContext<ScanProgressHub> _hubContext;

    public SignalRScanProgressNotifier(IHubContext<ScanProgressHub> hubContext)
    {
        _hubContext = hubContext;
    }

    public async Task NotifyProgressAsync(
        Guid scanId, int percentComplete, string phase,
        string activity, int findingsCount, CancellationToken cancellationToken = default)
    {
        await _hubContext.Clients.Group($"scan_{scanId}")
            .SendAsync("ScanProgress", new
            {
                ScanId = scanId,
                PercentComplete = percentComplete,
                Phase = phase,
                Activity = activity,
                FindingsCount = findingsCount,
                Timestamp = DateTime.UtcNow,
            }, cancellationToken);
    }

    public async Task NotifyCompletedAsync(
        Guid scanId, int totalFindings, CancellationToken cancellationToken = default)
    {
        await _hubContext.Clients.Group($"scan_{scanId}")
            .SendAsync("ScanCompleted", new
            {
                ScanId = scanId,
                TotalFindings = totalFindings,
                CompletedAt = DateTime.UtcNow,
            }, cancellationToken);
    }

    public async Task NotifyFailedAsync(
        Guid scanId, string errorMessage, CancellationToken cancellationToken = default)
    {
        await _hubContext.Clients.Group($"scan_{scanId}")
            .SendAsync("ScanFailed", new
            {
                ScanId = scanId,
                ErrorMessage = errorMessage,
                FailedAt = DateTime.UtcNow,
            }, cancellationToken);
    }
}
