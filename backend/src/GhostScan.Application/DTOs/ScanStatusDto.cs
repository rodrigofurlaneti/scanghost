namespace GhostScan.Application.DTOs;

public sealed class ScanStatusDto
{
    public Guid ScanId { get; init; }
    public string Target { get; init; } = string.Empty;
    public string Status { get; init; } = string.Empty;
    public int PercentComplete { get; init; }
    public string CurrentPhase { get; init; } = string.Empty;
    public string CurrentActivity { get; init; } = string.Empty;
    public int FindingsCount { get; init; }
    public DateTime? StartedAt { get; init; }
    public DateTime? CompletedAt { get; init; }
    public string? ErrorMessage { get; init; }
    public TimeSpan? Duration { get; init; }
    public string ScanProfile { get; init; } = string.Empty;
}
