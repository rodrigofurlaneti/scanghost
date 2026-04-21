namespace GhostScan.Application.DTOs;

public sealed class FindingDto
{
    public Guid Id { get; init; }
    public string Severity { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string? Url { get; init; }
    public string? Evidence { get; init; }
    public string? Remediation { get; init; }
    public string? AttackPath { get; init; }
    public double FinalScore { get; init; }
    public double Impact { get; init; }
    public double Confidence { get; init; }
    public double Exploitability { get; init; }
    public double BusinessImpact { get; init; }
    public string VulnType { get; init; } = string.Empty;
    public bool IsConfirmed { get; init; }
    public string? ContextBoost { get; init; }
    public DateTime DiscoveredAt { get; init; }
}
