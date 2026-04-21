using GhostScan.Domain.Common;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Domain.Entities;

public sealed class Finding : Entity
{
    public Severity Severity { get; private set; }
    public FindingCategory Category { get; }
    public string Title { get; }
    public string Detail { get; }
    public string? Url { get; }
    public string? Evidence { get; }
    public string? Remediation { get; }
    public VulnerabilityScore Score { get; private set; }
    public string VulnType { get; }
    public bool IsConfirmed { get; private set; }
    public DateTime DiscoveredAt { get; }
    public string? AttackPath { get; }
    public string? ContextBoost { get; private set; }
    public double Confidence => Score.Confidence;
    public double FinalScore => Score.FinalScore;

    private Finding(
        Guid id,
        Severity severity,
        FindingCategory category,
        string title,
        string detail,
        string? url,
        string? evidence,
        string? remediation,
        VulnerabilityScore score,
        string vulnType,
        bool isConfirmed,
        string? attackPath,
        string? contextBoost) : base(id)
    {
        Severity = severity;
        Category = category;
        Title = title;
        Detail = detail;
        Url = url;
        Evidence = evidence;
        Remediation = remediation;
        Score = score;
        VulnType = vulnType;
        IsConfirmed = isConfirmed;
        DiscoveredAt = DateTime.UtcNow;
        AttackPath = attackPath;
        ContextBoost = contextBoost;
    }

    public static Finding Create(
        Severity severity,
        FindingCategory category,
        string title,
        string detail = "",
        string? url = null,
        string? evidence = null,
        string? remediation = null,
        double impact = 5.0,
        double confidence = 0.70,
        double exploitability = 1.0,
        double businessImpact = 1.0,
        string vulnType = "default",
        bool isConfirmed = false,
        string? attackPath = null,
        string? contextBoost = null)
    {
        var score = VulnerabilityScore.Calculate(
            impact, confidence, exploitability, businessImpact, contextBoost);

        return new Finding(
            Guid.NewGuid(), severity, category, title, detail,
            url, evidence, remediation, score, vulnType,
            isConfirmed, attackPath, contextBoost);
    }

    public void EscalateSeverity(Severity newSeverity, string reason)
    {
        if (newSeverity.Rank > Severity.Rank)
        {
            Severity = newSeverity;
            ContextBoost = string.IsNullOrEmpty(ContextBoost)
                ? reason
                : $"{ContextBoost} | {reason}";
        }
    }

    public void ConfirmFinding()
    {
        IsConfirmed = true;
    }

    public void ApplyContextBoost(double multiplier, string reason)
    {
        Score = Score.WithContextMultiplier(multiplier, reason);
        ContextBoost = string.IsNullOrEmpty(ContextBoost)
            ? reason
            : $"{ContextBoost} | {reason}";

        var newSeverity = Score.DerivedSeverity;
        if (newSeverity.Rank > Severity.Rank)
            Severity = newSeverity;
    }

    public bool MeetsSeverityThreshold(Severity minimum) =>
        Severity.IsAtLeast(minimum);

    public override string ToString() =>
        $"[{Severity}] {Category}: {Title}";
}
