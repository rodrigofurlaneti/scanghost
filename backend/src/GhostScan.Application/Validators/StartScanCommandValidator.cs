using FluentValidation;
using GhostScan.Application.Commands.StartScan;

namespace GhostScan.Application.Validators;

public sealed class StartScanCommandValidator : AbstractValidator<StartScanCommand>
{
    private static readonly string[] ValidProfiles = ["stealth", "standard", "aggressive", "ghost"];
    private static readonly string[] ValidSeverities = ["critical", "high", "medium", "low", "info"];
    private static readonly string[] ValidWafProfiles =
        ["cloudflare", "akamai", "aws-waf", "f5", "imperva", "modsecurity", "wordfence", "sucuri", "generic"];

    public StartScanCommandValidator()
    {
        RuleFor(c => c.Request.Target)
            .NotEmpty()
            .WithMessage("Target is required.")
            .MaximumLength(253)
            .WithMessage("Target must not exceed 253 characters.");

        RuleFor(c => c.Request.Profile)
            .Must(p => ValidProfiles.Contains(p.ToLowerInvariant()))
            .WithMessage($"Profile must be one of: {string.Join(", ", ValidProfiles)}.");

        RuleFor(c => c.Request.MinSeverity)
            .Must(s => ValidSeverities.Contains(s.ToLowerInvariant()))
            .WithMessage($"MinSeverity must be one of: {string.Join(", ", ValidSeverities)}.");

        When(c => c.Request.WafProfile is not null, () =>
        {
            RuleFor(c => c.Request.WafProfile!)
                .Must(p => ValidWafProfiles.Contains(p.ToLowerInvariant()))
                .WithMessage($"WafProfile must be one of: {string.Join(", ", ValidWafProfiles)}.");
        });

        RuleFor(c => c.Request.CrawlDepth)
            .InclusiveBetween(1, 10)
            .WithMessage("CrawlDepth must be between 1 and 10.");

        RuleFor(c => c.Request.RequestTimeout)
            .InclusiveBetween(1, 120)
            .WithMessage("RequestTimeout must be between 1 and 120 seconds.");
    }
}
