using GhostScan.Domain.Aggregates.Scans;
using GhostScan.Domain.Repositories;
using GhostScan.Domain.Services;
using GhostScan.Domain.ValueObjects;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace GhostScan.Application.Commands.StartScan;

public sealed class StartScanCommandHandler : IRequestHandler<StartScanCommand, Guid>
{
    private readonly IScanRepository _scanRepository;
    private readonly IServiceScopeFactory _scopeFactory;

    public StartScanCommandHandler(
        IScanRepository scanRepository,
        IServiceScopeFactory scopeFactory)
    {
        _scanRepository = scanRepository;
        _scopeFactory = scopeFactory;
    }

    public async Task<Guid> Handle(StartScanCommand command, CancellationToken cancellationToken)
    {
        var request = command.Request;

        var targetResult = ScanTarget.Create(request.Target);
        if (targetResult.IsFailure)
            throw new InvalidOperationException($"Invalid target: {targetResult.Error}");

        var profileResult = ScanProfile.FromString(request.Profile);
        if (profileResult.IsFailure)
            throw new InvalidOperationException($"Invalid profile: {profileResult.Error}");

        var minSeverityResult = Severity.FromString(request.MinSeverity);
        if (minSeverityResult.IsFailure)
            throw new InvalidOperationException($"Invalid severity: {minSeverityResult.Error}");

        var ports = request.Ports?.Split(',') ?? [];

        var configuration = ScanConfiguration.Create(
            profile: profileResult.Value!,
            runRecon: request.RunRecon,
            runWeb: request.RunWeb,
            runVuln: request.RunVuln,
            enableBrowser: request.EnableBrowser,
            enableParallel: request.EnableParallel,
            noSubdomains: request.NoSubdomains,
            noCve: request.NoCve,
            noPlugins: request.NoPlugins,
            proxyUrl: request.ProxyUrl,
            wafProfile: request.WafProfile,
            minSeverity: minSeverityResult.Value,
            ports: ports.Length > 0 ? ports : null,
            crawlDepth: request.CrawlDepth,
            requestTimeout: request.RequestTimeout);

        var scan = Scan.Create(targetResult.Value!, configuration);
        await _scanRepository.SaveAsync(scan, cancellationToken);

        var scanId = scan.Id;

        // Fire and forget using a new DI scope to avoid disposed-scope issues
        _ = Task.Run(async () =>
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var orchestrator = scope.ServiceProvider.GetRequiredService<IScanOrchestrator>();
            var repo = scope.ServiceProvider.GetRequiredService<IScanRepository>();
            var freshScan = await repo.GetByIdAsync(scanId);
            if (freshScan is not null)
                await orchestrator.ExecuteAsync(freshScan, CancellationToken.None);
        });

        return scanId;
    }
}
