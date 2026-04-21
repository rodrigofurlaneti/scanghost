using GhostScan.Domain.Aggregates.Scans;
using GhostScan.Domain.Repositories;
using GhostScan.Domain.Services;
using GhostScan.Infrastructure.ScanModules;
using GhostScan.Infrastructure.ScanModules.Base;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.Orchestration;

public sealed class ScanOrchestrator : IScanOrchestrator
{
    private readonly IScanRepository _scanRepository;
    private readonly IScanProgressNotifier _progressNotifier;
    private readonly ReconScanModule _reconModule;
    private readonly WebAnalysisScanModule _webModule;
    private readonly VulnDetectionScanModule _vulnModule;
    private readonly IntelligenceEngineScanModule _intelligenceModule;
    private readonly ILogger<ScanOrchestrator> _logger;

    public ScanOrchestrator(
        IScanRepository scanRepository,
        IScanProgressNotifier progressNotifier,
        ReconScanModule reconModule,
        WebAnalysisScanModule webModule,
        VulnDetectionScanModule vulnModule,
        IntelligenceEngineScanModule intelligenceModule,
        ILogger<ScanOrchestrator> logger)
    {
        _scanRepository = scanRepository;
        _progressNotifier = progressNotifier;
        _reconModule = reconModule;
        _webModule = webModule;
        _vulnModule = vulnModule;
        _intelligenceModule = intelligenceModule;
        _logger = logger;
    }

    public async Task ExecuteAsync(Scan scan, CancellationToken cancellationToken = default)
    {
        var startResult = scan.Start();
        if (startResult.IsFailure)
        {
            _logger.LogWarning("Cannot start scan {ScanId}: {Error}", scan.Id, startResult.Error);
            return;
        }

        await _scanRepository.SaveAsync(scan, cancellationToken);

        try
        {
            var context = new ScanContext();
            var modules = BuildModulePipeline(scan);
            var totalModules = modules.Count;
            var completedModules = 0;

            _logger.LogInformation("[Orchestrator] Starting scan {ScanId} for {Target} — {Count} modules",
                scan.Id, scan.Target.Value, totalModules);

            foreach (var (module, phase, weight) in modules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var percent = (int)(completedModules * 100.0 / totalModules);
                scan.UpdateProgress(percent, phase, $"Running {module.Name} module...");
                await _scanRepository.SaveAsync(scan, cancellationToken);
                await _progressNotifier.NotifyProgressAsync(
                    scan.Id, percent, phase, $"Running {module.Name}...",
                    scan.FindingsCount, cancellationToken);

                _logger.LogInformation("[Orchestrator] [{ScanId}] Phase {Phase} — {Module}",
                    scan.Id, phase, module.Name);

                try
                {
                    var result = await module.ExecuteAsync(
                        scan.Target, scan.Configuration, context, cancellationToken);

                    if (result.Success && result.Findings.Count > 0)
                    {
                        scan.AddFindings(result.Findings);
                        _logger.LogInformation("[Orchestrator] [{ScanId}] {Module} found {Count} issues",
                            scan.Id, module.Name, result.Findings.Count);
                    }
                    else if (!result.Success)
                    {
                        _logger.LogWarning("[Orchestrator] [{ScanId}] {Module} failed: {Error}",
                            scan.Id, module.Name, result.ErrorMessage);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // One module failure must not stop the pipeline
                    _logger.LogError(ex, "[Orchestrator] [{ScanId}] {Module} threw exception",
                        scan.Id, module.Name);
                }

                completedModules++;
                await _scanRepository.SaveAsync(scan, cancellationToken);
            }

            scan.Complete();
            await _scanRepository.SaveAsync(scan, cancellationToken);

            await _progressNotifier.NotifyCompletedAsync(
                scan.Id, scan.FindingsCount, cancellationToken);

            _logger.LogInformation("[Orchestrator] [{ScanId}] Scan completed. {Count} findings total.",
                scan.Id, scan.FindingsCount);
        }
        catch (OperationCanceledException)
        {
            scan.Cancel();
            await _scanRepository.SaveAsync(scan, CancellationToken.None);
            _logger.LogInformation("[Orchestrator] [{ScanId}] Scan cancelled.", scan.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Orchestrator] [{ScanId}] Fatal error during scan", scan.Id);
            scan.Fail($"Unexpected error: {ex.Message}");
            await _scanRepository.SaveAsync(scan, CancellationToken.None);
            await _progressNotifier.NotifyFailedAsync(scan.Id, ex.Message, CancellationToken.None);
        }
    }

    private List<(IScanModule Module, string Phase, int Weight)> BuildModulePipeline(Scan scan)
    {
        var pipeline = new List<(IScanModule, string, int)>();
        var config = scan.Configuration;

        if (config.RunRecon)
            pipeline.Add((_reconModule, "Reconnaissance", 30));

        if (config.RunWeb)
            pipeline.Add((_webModule, "Web Analysis", 40));

        if (config.RunVuln)
            pipeline.Add((_vulnModule, "Vulnerability Detection", 20));

        // Intelligence always runs last
        pipeline.Add((_intelligenceModule, "Intelligence Analysis", 10));

        return pipeline;
    }
}
