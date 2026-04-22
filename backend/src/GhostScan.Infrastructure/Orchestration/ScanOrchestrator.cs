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
    private readonly BrowserScanModule _browserModule;
    private readonly IntelligenceEngineScanModule _intelligenceModule;
    private readonly ILogger<ScanOrchestrator> _logger;

    public ScanOrchestrator(
        IScanRepository scanRepository,
        IScanProgressNotifier progressNotifier,
        ReconScanModule reconModule,
        WebAnalysisScanModule webModule,
        VulnDetectionScanModule vulnModule,
        BrowserScanModule browserModule,
        IntelligenceEngineScanModule intelligenceModule,
        ILogger<ScanOrchestrator> logger)
    {
        _scanRepository = scanRepository;
        _progressNotifier = progressNotifier;
        _reconModule = reconModule;
        _webModule = webModule;
        _vulnModule = vulnModule;
        _browserModule = browserModule;
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
            var pipeline = BuildModulePipeline(scan);

            _logger.LogInformation("[Orchestrator] Starting scan {ScanId} for {Target} — {Count} modules (parallel={Parallel})",
                scan.Id, scan.Target.Value, pipeline.Count, scan.Configuration.EnableParallel);

            if (scan.Configuration.EnableParallel)
            {
                // ── Parallel mode: Recon first, then Web+Vuln+Browser in parallel, then Intelligence ──
                await RunModulesSequentialAsync(
                    scan, context, pipeline.Where(m => m.Phase == "Reconnaissance").ToList(),
                    0, 30, cancellationToken);

                var parallelGroup = pipeline
                    .Where(m => m.Phase is "Web Analysis" or "Vulnerability Detection" or "Browser/DOM Analysis")
                    .ToList();

                await RunModulesParallelAsync(scan, context, parallelGroup, 30, 85, cancellationToken);

                await RunModulesSequentialAsync(
                    scan, context, pipeline.Where(m => m.Phase == "Intelligence Analysis").ToList(),
                    85, 100, cancellationToken);
            }
            else
            {
                // ── Sequential mode (default) ──
                await RunModulesSequentialAsync(scan, context, pipeline, 0, 100, cancellationToken);
            }

            // Persist ScanContext shared state so the report handler can access cross-module data
            PersistContextToScan(scan, context);

            scan.Complete();
            await _scanRepository.SaveAsync(scan, cancellationToken);

            await _progressNotifier.NotifyCompletedAsync(
                scan.Id, scan.FindingsCount, scan.Duration ?? TimeSpan.Zero, cancellationToken);

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

    // ── Sequential runner ────────────────────────────────────────────────────────

    private async Task RunModulesSequentialAsync(
        Scan scan, ScanContext context,
        List<(IScanModule Module, string Phase, int Weight)> modules,
        int startPercent, int endPercent,
        CancellationToken cancellationToken)
    {
        var total = modules.Count;
        for (var i = 0; i < total; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (module, phase, _) = modules[i];
            var percent = total == 0 ? endPercent
                : startPercent + (int)((i * 1.0 / total) * (endPercent - startPercent));

            scan.UpdateProgress(percent, phase, $"Running {module.Name}...");
            await _scanRepository.SaveAsync(scan, cancellationToken);
            await _progressNotifier.NotifyProgressAsync(
                scan.Id, percent, phase, $"Running {module.Name}...",
                scan.FindingsCount, cancellationToken);

            _logger.LogInformation("[Orchestrator] [{ScanId}] Phase {Phase} — {Module}", scan.Id, phase, module.Name);
            await RunSingleModuleAsync(scan, context, module, phase, cancellationToken);

            await _scanRepository.SaveAsync(scan, cancellationToken);
        }
    }

    // ── Parallel runner ──────────────────────────────────────────────────────────

    private async Task RunModulesParallelAsync(
        Scan scan, ScanContext context,
        List<(IScanModule Module, string Phase, int Weight)> modules,
        int startPercent, int endPercent,
        CancellationToken cancellationToken)
    {
        _logger.LogInformation("[Orchestrator] [{ScanId}] Running {Count} modules in parallel: {Names}",
            scan.Id, modules.Count, string.Join(", ", modules.Select(m => m.Module.Name)));

        // Notify start of parallel phase
        scan.UpdateProgress(startPercent, "Parallel Analysis", "Running modules in parallel...");
        await _scanRepository.SaveAsync(scan, cancellationToken);
        await _progressNotifier.NotifyProgressAsync(
            scan.Id, startPercent, "Parallel Analysis", "Running modules in parallel...",
            scan.FindingsCount, cancellationToken);

        var tasks = modules.Select(m => RunSingleModuleAsync(scan, context, m.Module, m.Phase, cancellationToken));
        await Task.WhenAll(tasks);

        scan.UpdateProgress(endPercent, "Parallel Analysis", "Parallel modules completed");
        await _scanRepository.SaveAsync(scan, cancellationToken);
    }

    // ── Single module runner (shared logic) ──────────────────────────────────────

    private async Task RunSingleModuleAsync(
        Scan scan, ScanContext context,
        IScanModule module, string phase,
        CancellationToken cancellationToken)
    {
        try
        {
            var result = await module.ExecuteAsync(scan.Target, scan.Configuration, context, cancellationToken);

            if (result.Success && result.Findings.Count > 0)
            {
                lock (scan)  // findings list must be thread-safe when parallel
                {
                    scan.AddFindings(result.Findings);
                }
                _logger.LogInformation("[Orchestrator] [{ScanId}] {Module} found {Count} issues",
                    scan.Id, module.Name, result.Findings.Count);
            }
            else if (!result.Success)
            {
                _logger.LogWarning("[Orchestrator] [{ScanId}] {Module} failed: {Error}",
                    scan.Id, module.Name, result.ErrorMessage);
            }

            if (result.Data.Count > 0)
                scan.SetModuleData(module.Name, result.Data);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Orchestrator] [{ScanId}] {Module} threw exception", scan.Id, module.Name);
        }
    }

    /// <summary>
    /// Dumps relevant ScanContext keys into the Scan aggregate so the report handler
    /// can build reconResults, webResults, and intelligenceResults DTOs.
    /// </summary>
    private static void PersistContextToScan(Scan scan, ScanContext context)
    {
        var contextKeys = new[]
        {
            "subdomains", "dns_records", "open_ports", "banners", "emails",
            "endpoints", "base_urls", "technologies", "waf", "js_secrets",
            "forms", "missing_headers", "sqli_findings", "xss_findings", "cve_findings",
        };

        foreach (var key in contextKeys)
        {
            if (!context.Has(key)) continue;
            var value = context.Get<object>(key);
            if (value is not null)
                scan.SetModuleData($"ctx:{key}", value);
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
            pipeline.Add((_vulnModule, "Vulnerability Detection", 15));

        if (config.RunWeb)
            pipeline.Add((_browserModule, "Browser/DOM Analysis", 15));

        // Intelligence always runs last
        pipeline.Add((_intelligenceModule, "Intelligence Analysis", 10));

        return pipeline;
    }
}
