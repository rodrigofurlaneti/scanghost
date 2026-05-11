using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using GhostScan.Infrastructure.ScanModules.Web.Engines;
using GhostScan.Infrastructure.ScanModules.Web.Adapters;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

public sealed class WebAnalysisScanModule(
    IHttpClientFactory httpClientFactory,
    ICrawlerEngine crawler,
    ISecretScanner secretScanner,
    ITechDetector techDetector,
    IPathProber pathProber,
    ISecurityAuditEngine auditEngine,
    IApiFuzzerEngine apiFuzzer,
    IDnsTakeoverEngine dnsTakeover,
    IScreenshotEngine screenshotter,
    IEnumerable<IToolAdapter> externalTools,
    ILogger<WebAnalysisScanModule> logger) : IScanModule
{
    public string Name => "WebAnalysis";

    public async Task<ScanModuleResult> ExecuteAsync(ScanTarget target, ScanConfiguration config, ScanContext context, CancellationToken ct)
    {
        var findings = new List<Finding>();
        var data = new Dictionary<string, object>();
        var client = httpClientFactory.CreateClient("scanner");

        try
        {
            // 1. Descoberta (Alimenta os outros)
            var (endpoints, forms) = await crawler.CrawlAsync(target.Value, client, config.CrawlDepth, ct);
            context.Set("endpoints", endpoints);
            context.Set("forms", forms);

            // 2. Execução de Motores em Paralelo (Alta Performance)
            var taskSecrets = secretScanner.ScanAsync(endpoints, client, target.Value, ct);
            var taskProbe = pathProber.ProbeAsync(target.Value, client, config.Profile.Threads, ct);
            var taskAudit = auditEngine.AuditAsync(target.Value, client, ct);
            var taskTech = techDetector.DetectAsync(target.Value, client, ct);
            var taskApi = apiFuzzer.FuzzAsync(endpoints, client, ct);
            var taskDns = dnsTakeover.CheckTakeoverAsync(target.Value, ct);
            var taskScreen = screenshotter.CaptureAsync(target.Value, ct);

            // 3. Ferramentas Externas (Nikto, Nuclei)
            var toolTasks = externalTools.Select(t => t.ExecuteAsync(target.Value, ct)).ToList();

            // Aguarda a conclusão de todas as operações
            await Task.WhenAll(taskSecrets, taskProbe, taskAudit, taskTech, taskApi, taskDns, taskScreen);
            await Task.WhenAll(toolTasks);

            // 4. Consolidação dos resultados
            findings.AddRange((await taskSecrets).Findings);
            findings.AddRange((await taskProbe).Findings);
            findings.AddRange(await taskAudit);
            findings.AddRange(await taskApi);
            findings.AddRange(await taskDns);

            foreach (var t in toolTasks) findings.AddRange(await t);

            // Dados adicionais para o relatório
            data["technologies"] = await taskTech;
            data["endpoints"] = endpoints;
            data["forms"] = forms;

            var screenshot = await taskScreen;
            if (!string.IsNullOrEmpty(screenshot)) data["screenshot_base64"] = screenshot;

            return ScanModuleResult.Succeeded(findings, data);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Web Analysis Failed for {Target}", target.Value);
            return ScanModuleResult.Failed($"Critical error in WebAnalysis: {ex.Message}");
        }
    }
}