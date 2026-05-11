using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using GhostScan.Infrastructure.ScanModules.Web.Engines;
using GhostScan.Infrastructure.ScanModules.Web.Adapters;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules
{
    public sealed class WebAnalysisScanModule(
    IHttpClientFactory httpClientFactory,
    ICrawlerEngine crawler,
    ISecretScanner secretScanner,
    ITechDetector techDetector,
    IPathProber pathProber,
    ISecurityAuditEngine auditEngine,
    IEnumerable<IToolAdapter> externalTools,
    ILogger<WebAnalysisScanModule> logger) : IScanModule
    {
        public string Name => "WebAnalysis";

        public async Task<ScanModuleResult> ExecuteAsync(ScanTarget target, ScanConfiguration config, ScanContext context, CancellationToken ct)
        {
            var findings = new List<Finding>();
            var client = httpClientFactory.CreateClient("scanner");

            try
            {
                // 1. Descoberta
                var (endpoints, _) = await crawler.CrawlAsync(target.Value, client, config.CrawlDepth, ct);
                context.Set("endpoints", endpoints);

                // 2. Motores Paralelos
                var taskSecrets = secretScanner.ScanAsync(endpoints, client, target.Value, ct);
                var taskProbe = pathProber.ProbeAsync(target.Value, client, config.Profile.Threads, ct);
                var taskAudit = auditEngine.AuditAsync(target.Value, client, ct);
                var taskTech = techDetector.DetectAsync(target.Value, client, ct);

                // 3. Ferramentas Externas
                var toolTasks = externalTools.Select(t => t.ExecuteAsync(target.Value, ct)).ToList();

                await Task.WhenAll(taskSecrets, taskProbe, taskAudit, taskTech);
                await Task.WhenAll(toolTasks);

                // 4. Consolidação
                findings.AddRange((await taskSecrets).Findings);
                findings.AddRange((await taskProbe).Findings);
                findings.AddRange(await taskAudit);
                foreach (var t in toolTasks) findings.AddRange(await t);

                var data = new Dictionary<string, object>
                {
                    ["technologies"] = await taskTech,
                    ["endpoints"] = endpoints
                };

                return ScanModuleResult.Succeeded(findings, data);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Web Analysis Failed for {Target}", target.Value);
                return ScanModuleResult.Failed(ex.Message);
            }
        }
    }
}

