using GhostScan.Domain.Repositories;
using GhostScan.Domain.Services;
using GhostScan.Infrastructure.Orchestration;
using GhostScan.Infrastructure.Repositories;
using GhostScan.Infrastructure.ScanModules;
using GhostScan.Infrastructure.ScanModules.Web.Adapters;
using GhostScan.Infrastructure.ScanModules.Web.Engines;
using GhostScan.Infrastructure.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace GhostScan.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services)
    {
        // Repositories
        services.AddSingleton<IScanRepository, InMemoryScanRepository>();

        // External tool runner
        services.AddSingleton<ExternalToolRunner>();
        services.AddSingleton<SafeExecutor>();

        // HTTP Client for scanning (ignore SSL errors for pentest)
        services.AddHttpClient("scanner", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
        });

        services.AddHttpClient("scanner_strict", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        // Scan Modules
        services.AddScoped<ReconScanModule>();
        services.AddScoped<WebAnalysisScanModule>();
        services.AddScoped<VulnDetectionScanModule>();
        services.AddScoped<BrowserScanModule>();
        services.AddScoped<IntelligenceEngineScanModule>();
        services.AddScoped<ICrawlerEngine, CrawlerEngine>();
        services.AddScoped<ISecretScanner, SecretScanner>();
        services.AddScoped<IPathProber, PathProber>();
        services.AddScoped<ITechDetector, TechDetector>();
        services.AddScoped<ISecurityAuditEngine, SecurityAuditEngine>();
        services.AddScoped<IToolAdapter, NiktoAdapter>();
        services.AddScoped<IToolAdapter, NucleiAdapter>();
        services.AddScoped<IApiFuzzerEngine, ApiFuzzerEngine>();
        services.AddScoped<IDnsTakeoverEngine, DnsTakeoverEngine>();
        services.AddScoped<IScreenshotEngine, ScreenshotEngine>();

        // Orchestration
        services.AddScoped<IScanOrchestrator, ScanOrchestrator>();

        return services;
    }
}
