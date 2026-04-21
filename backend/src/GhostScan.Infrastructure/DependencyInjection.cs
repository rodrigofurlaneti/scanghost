using GhostScan.Domain.Repositories;
using GhostScan.Domain.Services;
using GhostScan.Infrastructure.Orchestration;
using GhostScan.Infrastructure.Repositories;
using GhostScan.Infrastructure.ScanModules;
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
        services.AddScoped<IntelligenceEngineScanModule>();

        // Orchestration
        services.AddScoped<IScanOrchestrator, ScanOrchestrator>();

        return services;
    }
}
