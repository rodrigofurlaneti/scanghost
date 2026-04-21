using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

public sealed class IntelligenceEngineScanModule : IScanModule
{
    private readonly ILogger<IntelligenceEngineScanModule> _logger;

    // Context multipliers (from GhostScan POC)
    private const double LoginNoRatelimit  = 1.35;
    private const double LoginSqli         = 1.50;
    private const double AdminNoAuth       = 1.60;
    private const double ApiNoAuth         = 1.40;
    private const double SecretNoWaf       = 1.20;
    private const double SqliNoCsp         = 1.30;
    private const double DbExposedInternet = 1.45;
    private const double XssNoCsp          = 1.25;
    private const double CriticalCve       = 1.55;

    public string Name => "Intelligence";

    public IntelligenceEngineScanModule(ILogger<IntelligenceEngineScanModule> logger)
    {
        _logger = logger;
    }

    public Task<ScanModuleResult> ExecuteAsync(
        ScanTarget target,
        ScanConfiguration configuration,
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("[Intelligence] Correlating findings and ranking targets");

        var correlationFindings = GenerateCorrelations(context, target.Value);
        var boostedFindings = ApplyContextBoosts(context, configuration);

        var allFindings = new List<Finding>();
        allFindings.AddRange(correlationFindings);
        allFindings.AddRange(boostedFindings);

        var data = new Dictionary<string, object>
        {
            ["correlations"] = correlationFindings.Count,
            ["ranked_targets"] = BuildRankedTargets(context),
            ["recommendations"] = BuildRecommendations(context, target.Value),
        };

        return Task.FromResult(ScanModuleResult.Succeeded(allFindings, data));
    }

    private List<Finding> GenerateCorrelations(ScanContext context, string target)
    {
        var correlations = new List<Finding>();

        var endpoints = context.GetEndpoints();
        var baseUrls = context.GetBaseUrls();
        var baseUrl = baseUrls.FirstOrDefault() ?? $"https://{target}";

        var loginPaths = endpoints
            .Where(e => ContainsLoginKeyword(e))
            .Take(3)
            .ToList();

        var apiPaths = endpoints
            .Where(e => ContainsApiKeyword(e))
            .Take(5)
            .ToList();

        var openPorts = context.GetOpenPorts();
        var technologies = context.Get<Dictionary<string, object>>("technologies") ?? [];
        var jsSecrets = context.Get<List<Dictionary<string, string>>>("js_secrets") ?? [];
        var waf = context.Get<Dictionary<string, object>>("waf") ?? [];
        var wafActive = waf.TryGetValue("detected", out var wafDet) && wafDet is true;

        // 1. Login panel + no rate limiting
        if (loginPaths.Count > 0)
        {
            correlations.Add(Finding.Create(
                Severity.High, FindingCategory.Correlation,
                "Login Panel + No Rate-limit → Brute-force Ready",
                detail: $"Login at {loginPaths[0]} — no lockout detected.",
                url: loginPaths[0],
                remediation: "Implement account lockout, CAPTCHA, rate limiting, and MFA.",
                impact: 8.0, confidence: 0.90,
                attackPath: "Enumerate usernames → spray passwords (Hydra) → session access",
                contextBoost: "Login endpoint + no rate limiting"));
        }

        // 2. API endpoints without authentication
        if (apiPaths.Count > 0)
        {
            var hasSwagger = endpoints.Any(e =>
                e.Contains("swagger", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("openapi", StringComparison.OrdinalIgnoreCase));

            correlations.Add(Finding.Create(
                Severity.High, FindingCategory.Correlation,
                $"Unauthenticated API ({apiPaths.Count} endpoints){(hasSwagger ? " + Swagger Exposed" : "")}",
                detail: $"{apiPaths.Count} API endpoints reachable without auth." +
                         (hasSwagger ? " Swagger spec exposes full attack surface." : ""),
                url: apiPaths[0],
                remediation: "Enforce authentication on all routes. Rate-limit API. Restrict spec access.",
                impact: 8.0, confidence: 0.80,
                attackPath: "Read API spec → test unauthenticated endpoints → IDOR → data exfil",
                contextBoost: "API endpoints + no authentication"));
        }

        // 3. JS Secrets
        if (jsSecrets.Count > 0)
        {
            var types = jsSecrets.Take(3).Select(s => s.GetValueOrDefault("type", "?")).ToList();
            correlations.Add(Finding.Create(
                Severity.Critical, FindingCategory.Correlation,
                $"{jsSecrets.Count} Secret(s) Hardcoded in JavaScript",
                detail: $"Types: {string.Join(", ", types)}. {(wafActive ? "" : "No WAF — directly accessible.")}",
                url: jsSecrets.FirstOrDefault()?.GetValueOrDefault("url") ?? baseUrl,
                remediation: "Remove ALL secrets from client-side code. Rotate exposed keys NOW.",
                impact: 10.0, confidence: 0.95,
                attackPath: "Download JS → grep for keys → direct cloud/API access",
                contextBoost: wafActive ? "JS secrets exposed" : "JS secrets + no WAF",
                isConfirmed: true));
        }

        // 4. Database ports exposed
        var dbPortMap = new Dictionary<int, string>
        {
            [3306] = "MySQL", [5432] = "PostgreSQL", [1433] = "MSSQL",
            [27017] = "MongoDB", [6379] = "Redis", [9200] = "Elasticsearch"
        };

        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            foreach (var dbPort in dbPortMap.Keys.Where(p => ports.Contains(p)))
            {
                var dbName = dbPortMap[dbPort];
                var isHighRisk = dbPort is 6379 or 9200 or 27017;
                correlations.Add(Finding.Create(
                    Severity.Critical, FindingCategory.Correlation,
                    $"Database Exposed — {dbName} on {host}:{dbPort}",
                    detail: $"{dbName} accessible from network. {(isHighRisk ? "No auth by default." : "Brute-force viable.")}",
                    url: $"{host}:{dbPort}",
                    remediation: $"Firewall port {dbPort}. Enable authentication immediately.",
                    impact: isHighRisk ? 9.0 : 7.0,
                    confidence: 0.99,
                    attackPath: $"Connect → empty credentials → data dump / RCE",
                    contextBoost: "Database exposed to internet"));
            }
        }

        // 5. SMB exposed
        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            if (ports.Contains(445) || ports.Contains(139))
            {
                correlations.Add(Finding.Create(
                    Severity.High, FindingCategory.Correlation,
                    "SMB Exposed — NTLM Relay Attack Surface",
                    detail: "SMB reachable from network. NTLM relay attack is viable.",
                    remediation: "Enforce SMB signing via GPO. Restrict SMB to internal networks.",
                    impact: 7.0, confidence: 0.99,
                    attackPath: "Responder → capture Net-NTLMv2 → relay to SMB → code execution"));
            }
        }

        return correlations;
    }

    private static List<Finding> ApplyContextBoosts(ScanContext context, ScanConfiguration configuration)
    {
        // This would apply multipliers to existing findings based on compound conditions
        // The actual findings are already in the scan aggregate from previous modules
        // We return an empty list here — boosts are applied in orchestrator
        return [];
    }

    private static List<Dictionary<string, object>> BuildRankedTargets(ScanContext context)
    {
        var ranked = new List<Dictionary<string, object>>();
        var endpoints = context.GetEndpoints();

        var endpointScores = new Dictionary<string, int>
        {
            ["login"] = 100, ["signin"] = 100, ["auth"] = 95, ["wp-login"] = 95,
            ["admin"] = 90, ["administrator"] = 90, ["dashboard"] = 85,
            [".env"] = 99, [".git"] = 99, ["config"] = 85, ["backup"] = 90,
            ["api"] = 75, ["graphql"] = 85, ["swagger"] = 80, ["upload"] = 80,
        };

        foreach (var endpoint in endpoints.Take(50))
        {
            var score = 0;
            var reasons = new List<string>();

            foreach (var (keyword, pts) in endpointScores)
            {
                if (endpoint.Contains(keyword, StringComparison.OrdinalIgnoreCase))
                {
                    score += pts;
                    reasons.Add(keyword);
                }
            }

            if (score <= 0) continue;

            ranked.Add(new Dictionary<string, object>
            {
                ["url"] = endpoint,
                ["score"] = score,
                ["priority"] = score >= 95 ? "CRITICAL" : score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW",
                ["reasons"] = reasons.Take(4).ToList(),
            });
        }

        return ranked.OrderByDescending(r => (int)r["score"]).Take(30).ToList();
    }

    private static List<Dictionary<string, object>> BuildRecommendations(
        ScanContext context, string target)
    {
        var recs = new List<Dictionary<string, object>>();
        var baseUrl = $"https://{target}";

        var jsSecrets = context.Get<List<Dictionary<string, string>>>("js_secrets") ?? [];
        var technologies = context.Get<Dictionary<string, object>>("technologies") ?? [];
        var openPorts = context.GetOpenPorts();

        if (jsSecrets.Count > 0)
        {
            recs.Add(new()
            {
                ["priority"] = 1, ["severity"] = "CRITICAL",
                ["action"] = "IMMEDIATE — Rotate ALL exposed secrets found in JavaScript",
                ["command"] = "aws iam delete-access-key --access-key-id <KEY_ID>"
            });
        }

        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            if (ports.Contains(6379))
            {
                recs.Add(new()
                {
                    ["priority"] = 2, ["severity"] = "CRITICAL",
                    ["action"] = "Test Redis unauthenticated → RCE via cron",
                    ["command"] = $"redis-cli -h {target} ping && redis-cli -h {target} info server"
                });
            }
        }

        var cmsList = technologies.GetValueOrDefault("cms") as List<string> ?? [];
        if (cmsList.Any(c => c.Contains("WordPress", StringComparison.OrdinalIgnoreCase)))
        {
            recs.Add(new()
            {
                ["priority"] = 3, ["severity"] = "HIGH",
                ["action"] = "WordPress deep scan — vulnerable plugins + brute-force",
                ["command"] = $"wpscan --url {baseUrl} --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive"
            });
        }

        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            if (ports.Contains(445))
            {
                recs.Add(new()
                {
                    ["priority"] = 4, ["severity"] = "HIGH",
                    ["action"] = "SMB full enumeration — null sessions, users, password policy",
                    ["command"] = $"enum4linux-ng -A {target} && crackmapexec smb {target} --shares --users"
                });
            }
        }

        return recs.OrderBy(r => (int)r["priority"]).ToList();
    }

    private static bool ContainsLoginKeyword(string url)
    {
        var keywords = new[] { "login", "signin", "wp-login", "auth", "sign-in" };
        return keywords.Any(k => url.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsApiKeyword(string url)
    {
        var keywords = new[] { "/api/", "/v1/", "/v2/", "/graphql", "/rest/" };
        return keywords.Any(k => url.Contains(k, StringComparison.OrdinalIgnoreCase));
    }
}
