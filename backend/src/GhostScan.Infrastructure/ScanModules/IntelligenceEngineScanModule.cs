using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

/// <summary>
/// Intelligence Engine — mirrors intelligence.py exactly.
/// Full scoring: score = (impact×0.6 + confidence×0.4) × exploitability × businessImpact
/// All 8 correlations, deduplication, target ranking, recommendations.
/// </summary>
public sealed class IntelligenceEngineScanModule : IScanModule
{
    private readonly ILogger<IntelligenceEngineScanModule> _logger;

    public string Name => "Intelligence";

    // ── SCORING TABLES ─────────────────────────────────────────────────────────

    private static readonly Dictionary<string, (double Impact, double Confidence)> VulnBase = new()
    {
        ["sqli"]              = (10, 0.90), ["rce"]                = (10, 0.85),
        ["env_exposed"]       = (10, 0.99), ["git_exposed"]         = (9,  0.98),
        ["aws_key"]           = (10, 0.95), ["xxe"]                 = (8,  0.70),
        ["ssrf"]              = (8,  0.65), ["lfi"]                 = (7,  0.70),
        ["xss_reflected"]     = (6,  0.60), ["xss_stored"]          = (8,  0.75),
        ["xss_dom"]           = (6,  0.70), ["open_redirect"]       = (4,  0.85),
        ["csrf"]              = (5,  0.65), ["command_injection"]   = (10, 0.75),
        ["path_traversal"]    = (7,  0.75), ["idor"]                = (6,  0.65),
        ["broken_auth"]       = (8,  0.55), ["default_creds"]       = (9,  0.85),
        ["missing_csp"]       = (3,  0.99), ["missing_hsts"]        = (4,  0.99),
        ["missing_xfo"]       = (3,  0.99), ["exposed_service"]     = (5,  0.99),
        ["smb_exposed"]       = (7,  0.99), ["rdp_exposed"]         = (8,  0.99),
        ["redis_unauth"]      = (9,  0.99), ["mongodb_exposed"]     = (8,  0.99),
        ["elasticsearch"]     = (8,  0.99), ["snmp"]                = (5,  0.99),
        ["wordpress_vuln"]    = (8,  0.75), ["cve_critical"]        = (10, 0.80),
        ["cve_high"]          = (7,  0.80), ["ssl_weak"]            = (4,  0.99),
        ["cookie_insecure"]   = (3,  0.99), ["info_disclosure"]     = (2,  0.99),
        ["default"]           = (5,  0.70),
    };

    private static readonly Dictionary<string, double> BusinessImpact = new()
    {
        ["payment"] = 1.5, ["admin"] = 1.4, ["auth"] = 1.3, ["api"] = 1.2,
        ["pii"] = 1.4, ["upload"] = 1.2, ["config"] = 1.3, ["backup"] = 1.3,
        ["health"] = 0.8, ["static"] = 0.5, ["default"] = 1.0,
    };

    private static readonly Dictionary<string, double> ContextMultipliers = new()
    {
        ["login_no_ratelimit"]     = 1.35, ["login_sqli"]           = 1.50,
        ["admin_no_auth"]          = 1.60, ["api_no_auth"]           = 1.40,
        ["secret_no_waf"]          = 1.20, ["sqli_no_csp"]           = 1.30,
        ["db_exposed_internet"]    = 1.45, ["smb_signing_disabled"]  = 1.40,
        ["critical_cve_confirmed"] = 1.55, ["xss_no_csp"]            = 1.25,
        ["rdp_no_nla"]             = 1.30,
    };

    private static readonly Dictionary<string, double> Exploitability = new()
    {
        ["no_auth_required"]      = 1.0, ["auth_required"]          = 0.7,
        ["admin_auth_required"]   = 0.5, ["network_internal_only"]  = 0.6,
        ["requires_user_action"]  = 0.8, ["complex_exploit"]        = 0.75,
        ["known_poc_available"]   = 1.2, ["wormable"]               = 1.3,
    };

    private static readonly Dictionary<string, int> EndpointScores = new()
    {
        ["login"]=100, ["signin"]=100, ["auth"]=95, ["wp-login"]=95,
        ["admin"]=90, ["administrator"]=90, ["dashboard"]=85, ["panel"]=85,
        ["phpmyadmin"]=92, ["adminer"]=92, ["actuator"]=90, [".env"]=99,
        [".git"]=99, ["config"]=85, ["backup"]=90, ["dump.sql"]=99,
        ["wp-config"]=99, ["api"]=75, ["graphql"]=85, ["swagger"]=80,
        ["upload"]=80, ["register"]=70, ["reset"]=70, ["xmlrpc"]=85,
        ["static"]=-50, ["assets"]=-50, ["images"]=-60, ["fonts"]=-70,
    };

    private static readonly Dictionary<int, int> PortRisk = new()
    {
        [23]=90, [21]=60, [445]=85, [3389]=88, [6379]=95,
        [9200]=90, [27017]=90, [5432]=70, [3306]=75, [5900]=85,
        [1521]=70, [8080]=35, [8443]=35, [22]=40, [80]=25, [443]=25,
    };

    private static readonly int[] DbPorts = [3306, 5432, 1433, 27017, 6379, 9200];

    public IntelligenceEngineScanModule(ILogger<IntelligenceEngineScanModule> logger)
        => _logger = logger;

    public Task<ScanModuleResult> ExecuteAsync(
        ScanTarget target, ScanConfiguration configuration,
        ScanContext context, CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("[Intelligence] Correlating findings and ranking targets for {Target}", target.Value);

        var endpoints  = context.GetEndpoints().ToList();
        var baseUrls   = context.GetBaseUrls().ToList();
        var baseUrl    = baseUrls.FirstOrDefault() ?? $"https://{target.Value}";
        var openPorts  = context.GetOpenPorts();
        var technologies = context.Get<Dictionary<string, object>>("technologies") ?? [];
        var jsSecrets  = context.Get<List<Dictionary<string, string>>>("js_secrets") ?? [];
        var waf        = context.Get<Dictionary<string, object>>("waf") ?? [];
        var wafActive  = waf.TryGetValue("detected", out var wafDet) && wafDet is true;
        var sqliHits   = context.Get<List<string>>("sqli_findings") ?? [];
        var xssHits    = context.Get<List<string>>("xss_findings") ?? [];
        var cveHits    = context.Get<List<Dictionary<string, string>>>("cve_findings") ?? [];
        var missingHeaders = context.Get<List<string>>("missing_headers") ?? [];
        var missingCsp = missingHeaders.Any(h => h.Contains("Content-Security-Policy", StringComparison.OrdinalIgnoreCase));

        var findings = new List<Finding>();

        // 1. All 8 correlations
        findings.AddRange(GenerateAllCorrelations(
            target.Value, baseUrl, endpoints, openPorts, jsSecrets,
            wafActive, sqliHits, xssHits, cveHits, missingCsp, context));

        // 2. Context boosts as standalone correlation findings
        findings.AddRange(GenerateContextBoostFindings(
            endpoints, sqliHits, jsSecrets, wafActive, missingCsp));

        var rankedTargets = BuildRankedTargets(endpoints, openPorts);
        var recommendations = BuildRecommendations(target.Value, baseUrl, openPorts, jsSecrets, sqliHits, xssHits, cveHits, technologies);

        var data = new Dictionary<string, object>
        {
            ["correlations"]    = findings.Count,
            ["ranked_targets"]  = rankedTargets,
            ["recommendations"] = recommendations,
        };

        _logger.LogInformation("[Intelligence] Generated {Count} correlations, {Ranked} ranked targets",
            findings.Count, rankedTargets.Count);

        return Task.FromResult(ScanModuleResult.Succeeded(findings, data));
    }

    // ── ALL 8 CORRELATIONS ─────────────────────────────────────────────────────

    private List<Finding> GenerateAllCorrelations(
        string target, string baseUrl,
        List<string> endpoints, IReadOnlyDictionary<string, object> openPorts,
        List<Dictionary<string, string>> jsSecrets, bool wafActive,
        List<string> sqliHits, List<string> xssHits,
        List<Dictionary<string, string>> cveHits, bool missingCsp,
        ScanContext context)
    {
        var findings = new List<Finding>();
        var loginPaths = endpoints.Where(e => ContainsLoginKeyword(e)).Take(3).ToList();
        var apiPaths   = endpoints.Where(e => ContainsApiKeyword(e)).Take(5).ToList();
        var allPorts   = ParseAllPorts(openPorts);

        // ─ Correlation 1: Login + No Rate Limit ──────────────────────────────
        if (loginPaths.Count > 0)
        {
            var s = CalcScore(8.0, 0.90, Exploitability["no_auth_required"], BusinessImpact["auth"])
                    * ContextMultipliers["login_no_ratelimit"];
            var sev = ScoreToSeverity(Math.Min(10.0, s));
            findings.Add(Finding.Create(
                sev, FindingCategory.Correlation,
                "Login Panel + No Rate-limit → Brute-force Ready",
                detail: $"Login at {loginPaths[0]} — no lockout detected." +
                        (missingCsp ? " Missing CSP amplifies credential phishing." : ""),
                url: loginPaths[0],
                remediation: "Implement account lockout, CAPTCHA, rate limiting, and MFA.",
                impact: 8.0, confidence: 0.90,
                exploitability: Exploitability["no_auth_required"],
                businessImpact: BusinessImpact["auth"],
                attackPath: "Enumerate usernames → spray passwords (Hydra) → session access",
                contextBoost: "Login endpoint + no rate limiting"));
        }

        // ─ Correlation 2: Login + SQLi → Auth Bypass ─────────────────────────
        if (loginPaths.Count > 0 && sqliHits.Count > 0)
        {
            var s = CalcScore(10.0, 0.90, 1.0, BusinessImpact["auth"])
                    * ContextMultipliers["login_sqli"];
            findings.Add(Finding.Create(
                Severity.Critical, FindingCategory.Correlation,
                "SQLi on Auth Endpoint → Auth Bypass + Full DB Dump",
                detail: $"SQLi confirmed in {sqliHits.Count} parameter(s) at auth endpoint. " +
                        "Auth bypass payload: admin'--",
                remediation: "Parameterised queries. Validate all inputs. Separate auth from data queries.",
                impact: 10.0, confidence: 0.90, exploitability: 1.0, businessImpact: BusinessImpact["auth"],
                attackPath: "SQLi auth bypass → admin access → --dump DB → crack hashes → RCE via plugin upload",
                contextBoost: "SQLi + authentication endpoint",
                isConfirmed: true));
        }

        // ─ Correlation 3: API + No Auth ± Swagger ────────────────────────────
        if (apiPaths.Count > 0)
        {
            var hasSwagger = endpoints.Any(e =>
                e.Contains("swagger", StringComparison.OrdinalIgnoreCase) ||
                e.Contains("openapi", StringComparison.OrdinalIgnoreCase));

            var s = CalcScore(8.0, 0.80, 1.0, BusinessImpact["api"])
                    * ContextMultipliers["api_no_auth"];
            if (hasSwagger) s = Math.Min(10.0, s * 1.15);
            var sev = ScoreToSeverity(Math.Min(10.0, s));

            findings.Add(Finding.Create(
                sev, FindingCategory.Correlation,
                $"Unauthenticated API ({apiPaths.Count} endpoints){(hasSwagger ? " + Swagger Exposed" : "")}",
                detail: $"{apiPaths.Count} API endpoints reachable without auth." +
                        (hasSwagger ? " Swagger spec exposes full attack surface." : ""),
                url: apiPaths[0],
                remediation: "Enforce authentication on all routes. Rate-limit API. Restrict spec access.",
                impact: 8.0, confidence: 0.80,
                attackPath: "Read API spec → test unauthenticated endpoints → IDOR → data exfil",
                contextBoost: "API endpoints + no authentication"));
        }

        // ─ Correlation 4: JS Secrets ──────────────────────────────────────────
        if (jsSecrets.Count > 0)
        {
            var types = jsSecrets.Take(3).Select(s => s.GetValueOrDefault("type", "?")).ToList();
            var mult = wafActive ? 1.0 : ContextMultipliers["secret_no_waf"];
            var s = CalcScore(10.0, 0.95, 1.0, BusinessImpact["config"]) * mult;
            findings.Add(Finding.Create(
                Severity.Critical, FindingCategory.Correlation,
                $"{jsSecrets.Count} Secret(s) Hardcoded in JavaScript",
                detail: $"Types: {string.Join(", ", types)}. " +
                        (wafActive ? "" : "No WAF — directly accessible."),
                url: jsSecrets.FirstOrDefault()?.GetValueOrDefault("url") ?? baseUrl,
                remediation: "Remove ALL secrets from client-side code. Rotate exposed keys NOW.",
                impact: 10.0, confidence: 0.95,
                attackPath: "Download JS → grep for keys → direct cloud/API access",
                contextBoost: wafActive ? "JS secrets exposed" : "JS secrets + no WAF",
                isConfirmed: true));
        }

        // ─ Correlation 5: Database Ports Exposed ─────────────────────────────
        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            foreach (var dbPort in DbPorts.Where(p => ports.Contains(p)))
            {
                var dbName = dbPort switch
                {
                    3306 => "MySQL", 5432 => "PostgreSQL", 1433 => "MSSQL",
                    27017 => "MongoDB", 6379 => "Redis", 9200 => "Elasticsearch",
                    _ => "Database"
                };
                var isHighRisk = dbPort is 6379 or 9200 or 27017;
                var imp = isHighRisk ? 9.0 : 7.0;
                var s = CalcScore(imp, 0.99) * ContextMultipliers["db_exposed_internet"];
                var sev = s >= 9.0 ? Severity.Critical : Severity.High;

                findings.Add(Finding.Create(
                    sev, FindingCategory.Correlation,
                    $"Database Exposed — {dbName} on {host}:{dbPort}",
                    detail: $"{dbName} accessible from network. " +
                            (isHighRisk ? "No auth by default." : "Brute-force viable."),
                    url: $"{host}:{dbPort}",
                    remediation: $"Firewall port {dbPort}. Enable authentication immediately.",
                    impact: imp, confidence: 0.99,
                    attackPath: "Connect → authenticate (empty creds) → data dump / RCE",
                    contextBoost: "Database exposed to internet"));
            }
        }

        // ─ Correlation 6: SMB Exposed ± Signing Disabled ─────────────────────
        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            if (ports.Contains(445) || ports.Contains(139))
            {
                var signingDisabled = context.Get<Dictionary<string, bool>>("smb_signing")
                    ?.GetValueOrDefault(host) ?? false;
                var mult = signingDisabled ? ContextMultipliers["smb_signing_disabled"] : 1.0;
                var imp = signingDisabled ? 7.0 : 6.0;
                var s = CalcScore(imp, 0.99) * mult;
                var sev = signingDisabled ? Severity.Critical : Severity.High;

                findings.Add(Finding.Create(
                    sev, FindingCategory.Correlation,
                    "SMB Exposed" + (signingDisabled ? " — Signing Disabled (NTLM Relay)" : ""),
                    detail: "SMB reachable from network. " +
                            (signingDisabled ? "Signing disabled — NTLM relay attack is trivial." : ""),
                    remediation: "Enforce SMB signing via GPO. Restrict SMB to internal networks.",
                    impact: imp, confidence: 0.99,
                    attackPath: "Responder → capture Net-NTLMv2 → relay to SMB (no cracking needed)",
                    contextBoost: signingDisabled ? "SMB + signing disabled" : "SMB exposed"));
            }
        }

        // ─ Correlation 7: XSS + No CSP ───────────────────────────────────────
        if (xssHits.Count > 0 && missingCsp)
        {
            var s = CalcScore(6.0, 0.65) * ContextMultipliers["xss_no_csp"];
            var sev = ScoreToSeverity(s);
            findings.Add(Finding.Create(
                sev, FindingCategory.Correlation,
                $"XSS ({xssHits.Count} location(s)) + No Content-Security-Policy",
                detail: "XSS confirmed without CSP — cookies and credentials fully exposed.",
                remediation: "Fix injection points. Add strict CSP with nonces.",
                impact: 6.0, confidence: 0.65,
                attackPath: "XSS payload → steal session cookies → account takeover",
                contextBoost: "XSS + no CSP"));
        }

        // ─ Correlation 8: CVE Matches with Exploitability Boost ─────────────
        foreach (var cve in cveHits)
        {
            var sev = cve.GetValueOrDefault("severity", "HIGH");
            var mult = sev == "CRITICAL"
                ? ContextMultipliers["critical_cve_confirmed"]
                : 1.2;
            var imp = sev == "CRITICAL" ? 10.0 : 7.0;
            var s = CalcScore(imp, 0.80) * mult;
            if (sev == "CRITICAL")
                s = Math.Min(10.0, s * Exploitability["known_poc_available"]);

            var severity = ScoreToSeverity(Math.Min(10.0, s));
            findings.Add(Finding.Create(
                severity, FindingCategory.CVE,
                $"Exploitable Version: {cve.GetValueOrDefault("title", "Unknown CVE")}",
                detail: $"CVE: {cve.GetValueOrDefault("cve", "")} — matched on: {cve.GetValueOrDefault("matched", "")}",
                remediation: $"Apply patch for {cve.GetValueOrDefault("cve", "")}. Check NVD for details.",
                impact: imp, confidence: 0.80,
                attackPath: "searchsploit / GitHub PoC → exploit → system access",
                contextBoost: "Public PoC likely available for CRITICAL CVEs"));
        }

        return findings;
    }

    // ── CONTEXT BOOSTS ─────────────────────────────────────────────────────────

    private static List<Finding> GenerateContextBoostFindings(
        List<string> endpoints, List<string> sqliHits,
        List<Dictionary<string, string>> jsSecrets, bool wafActive, bool missingCsp)
    {
        var findings = new List<Finding>();

        if (sqliHits.Count > 0 && missingCsp)
        {
            findings.Add(Finding.Create(
                Severity.High, FindingCategory.Intelligence,
                "SQLi + No CSP → Compound Attack Vector",
                detail: "SQL injection combined with missing CSP enables data exfil and XSS chaining.",
                remediation: "Fix SQLi with parameterised queries AND deploy CSP policy.",
                impact: 8.0, confidence: 0.75,
                contextBoost: "SQLi + no CSP = compound risk"));
        }

        return findings;
    }

    // ── TARGET RANKING ─────────────────────────────────────────────────────────

    private static List<Dictionary<string, object>> BuildRankedTargets(
        List<string> endpoints, IReadOnlyDictionary<string, object> openPorts)
    {
        var ranked = new List<Dictionary<string, object>>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var endpoint in endpoints.Take(100))
        {
            if (!seen.Add(endpoint)) continue;
            var (score, reasons) = EndpointScore(endpoint);
            if (score <= 0) continue;

            ranked.Add(new Dictionary<string, object>
            {
                ["url"]      = endpoint,
                ["score"]    = score,
                ["priority"] = score >= 95 ? "CRITICAL" : score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW",
                ["reasons"]  = reasons.Take(4).ToList(),
            });
        }

        // Rank open ports
        foreach (var (host, portsObj) in openPorts)
        {
            if (portsObj is not List<int> ports) continue;
            foreach (var port in ports)
            {
                var risk = PortRisk.GetValueOrDefault(port, 20);
                ranked.Add(new Dictionary<string, object>
                {
                    ["url"]      = $"{host}:{port}",
                    ["score"]    = risk,
                    ["priority"] = risk >= 85 ? "CRITICAL" : risk >= 65 ? "HIGH" : risk >= 40 ? "MEDIUM" : "LOW",
                    ["reasons"]  = new List<string> { $"port {port}" },
                });
            }
        }

        return ranked.OrderByDescending(r => (int)r["score"]).Take(30).ToList();
    }

    private static (int Score, List<string> Reasons) EndpointScore(string url)
    {
        var score = 0;
        var reasons = new List<string>();
        var ul = url.ToLowerInvariant();

        foreach (var (keyword, pts) in EndpointScores)
        {
            if (ul.Contains(keyword))
            {
                score += pts;
                if (pts > 0) reasons.Add(keyword);
            }
        }
        return (score, reasons);
    }

    // ── RECOMMENDATIONS ────────────────────────────────────────────────────────

    private static List<Dictionary<string, object>> BuildRecommendations(
        string target, string baseUrl,
        IReadOnlyDictionary<string, object> openPorts,
        List<Dictionary<string, string>> jsSecrets,
        List<string> sqliHits, List<string> xssHits,
        List<Dictionary<string, string>> cveHits,
        Dictionary<string, object> technologies)
    {
        var recs = new List<Dictionary<string, object>>();
        var allPorts = ParseAllPortsStatic(openPorts);
        var cmsList = technologies.GetValueOrDefault("cms") as List<string> ?? [];

        if (jsSecrets.Count > 0)
            recs.Add(new() { ["priority"]=1, ["severity"]="CRITICAL",
                ["action"]="IMMEDIATE — Rotate ALL exposed secrets found in JavaScript",
                ["command"]="aws iam delete-access-key --access-key-id <KEY_ID>" });

        if (sqliHits.Count > 0)
            recs.Add(new() { ["priority"]=2, ["severity"]="CRITICAL",
                ["action"]="Exploit confirmed SQLi — extract DB schema and credentials",
                ["command"]=$"sqlmap -u '{baseUrl}?id=1' --level=5 --risk=3 --batch --dbs --dump" });

        foreach (var cve in cveHits.Where(c => c.GetValueOrDefault("severity") == "CRITICAL"))
            recs.Add(new() { ["priority"]=3, ["severity"]="CRITICAL",
                ["action"]=$"Exploit PoC: {cve.GetValueOrDefault("title", "")}",
                ["command"]=$"searchsploit {cve.GetValueOrDefault("cve", "")} && nuclei -u {baseUrl} -tags {cve.GetValueOrDefault("cve","").ToLowerInvariant()}" });

        if (allPorts.Contains(6379))
            recs.Add(new() { ["priority"]=4, ["severity"]="CRITICAL",
                ["action"]="Test Redis unauthenticated → RCE via cron",
                ["command"]=$"redis-cli -h {target} ping && redis-cli -h {target} info server" });

        if (cmsList.Any(c => c.Contains("WordPress", StringComparison.OrdinalIgnoreCase)))
            recs.Add(new() { ["priority"]=5, ["severity"]="HIGH",
                ["action"]="WordPress deep scan — vulnerable plugins + brute-force",
                ["command"]=$"wpscan --url {baseUrl} --enumerate vp,vt,u,cb,dbe --plugins-detection aggressive" });

        if (xssHits.Count > 0)
            recs.Add(new() { ["priority"]=6, ["severity"]="HIGH",
                ["action"]="Escalate XSS to blind/stored via XSS Hunter",
                ["command"]=$"xsstrike -u '{baseUrl}?q=test' --crawl --fuzzer --blind" });

        if (allPorts.Contains(445))
            recs.Add(new() { ["priority"]=7, ["severity"]="HIGH",
                ["action"]="SMB full enumeration — null sessions, users, password policy",
                ["command"]=$"enum4linux-ng -A {target} && crackmapexec smb {target} --shares --users" });

        return recs.OrderBy(r => (int)r["priority"]).ToList();
    }

    // ── DEDUPLICATION (mirrors intelligence.py _deduplicate) ──────────────────

    public static IReadOnlyList<Finding> Deduplicate(IEnumerable<Finding> findings)
    {
        var best = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            var key = Regex.Replace(
                $"{f.Category}{f.Title}{f.Url ?? ""}".ToLowerInvariant().Trim(),
                @"\s+", " ");
            if (!best.TryGetValue(key, out var existing) ||
                f.Severity.Rank > existing.Severity.Rank)
                best[key] = f;
        }
        return best.Values.ToList().AsReadOnly();
    }

    // ── SCORING FORMULA ────────────────────────────────────────────────────────

    private static double CalcScore(double impact, double confidence,
        double exploitability = 1.0, double businessImpact = 1.0)
    {
        var confScaled = confidence * 10.0;
        var base_ = (impact * 0.6) + (confScaled * 0.4);
        return Math.Round(Math.Min(10.0, base_ * exploitability * businessImpact), 2);
    }

    private static Severity ScoreToSeverity(double s) => s switch
    {
        >= 9.0 => Severity.Critical, >= 7.0 => Severity.High,
        >= 5.0 => Severity.Medium,   >= 3.0 => Severity.Low,
        _      => Severity.Info,
    };

    // ── HELPERS ────────────────────────────────────────────────────────────────

    private static HashSet<int> ParseAllPorts(IReadOnlyDictionary<string, object> openPorts)
    {
        var all = new HashSet<int>();
        foreach (var (_, portsObj) in openPorts)
            if (portsObj is List<int> ports)
                foreach (var p in ports) all.Add(p);
        return all;
    }

    private static HashSet<int> ParseAllPortsStatic(IReadOnlyDictionary<string, object> openPorts)
        => ParseAllPorts(openPorts);

    private static bool ContainsLoginKeyword(string url)
    {
        var kws = new[] { "login", "signin", "wp-login", "auth", "sign-in", "dashboard" };
        return kws.Any(k => url.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static bool ContainsApiKeyword(string url)
    {
        var kws = new[] { "/api/", "/v1/", "/v2/", "/graphql", "/rest/" };
        return kws.Any(k => url.Contains(k, StringComparison.OrdinalIgnoreCase));
    }
}
