using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using DnsClient;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;
using GhostScan.Infrastructure.ScanModules.Base;
using GhostScan.Infrastructure.Tools;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.ScanModules;

public sealed class ReconScanModule : IScanModule
{
    private readonly ExternalToolRunner _toolRunner;
    private readonly ILogger<ReconScanModule> _logger;

    private static readonly Dictionary<int, (string Severity, string Title, string Detail)> RiskyPorts = new()
    {
        [23]    = ("HIGH",     "Telnet exposed",          "Plaintext credentials over network."),
        [21]    = ("MEDIUM",   "FTP exposed",              "Test for anonymous access."),
        [445]   = ("HIGH",     "SMB exposed",              "EternalBlue / SMB relay attack surface."),
        [3389]  = ("HIGH",     "RDP exposed",              "BlueKeep / brute-force risk."),
        [6379]  = ("CRITICAL", "Redis exposed",            "No auth by default — RCE possible."),
        [9200]  = ("HIGH",     "Elasticsearch exposed",    "Unauthenticated — data exfiltration."),
        [27017] = ("HIGH",     "MongoDB exposed",          "Often unauthenticated in default config."),
        [5432]  = ("MEDIUM",   "PostgreSQL exposed",       "Test default credentials."),
        [3306]  = ("MEDIUM",   "MySQL exposed",            "Test default/empty root credentials."),
        [5900]  = ("HIGH",     "VNC exposed",              "Remote desktop, commonly weak passwords."),
        [1521]  = ("MEDIUM",   "Oracle DB exposed",        "Test default credentials."),
    };

    public string Name => "Recon";

    public ReconScanModule(ExternalToolRunner toolRunner, ILogger<ReconScanModule> logger)
    {
        _toolRunner = toolRunner;
        _logger = logger;
    }

    public async Task<ScanModuleResult> ExecuteAsync(
        ScanTarget target,
        ScanConfiguration configuration,
        ScanContext context,
        CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();
        var data = new Dictionary<string, object>();

        try
        {
            if (!target.IsIpAddress && !target.IsCidr)
            {
                _logger.LogInformation("[Recon] DNS enumeration for {Target}", target.Value);
                var dnsRecords = await EnumerateDnsAsync(target.Value, cancellationToken);
                data["dns_records"] = dnsRecords;

                var dnsFindings = AnalyzeDnsRecords(dnsRecords, target.Value);
                findings.AddRange(dnsFindings);

                if (!configuration.NoSubdomains)
                {
                    _logger.LogInformation("[Recon] Subdomain enumeration for {Target}", target.Value);
                    var subdomains = await EnumerateSubdomainsAsync(target.Value, configuration, cancellationToken);
                    data["subdomains"] = subdomains;

                    if (subdomains.Count > 20)
                    {
                        findings.Add(Finding.Create(
                            Severity.Info, FindingCategory.Recon,
                            $"Large attack surface: {subdomains.Count} subdomains found",
                            remediation: "Audit all subdomains for stale or unprotected services.",
                            impact: 3.0, confidence: 0.99));
                    }
                }
            }

            _logger.LogInformation("[Recon] Port scanning {Target}", target.Value);
            var openPorts = await ScanPortsAsync(target.Value, configuration, cancellationToken);
            data["open_ports"] = openPorts;

            foreach (var (host, hostPorts) in openPorts)
            {
                foreach (var port in hostPorts)
                {
                    if (RiskyPorts.TryGetValue(port, out var risk))
                    {
                        var (sevName, title, detail) = risk;
                        var severity = Severity.FromString(sevName).Value ?? Severity.Medium;
                        findings.Add(Finding.Create(
                            severity, FindingCategory.Port,
                            $"{title} on {host}:{port}",
                            detail: detail,
                            impact: GetPortImpact(port),
                            confidence: 0.99,
                            vulnType: "exposed_service"));
                    }
                }
            }

            context.Set("open_ports", openPorts);
            if (data.TryGetValue("subdomains", out var subs))
                context.Set("subdomains", subs);

            return ScanModuleResult.Succeeded(findings, data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Recon] Error scanning {Target}", target.Value);
            return ScanModuleResult.Failed($"Recon error: {ex.Message}");
        }
    }

    private async Task<Dictionary<string, List<string>>> EnumerateDnsAsync(
        string domain, CancellationToken cancellationToken)
    {
        var records = new Dictionary<string, List<string>>();
        try
        {
            var client = new LookupClient();
            var recordTypes = new[]
            {
                QueryType.A, QueryType.AAAA, QueryType.MX,
                QueryType.NS, QueryType.TXT, QueryType.CNAME
            };

            foreach (var rType in recordTypes)
            {
                try
                {
                    var result = await client.QueryAsync(domain, rType, cancellationToken: cancellationToken);
                    var values = result.AllRecords
                        .Select(r => r.RecordToString())
                        .Where(s => !string.IsNullOrEmpty(s))
                        .ToList();

                    if (values.Count > 0)
                        records[rType.ToString().ToUpperInvariant()] = values;
                }
                catch
                {
                    // Skip individual record type failures
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Recon] DNS enumeration partial failure for {Domain}", domain);
        }

        return records;
    }

    private async Task<List<string>> EnumerateSubdomainsAsync(
        string domain, ScanConfiguration configuration, CancellationToken cancellationToken)
    {
        var found = new HashSet<string>();

        // Try amass if available
        if (_toolRunner.IsAvailable("amass"))
        {
            var (_, stdout, _) = await _toolRunner.RunAsync(
                "amass", $"enum -passive -d {domain}", 180, cancellationToken);

            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var sub = line.Trim();
                if (sub.EndsWith(domain, StringComparison.OrdinalIgnoreCase))
                    found.Add(sub.ToLowerInvariant());
            }
        }

        // DNS brute-force fallback with common prefixes
        var prefixes = GetSubdomainPrefixes(configuration.Profile.WordlistSize);
        var client = new LookupClient();

        var tasks = prefixes.Select(async prefix =>
        {
            var fqdn = $"{prefix}.{domain}";
            try
            {
                var result = await client.QueryAsync(fqdn, QueryType.A, cancellationToken: cancellationToken);
                if (result.Answers.Count > 0)
                    return fqdn;
            }
            catch { }
            return null;
        });

        var results = await Task.WhenAll(tasks);
        foreach (var sub in results.Where(s => s is not null))
            found.Add(sub!);

        return found.ToList();
    }

    private async Task<Dictionary<string, List<int>>> ScanPortsAsync(
        string target, ScanConfiguration configuration, CancellationToken cancellationToken)
    {
        var results = new Dictionary<string, List<int>>();
        var hosts = new List<string>();

        // Resolve to IP if domain
        if (!target.Contains('/'))
        {
            try
            {
                var addresses = await Dns.GetHostAddressesAsync(target, cancellationToken);
                hosts.AddRange(addresses.Select(a => a.ToString()).Take(3));
            }
            catch
            {
                hosts.Add(target);
            }
        }
        else
        {
            hosts.Add(target);
        }

        // Try nmap first
        if (_toolRunner.IsAvailable("nmap"))
        {
            var ports = string.Join(",", configuration.Ports);
            var scanType = configuration.Profile.Intensity == "passive" ? "-sT" : "-sV";
            var (_, stdout, _) = await _toolRunner.RunAsync(
                "nmap", $"{scanType} -p {ports} --open -oX - {hosts.FirstOrDefault() ?? target}",
                300, cancellationToken);

            var parsed = ParseNmapOutput(stdout, hosts.FirstOrDefault() ?? target);
            foreach (var (host, openPorts) in parsed)
                results[host] = openPorts;
        }

        // Socket scan fallback
        if (results.Count == 0)
        {
            foreach (var host in hosts.Take(3))
            {
                var openPorts = await SocketScanAsync(host, configuration.Ports.ToList(), cancellationToken);
                if (openPorts.Count > 0)
                    results[host] = openPorts;
            }
        }

        return results;
    }

    private static async Task<List<int>> SocketScanAsync(
        string host, List<string> ports, CancellationToken cancellationToken)
    {
        var openPorts = new List<int>();
        var portNumbers = ports
            .SelectMany(ParsePortEntry)
            .Distinct()
            .ToList();

        var semaphore = new SemaphoreSlim(50);
        var tasks = portNumbers.Select(async port =>
        {
            await semaphore.WaitAsync(cancellationToken);
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(host, port, cancellationToken).AsTask();
                if (await Task.WhenAny(connectTask, Task.Delay(2000, cancellationToken)) == connectTask
                    && !connectTask.IsFaulted)
                {
                    return port;
                }
            }
            catch { }
            finally
            {
                semaphore.Release();
            }
            return (int?)null;
        });

        var results = await Task.WhenAll(tasks);
        openPorts.AddRange(results.Where(p => p.HasValue).Select(p => p!.Value));
        return openPorts;
    }

    private static IEnumerable<int> ParsePortEntry(string entry)
    {
        if (entry.Contains('-'))
        {
            var parts = entry.Split('-');
            if (int.TryParse(parts[0], out var start) && int.TryParse(parts[1], out var end))
            {
                for (var i = start; i <= end; i++) yield return i;
            }
            yield break;
        }
        if (int.TryParse(entry.Trim(), out var port))
            yield return port;
    }

    private static Dictionary<string, List<int>> ParseNmapOutput(string xmlOutput, string defaultHost)
    {
        var results = new Dictionary<string, List<int>>();
        // Simple regex parse of nmap XML
        var hostMatches = System.Text.RegularExpressions.Regex.Matches(
            xmlOutput, @"<host[^>]*>.*?</host>",
            System.Text.RegularExpressions.RegexOptions.Singleline);

        foreach (System.Text.RegularExpressions.Match hostMatch in hostMatches)
        {
            var hostXml = hostMatch.Value;
            var addrMatch = System.Text.RegularExpressions.Regex.Match(
                hostXml, @"<address addr=""([^""]+)""");
            var host = addrMatch.Success ? addrMatch.Groups[1].Value : defaultHost;

            var portMatches = System.Text.RegularExpressions.Regex.Matches(
                hostXml, @"<port protocol=""tcp"" portid=""(\d+)"">.*?<state state=""open""",
                System.Text.RegularExpressions.RegexOptions.Singleline);

            var openPorts = portMatches
                .Select(m => int.Parse(m.Groups[1].Value))
                .ToList();

            if (openPorts.Count > 0)
                results[host] = openPorts;
        }

        return results;
    }

    private static List<Finding> AnalyzeDnsRecords(
        Dictionary<string, List<string>> records, string domain)
    {
        var findings = new List<Finding>();
        var txt = records.GetValueOrDefault("TXT", []);

        if (!txt.Any(t => t.Contains("v=spf1")))
        {
            findings.Add(Finding.Create(
                Severity.Medium, FindingCategory.DNS,
                "SPF record missing",
                detail: "Without SPF, email spoofing is trivial.",
                remediation: "Add 'v=spf1 include:... -all' TXT record.",
                impact: 4.0, confidence: 0.99, vulnType: "info_disclosure"));
        }

        if (!txt.Any(t => t.Contains("DMARC1")))
        {
            findings.Add(Finding.Create(
                Severity.Medium, FindingCategory.DNS,
                "DMARC record missing",
                detail: "Without DMARC, phishing emails can abuse your domain.",
                remediation: "Add _dmarc TXT record with p=reject policy.",
                impact: 4.0, confidence: 0.99));
        }

        return findings;
    }

    private static double GetPortImpact(int port) => port switch
    {
        6379 => 9.0,   // Redis
        27017 => 8.0,  // MongoDB
        9200 => 8.0,   // Elasticsearch
        3389 => 8.0,   // RDP
        445 => 7.0,    // SMB
        5900 => 7.0,   // VNC
        23 => 7.0,     // Telnet
        _ => 5.0
    };

    private static List<string> GetSubdomainPrefixes(string wordlistSize) => wordlistSize switch
    {
        "small" => ["www", "mail", "api", "dev", "test", "admin", "app", "ftp", "vpn", "remote"],
        "large" => GetLargePrefixList(),
        _ => GetMediumPrefixList()
    };

    private static List<string> GetMediumPrefixList() =>
    [
        "www", "mail", "api", "dev", "test", "admin", "app", "ftp", "vpn", "remote",
        "blog", "shop", "cdn", "auth", "login", "portal", "dashboard", "staging",
        "beta", "internal", "git", "ci", "jenkins", "grafana", "prometheus",
        "smtp", "pop", "imap", "m", "mobile", "secure", "payments", "checkout"
    ];

    private static List<string> GetLargePrefixList()
    {
        var medium = GetMediumPrefixList();
        var additional = new List<string>
        {
            "ns1", "ns2", "ns3", "mx1", "mx2", "demo", "sandbox", "prod", "qa",
            "help", "support", "docs", "status", "monitor", "metrics", "health",
            "backup", "db", "database", "redis", "elastic", "kibana", "rabbitmq",
            "kafka", "zookeeper", "consul", "vault", "nomad", "k8s", "kubernetes",
            "registry", "docker", "hub", "nexus", "sonar", "jira", "confluence",
            "gitlab", "github", "bitbucket", "npm", "pypi", "artifacts", "s3",
            "files", "uploads", "static", "assets", "img", "images", "media"
        };
        return [.. medium, .. additional];
    }
}
