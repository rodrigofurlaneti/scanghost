using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using DnsClient;
using DnsClient.Protocol;
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

                // Zone Transfer (AXFR) — CRITICAL if successful
                _logger.LogInformation("[Recon] Attempting zone transfer for {Target}", target.Value);
                var axfrFindings = await AttemptZoneTransferAsync(target.Value, dnsRecords, cancellationToken);
                findings.AddRange(axfrFindings);

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

                // OSINT — theHarvester
                _logger.LogInformation("[Recon] OSINT harvest for {Target}", target.Value);
                var osintData = await OsintHarvestAsync(target.Value, cancellationToken);
                if (osintData.Count > 0) data["osint"] = osintData;

                // WHOIS
                _logger.LogInformation("[Recon] WHOIS lookup for {Target}", target.Value);
                var whoisData = await WhoisLookupAsync(target.Value, cancellationToken);
                if (whoisData.Count > 0) data["whois"] = whoisData;
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

            // Banner Grabbing — after port scan
            _logger.LogInformation("[Recon] Banner grabbing on open ports");
            var banners = await GrabBannersAsync(openPorts, cancellationToken);
            if (banners.Count > 0) data["banners"] = banners;

            // Store openPorts as Dictionary<string,object> so GetOpenPorts() type-cast works.
            // Dictionary<string,List<int>> cannot be cast to Dictionary<string,object> in C#
            // (generics are invariant), so we must convert before storing in ScanContext.
            var openPortsAsObj = openPorts.ToDictionary(
                kv => kv.Key,
                kv => (object)kv.Value);
            context.Set("open_ports", openPortsAsObj);
            context.Set("banners", banners);
            context.Set("dns_records", dnsRecords);
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
            // Extended record types — includes SOA, SRV, CAA beyond basic set
            var recordTypes = new[]
            {
                QueryType.A, QueryType.AAAA, QueryType.MX,
                QueryType.NS, QueryType.TXT, QueryType.CNAME,
                QueryType.SOA, QueryType.SRV, QueryType.CAA
            };

            foreach (var rType in recordTypes)
            {
                try
                {
                    var result = await client.QueryAsync(domain, rType, cancellationToken: cancellationToken);
                    // Use Answers only — AllRecords also includes OPT (EDNS) and SOA authority records
                    // which pollute the output with noise entries like ". 0 512 OPT OPT 512."
                    var values = result.Answers
                        .Select(r => r.ToString() ?? string.Empty)
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

            // DMARC lives at _dmarc.{domain} — query it explicitly and store under "_dmarc" key
            try
            {
                var dmarcResult = await client.QueryAsync($"_dmarc.{domain}", QueryType.TXT,
                    cancellationToken: cancellationToken);
                // Use Answers only — avoid OPT/SOA noise from AllRecords
                var dmarcValues = dmarcResult.Answers
                    .Select(r => r.ToString() ?? string.Empty)
                    .Where(s => !string.IsNullOrEmpty(s))
                    .ToList();
                records["_dmarc"] = dmarcValues; // may be empty list — that means DMARC absent
            }
            catch
            {
                records["_dmarc"] = [];
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Recon] DNS enumeration partial failure for {Domain}", domain);
        }

        return records;
    }

    // ── Zone Transfer (AXFR) ──────────────────────────────────────────────────

    private async Task<List<Finding>> AttemptZoneTransferAsync(
        string domain,
        Dictionary<string, List<string>> dnsRecords,
        CancellationToken cancellationToken)
    {
        var findings = new List<Finding>();

        // Extract nameservers from already-resolved NS records
        var nameservers = new List<string>();
        if (dnsRecords.TryGetValue("NS", out var nsRecords))
        {
            foreach (var ns in nsRecords)
            {
                // NS records look like "0 ns1.example.com." — extract the last token
                var parts = ns.Trim().Split(' ');
                var nsHost = parts[^1].TrimEnd('.');
                if (!string.IsNullOrEmpty(nsHost))
                    nameservers.Add(nsHost);
            }
        }

        if (nameservers.Count == 0) return findings;

        // Try `dig` if available, otherwise raw TCP AXFR
        foreach (var ns in nameservers)
        {
            try
            {
                string axfrOutput;

                if (_toolRunner.IsAvailable("dig"))
                {
                    var (exitCode, stdout, _) = await _toolRunner.RunAsync(
                        "dig", $"@{ns} {domain} AXFR", 30, cancellationToken);
                    axfrOutput = stdout;
                }
                else
                {
                    axfrOutput = await RawAxfrAsync(ns, domain, cancellationToken);
                }

                if (!string.IsNullOrWhiteSpace(axfrOutput)
                    && axfrOutput.Contains(domain)
                    && !axfrOutput.Contains("Transfer failed")
                    && !axfrOutput.Contains("; XFR size: 0"))
                {
                    _logger.LogWarning("[Recon] Zone transfer succeeded on {NS} for {Domain}", ns, domain);
                    findings.Add(Finding.Create(
                        Severity.Critical, FindingCategory.DNS,
                        $"Zone transfer (AXFR) allowed on {ns}",
                        detail: $"The nameserver {ns} permits unauthenticated zone transfers for {domain}. " +
                                "This exposes the full DNS zone, including internal subdomains and IP addresses.",
                        remediation: "Restrict AXFR to authorized secondary nameservers only (ACL or TSIG keys).",
                        impact: 9.0, confidence: 1.0, vulnType: "info_disclosure",
                        url: $"dns://{ns}"));
                    break; // One success is enough
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[Recon] AXFR attempt failed for {NS}/{Domain}", ns, domain);
            }
        }

        return findings;
    }

    /// <summary>Raw TCP AXFR request — fallback when dig is unavailable.</summary>
    private static async Task<string> RawAxfrAsync(string nameserver, string domain, CancellationToken ct)
    {
        var sb = new StringBuilder();
        try
        {
            var nsIp = (await Dns.GetHostAddressesAsync(nameserver, ct)).FirstOrDefault();
            if (nsIp is null) return string.Empty;

            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(nsIp, 53, ct).AsTask();
            if (await Task.WhenAny(connectTask, Task.Delay(5000, ct)) != connectTask || connectTask.IsFaulted)
                return string.Empty;

            using var stream = tcp.GetStream();

            // Build AXFR DNS query
            var labels = domain.Split('.');
            var qname = new List<byte>();
            foreach (var label in labels)
            {
                var bytes = Encoding.ASCII.GetBytes(label);
                qname.Add((byte)bytes.Length);
                qname.AddRange(bytes);
            }
            qname.Add(0); // root label

            var query = new List<byte>
            {
                0x00, 0x01, // ID
                0x00, 0x00, // Flags: standard query
                0x00, 0x01, // QDCOUNT
                0x00, 0x00, // ANCOUNT
                0x00, 0x00, // NSCOUNT
                0x00, 0x00, // ARCOUNT
            };
            query.AddRange(qname);
            query.AddRange([0x00, 0xFC]); // QTYPE=AXFR
            query.AddRange([0x00, 0x01]); // QCLASS=IN

            var payload = query.ToArray();
            var length = new byte[] { (byte)(payload.Length >> 8), (byte)(payload.Length & 0xFF) };
            await stream.WriteAsync(length, ct);
            await stream.WriteAsync(payload, ct);
            await stream.FlushAsync(ct);

            using var cts2 = new CancellationTokenSource(5000);
            var buf = new byte[4096];
            try
            {
                var read = await stream.ReadAsync(buf, cts2.Token);
                if (read > 0) sb.Append(Encoding.ASCII.GetString(buf, 0, read));
            }
            catch (OperationCanceledException) { }
        }
        catch { }

        return sb.ToString();
    }

    // ── Banner Grabbing ───────────────────────────────────────────────────────

    private async Task<Dictionary<string, string>> GrabBannersAsync(
        Dictionary<string, List<int>> openPorts, CancellationToken cancellationToken)
    {
        var banners = new Dictionary<string, string>();
        var semaphore = new SemaphoreSlim(20);

        var tasks = openPorts.SelectMany(kvp =>
            kvp.Value.Select(port => GrabSingleBannerAsync(kvp.Key, port, semaphore, banners, cancellationToken)));

        await Task.WhenAll(tasks);
        return banners;
    }

    private async Task GrabSingleBannerAsync(
        string host, int port, SemaphoreSlim semaphore,
        Dictionary<string, string> banners, CancellationToken ct)
    {
        await semaphore.WaitAsync(ct);
        try
        {
            using var client = new TcpClient();
            var connectTask = client.ConnectAsync(host, port, ct).AsTask();
            using var timeoutCts = new CancellationTokenSource(3000);
            if (await Task.WhenAny(connectTask, Task.Delay(3000, timeoutCts.Token)) != connectTask
                || connectTask.IsFaulted)
                return;

            using var stream = client.GetStream();
            stream.ReadTimeout = 3000;

            // HTTP probe first
            if (port is 80 or 8080 or 8000 or 8008 or 3000 or 5000 or 443 or 8443)
            {
                var probe = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n");
                await stream.WriteAsync(probe, ct);
            }

            var buf = new byte[512];
            try
            {
                var read = await stream.ReadAsync(buf, 0, buf.Length, ct);
                if (read > 0)
                {
                    var banner = Encoding.UTF8.GetString(buf, 0, read)
                        .Split('\n')[0].Trim();
                    if (!string.IsNullOrWhiteSpace(banner))
                        banners[$"{host}:{port}"] = banner[..Math.Min(banner.Length, 200)];
                }
            }
            catch (Exception ex) when (ex is IOException or TimeoutException or OperationCanceledException) { }
        }
        catch { }
        finally { semaphore.Release(); }
    }

    // ── OSINT / theHarvester ──────────────────────────────────────────────────

    private async Task<Dictionary<string, object>> OsintHarvestAsync(
        string domain, CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, object>();
        if (!_toolRunner.IsAvailable("theHarvester"))
        {
            _logger.LogDebug("[Recon] theHarvester not available, skipping OSINT");
            return result;
        }

        try
        {
            var (_, stdout, _) = await _toolRunner.RunAsync(
                "theHarvester", $"-d {domain} -b all", 120, cancellationToken);

            var emails = new HashSet<string>();
            var hosts  = new HashSet<string>();

            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var l = line.Trim();
                // Email pattern
                if (Regex.IsMatch(l, @"^[\w\.\+\-]+@[\w\.\-]+\.[a-z]{2,}$",
                        RegexOptions.IgnoreCase))
                    emails.Add(l.ToLowerInvariant());

                // Subdomain/host pattern
                if (l.EndsWith(domain, StringComparison.OrdinalIgnoreCase) && l.Contains('.'))
                    hosts.Add(l.ToLowerInvariant());
            }

            if (emails.Count > 0) result["emails"] = emails.ToList();
            if (hosts.Count > 0)  result["hosts"]  = hosts.ToList();

            _logger.LogInformation("[Recon] OSINT: {Emails} emails, {Hosts} hosts found",
                emails.Count, hosts.Count);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Recon] theHarvester failed for {Domain}", domain);
        }

        return result;
    }

    // ── WHOIS ─────────────────────────────────────────────────────────────────

    private async Task<Dictionary<string, string>> WhoisLookupAsync(
        string domain, CancellationToken cancellationToken)
    {
        var result = new Dictionary<string, string>();
        if (!_toolRunner.IsAvailable("whois"))
        {
            _logger.LogDebug("[Recon] whois not available, skipping");
            return result;
        }

        try
        {
            var (_, stdout, _) = await _toolRunner.RunAsync(
                "whois", domain, 30, cancellationToken);

            var interestingKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Registrar", "Registrant", "Creation Date", "Updated Date",
                "Registry Expiry Date", "Name Server", "DNSSEC",
                "Registrar Abuse Contact Email", "Registrar Abuse Contact Phone"
            };

            foreach (var line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            {
                var colonIdx = line.IndexOf(':');
                if (colonIdx < 0) continue;

                var key   = line[..colonIdx].Trim();
                var value = line[(colonIdx + 1)..].Trim();

                if (string.IsNullOrEmpty(value)) continue;
                if (interestingKeys.Contains(key) && !result.ContainsKey(key))
                    result[key] = value;
            }

            _logger.LogInformation("[Recon] WHOIS: {Count} fields parsed for {Domain}",
                result.Count, domain);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[Recon] WHOIS failed for {Domain}", domain);
        }

        return result;
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

        // SPF — lives in TXT records of the root domain
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

        // DMARC — lives in TXT records of _dmarc.{domain}, checked separately
        // The key "_dmarc" is injected by EnumerateDnsAsync
        var dmarcTxt = records.GetValueOrDefault("_dmarc", []);
        if (!dmarcTxt.Any(t => t.Contains("DMARC1")))
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
