using System.Text;
using System.Web;

namespace GhostScan.Infrastructure.WafBypass;

/// <summary>
/// Full WAF evasion engine — mirrors waf_bypass.py exactly.
/// 9 profiles: CloudFlare, Akamai, AWS-WAF, F5, Imperva, ModSecurity, Wordfence, Sucuri, Generic.
/// </summary>
public sealed class WafBypassEngine
{
    private static readonly Random Rng = new();

    private static readonly string[] BrowserUserAgents =
    [
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Wget/1.21.3",
        "curl/7.88.1",
    ];

    public static readonly Dictionary<string, WafProfile> Profiles = new(StringComparer.OrdinalIgnoreCase)
    {
        ["cloudflare"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["CF-Connecting-IP"]  = "127.0.0.1",
                ["X-Forwarded-For"]   = "127.0.0.1",
                ["X-Real-IP"]         = "127.0.0.1",
                ["X-Originating-IP"]  = "127.0.0.1",
            },
            UserAgents      = ["Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"],
            SqlmapTamper    = "space2comment,randomcase,charencode,between",
            Techniques      = ["case_variation", "url_encode", "unicode_encode", "comment_insertion", "whitespace_injection"],
            DelayMin        = 0.8,  DelayMax = 2.5,
            GobusterDelay   = "500ms",
            FfufRate        = "30",
        },
        ["akamai"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"] = "127.0.0.1",
                ["True-Client-IP"]  = "127.0.0.1",
                ["X-Real-IP"]       = "127.0.0.1",
                ["Pragma"]          = "akamai-x-get-request-id",
                ["X-Akamai-Debug"]  = "true",
            },
            UserAgents   = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0"],
            SqlmapTamper = "space2comment,charunicodeencode,randomcase,between",
            Techniques   = ["double_url_encode", "unicode_encode", "hex_encode", "case_variation"],
            DelayMin = 1.0, DelayMax = 3.5,
            GobusterDelay = "800ms", FfufRate = "20",
        },
        ["aws-waf"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"]  = "127.0.0.1",
                ["X-Amzn-Trace-Id"]  = "Root=bypass",
                ["X-Real-IP"]        = "127.0.0.1",
            },
            UserAgents   = ["Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"],
            SqlmapTamper = "space2comment,randomcase,between",
            Techniques   = ["url_encode", "comment_insertion", "case_variation"],
            DelayMin = 0.3, DelayMax = 1.2,
            GobusterDelay = "300ms", FfufRate = "50",
        },
        ["f5"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"] = "127.0.0.1",
                ["X-F5-IP"]         = "127.0.0.1",
                ["X-Real-IP"]       = "127.0.0.1",
            },
            UserAgents   = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"],
            SqlmapTamper = "charunicodeencode,space2comment,randomcase,multiplespaces",
            Techniques   = ["double_url_encode", "unicode_encode", "multiline_payload"],
            DelayMin = 0.5, DelayMax = 2.0,
            GobusterDelay = "400ms", FfufRate = "40",
        },
        ["imperva"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"]     = "127.0.0.1",
                ["X-Real-IP"]           = "127.0.0.1",
                ["Incapsula-Client-IP"] = "127.0.0.1",
            },
            UserAgents   = ["Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"],
            SqlmapTamper = "space2comment,charencode,randomcase,between,multiplespaces",
            Techniques   = ["url_encode", "case_variation", "comment_insertion", "whitespace_injection"],
            DelayMin = 1.0, DelayMax = 3.0,
            GobusterDelay = "700ms", FfufRate = "25",
        },
        ["modsecurity"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"] = "127.0.0.1",
                ["X-Real-IP"]       = "127.0.0.1",
            },
            UserAgents   = ["Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"],
            SqlmapTamper = "space2comment,randomcase,charencode,between,equaltolike",
            Techniques   = ["url_encode", "case_variation", "comment_insertion", "whitespace_injection", "hex_encode"],
            DelayMin = 0.3, DelayMax = 1.5,
            GobusterDelay = "300ms", FfufRate = "40",
        },
        ["wordfence"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"] = "127.0.0.1",
                ["X-Real-IP"]       = "127.0.0.1",
            },
            UserAgents = ["Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                          "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"],
            SqlmapTamper = "space2comment,randomcase,charencode",
            Techniques   = ["case_variation", "url_encode", "comment_insertion"],
            DelayMin = 0.5, DelayMax = 2.0,
            GobusterDelay = "400ms", FfufRate = "35",
        },
        ["sucuri"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"]   = "127.0.0.1",
                ["X-Real-IP"]         = "127.0.0.1",
                ["X-Sucuri-Clientip"] = "127.0.0.1",
            },
            UserAgents   = ["Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"],
            SqlmapTamper = "space2comment,randomcase",
            Techniques   = ["case_variation", "url_encode"],
            DelayMin = 1.0, DelayMax = 3.0,
            GobusterDelay = "600ms", FfufRate = "25",
        },
        ["generic"] = new()
        {
            Headers = new Dictionary<string, string>
            {
                ["X-Forwarded-For"]          = "127.0.0.1",
                ["X-Real-IP"]                = "127.0.0.1",
                ["X-Originating-IP"]         = "127.0.0.1",
                ["X-Remote-IP"]              = "127.0.0.1",
                ["X-Remote-Addr"]            = "127.0.0.1",
                ["X-Client-IP"]              = "127.0.0.1",
                ["Forwarded"]                = "for=127.0.0.1",
                ["X-Custom-IP-Authorization"]= "127.0.0.1",
            },
            UserAgents = [
                "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            ],
            SqlmapTamper = "space2comment,randomcase,charencode",
            Techniques   = ["case_variation", "url_encode", "comment_insertion", "whitespace_injection"],
            DelayMin = 0.5, DelayMax = 2.0,
            GobusterDelay = "400ms", FfufRate = "40",
        },
    };

    private readonly WafProfile _profile;
    private readonly string _wafKey;
    private readonly string _intensity;
    private int _requestCount;

    public WafBypassEngine(string wafName = "generic", string intensity = "normal")
    {
        _wafKey   = Normalise(wafName);
        _profile  = Profiles.GetValueOrDefault(_wafKey, Profiles["generic"]);
        _intensity = intensity;
    }

    public string WafName => _wafKey;

    // ── HEADERS ────────────────────────────────────────────────────────────────

    /// <summary>Get full evasion headers dict including UA rotation.</summary>
    public Dictionary<string, string> GetHeaders()
    {
        var ua = PickUa();
        var headers = new Dictionary<string, string>(_profile.Headers, StringComparer.OrdinalIgnoreCase)
        {
            ["User-Agent"]               = ua,
            ["Accept"]                   = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ["Accept-Language"]          = "en-US,en;q=0.5",
            ["Accept-Encoding"]          = "gzip, deflate, br",
            ["Connection"]               = "keep-alive",
            ["Upgrade-Insecure-Requests"]= "1",
            ["Cache-Control"]            = "max-age=0",
            ["DNT"]                      = "1",
        };
        return headers;
    }

    public void ApplyToClient(HttpClient client)
    {
        foreach (var (k, v) in GetHeaders())
        {
            try { client.DefaultRequestHeaders.TryAddWithoutValidation(k, v); }
            catch { }
        }
    }

    // ── THROTTLE ───────────────────────────────────────────────────────────────

    public async Task ThrottleAsync(CancellationToken ct = default)
    {
        var mult = _intensity switch
        {
            "passive"     => 2.5,
            "aggressive"  => 0.2,
            _             => 1.0,
        };
        var delay = Rng.NextDouble() * (_profile.DelayMax - _profile.DelayMin) + _profile.DelayMin;
        delay *= mult;
        if (delay > 0.05)
            await Task.Delay(TimeSpan.FromSeconds(delay), ct);

        _requestCount++;
        if (_requestCount % 50 == 0)
            await Task.Delay(TimeSpan.FromSeconds(Rng.Next(3, 8)), ct);
    }

    // ── PAYLOAD ENCODING ───────────────────────────────────────────────────────

    public string EncodePayload(string payload, string? technique = null)
    {
        var tech = technique ?? _profile.Techniques[Rng.Next(_profile.Techniques.Length)];
        return tech switch
        {
            "url_encode"           => HttpUtility.UrlEncode(payload) ?? payload,
            "double_url_encode"    => HttpUtility.UrlEncode(HttpUtility.UrlEncode(payload)) ?? payload,
            "unicode_encode"       => UnicodeEncode(payload),
            "hex_encode"           => HexEncode(payload),
            "html_entity"          => HtmlEntity(payload),
            "case_variation"       => CaseVariation(payload),
            "comment_insertion"    => InsertComments(payload),
            "whitespace_injection" => WhitespaceInjection(payload),
            "multiline_payload"    => MultilinePayload(payload),
            _                      => HttpUtility.UrlEncode(payload) ?? payload,
        };
    }

    public List<string> EncodeAll(string payload)
    {
        var results = new List<string> { payload };
        foreach (var tech in _profile.Techniques)
        {
            try
            {
                var enc = EncodePayload(payload, tech);
                if (!string.IsNullOrEmpty(enc) && enc != payload)
                    results.Add(enc);
            }
            catch { }
        }
        return results.Distinct().ToList();
    }

    // ── TOOL CLI PATCHING ──────────────────────────────────────────────────────

    public string[] PatchGobusterArgs(string[] cmd)
    {
        var ua = PickUa();
        return [.. cmd,
            "-a", ua, "--random-agent", "--delay", _profile.GobusterDelay,
            "-H", "X-Forwarded-For: 127.0.0.1", "-H", "X-Real-IP: 127.0.0.1", "-k"];
    }

    public string[] PatchFfufArgs(string[] cmd)
    {
        var ua = PickUa();
        var mult = _intensity switch { "passive" => 0.3, "aggressive" => 3.0, _ => 1.0 };
        var rate = (int)(int.Parse(_profile.FfufRate) * mult);
        return [.. cmd,
            "-H", $"User-Agent: {ua}", "-H", "X-Forwarded-For: 127.0.0.1",
            "-H", "X-Real-IP: 127.0.0.1", "-rate", rate.ToString(), "-timeout", "15", "-k"];
    }

    public string[] PatchSqlmapArgs(string[] cmd)
    {
        var ua = PickUa();
        var delay = (Rng.NextDouble() * (_profile.DelayMax - _profile.DelayMin) + _profile.DelayMin)
                    .ToString("F1");
        return [.. cmd,
            "--tamper", _profile.SqlmapTamper, "--random-agent", "--delay", delay,
            "--headers", "X-Forwarded-For: 127.0.0.1\nX-Real-IP: 127.0.0.1",
            "--timeout", "15", "--retries", "3"];
    }

    public string[] PatchNiktoArgs(string[] cmd)
    {
        var ua = PickUa();
        var evasion = _intensity switch { "passive" => "1", "aggressive" => "12345678", _ => "1234" };
        return [.. cmd, "-useragent", ua, "-evasion", evasion];
    }

    public string GetTamperScripts() => _profile.SqlmapTamper;

    // ── PRIVATE ────────────────────────────────────────────────────────────────

    private string PickUa()
    {
        var list = _profile.UserAgents.Length > 0 ? _profile.UserAgents : BrowserUserAgents;
        return list[Rng.Next(list.Length)];
    }

    private static string Normalise(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "generic";
        var nl = name.ToLowerInvariant();
        foreach (var key in Profiles.Keys)
            if (nl.Contains(key)) return key;
        return "generic";
    }

    private static string UnicodeEncode(string p) =>
        string.Concat(p.Select(c =>
            c > 127 || "<>\"'&=()".Contains(c) ? $"\\u{(int)c:x4}" : c.ToString()));

    private static string HexEncode(string p)
    {
        if (System.Text.RegularExpressions.Regex.IsMatch(p, @"^[a-zA-Z0-9_\s]+$"))
            return "0x" + Convert.ToHexString(Encoding.UTF8.GetBytes(p)).ToLowerInvariant();
        return p;
    }

    private static string HtmlEntity(string p)
    {
        var map = new Dictionary<char, string>
        { ['<']="&lt;", ['>']="&gt;", ['"']="&quot;", ['\'']="&#x27;", ['&']="&amp;" };
        return string.Concat(p.Select(c => map.TryGetValue(c, out var e) ? e : c.ToString()));
    }

    private static string CaseVariation(string p) =>
        string.Concat(p.Select((c, i) => i % 2 == 0 ? char.ToUpperInvariant(c) : char.ToLowerInvariant(c)));

    private static string InsertComments(string p)
    {
        var result = System.Text.RegularExpressions.Regex.Replace(p,
            @"\b(SELECT|FROM|WHERE|AND|OR|UNION|INSERT|UPDATE|DELETE|DROP|TABLE|INTO)\b",
            m => m.Value + "/**/",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        return result != p ? result : p.Replace(" ", "/**/");
    }

    private static string WhitespaceInjection(string p)
    {
        var alts = new[] { "\t", "%09", "%0a", "%0d", "%0b", "%0c" };
        return p.Replace(" ", alts[Rng.Next(alts.Length)]);
    }

    private static string MultilinePayload(string p)
    {
        var mid = p.Length / 2;
        return p[..mid] + "%0d%0a" + p[mid..];
    }
}

public sealed class WafProfile
{
    public Dictionary<string, string> Headers { get; init; } = new();
    public string[] UserAgents { get; init; } = [];
    public string SqlmapTamper { get; init; } = "space2comment,randomcase";
    public string[] Techniques { get; init; } = ["url_encode"];
    public double DelayMin { get; init; } = 0.3;
    public double DelayMax { get; init; } = 1.0;
    public string GobusterDelay { get; init; } = "400ms";
    public string FfufRate { get; init; } = "40";
}

/// <summary>Build a WafBypassEngine from a WAF detection result.</summary>
public static class WafBypassFactory
{
    public static WafBypassEngine Build(Dictionary<string, object>? wafResult, string intensity = "normal")
    {
        if (wafResult is null || !wafResult.TryGetValue("detected", out var det) || det is not true)
            return new WafBypassEngine("generic", intensity);

        var name = wafResult.GetValueOrDefault("waf")?.ToString()
                ?? wafResult.GetValueOrDefault("manufacturer")?.ToString()
                ?? "generic";
        return new WafBypassEngine(name, intensity);
    }
}
