using System.Text.RegularExpressions;
using GhostScan.Infrastructure.Tools;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class TechDetector(ExternalToolRunner toolRunner) : ITechDetector
{
    public async Task<Dictionary<string, object>> DetectAsync(string baseUrl, HttpClient client, CancellationToken ct)
    {
        var tech = new Dictionary<string, object>
        {
            ["server"] = new List<string>(),
            ["backend"] = new List<string>(),
            ["cms"] = new List<string>(),
            ["frontend"] = new List<string>(),
            ["cdn"] = new List<string>()
        };

        try
        {
            var response = await client.GetAsync(baseUrl, ct);
            var html = await response.Content.ReadAsStringAsync(ct);
            var h = response.Headers.Concat(response.Content.Headers).ToDictionary(x => x.Key.ToLower(), x => string.Join(",", x.Value));

            if (h.TryGetValue("server", out var s)) ((List<string>)tech["server"]).Add(s);
            if (h.TryGetValue("x-powered-by", out var p)) ((List<string>)tech["backend"]).Add(p);

            if (html.Contains("wp-content/")) ((List<string>)tech["cms"]).Add("WordPress");
            if (html.Contains("drupal")) ((List<string>)tech["cms"]).Add("Drupal");
            if (html.Contains("data-reactroot")) ((List<string>)tech["frontend"]).Add("React");
        }
        catch { }

        return tech;
    }

    public async Task<(Dictionary<string, object> WafInfo, bool Detected)> DetectWafAsync(string baseUrl, HttpClient client, CancellationToken ct)
    {
        var wafInfo = new Dictionary<string, object> { ["detected"] = false, ["name"] = "" };
        if (toolRunner.IsAvailable("wafw00f"))
        {
            var (_, stdout, _) = await toolRunner.RunAsync("wafw00f", $"-a {baseUrl} -o -", 60, ct);
            if (stdout.Contains("is behind"))
            {
                wafInfo["detected"] = true;
                var match = Regex.Match(stdout, @"is behind (.+?) WAF");
                if (match.Success) wafInfo["name"] = match.Groups[1].Value.Trim();
            }
        }
        return (wafInfo, (bool)wafInfo["detected"]);
    }
}