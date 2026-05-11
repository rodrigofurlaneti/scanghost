using System.Text.RegularExpressions;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class TechDetector : ITechDetector
{
    public async Task<Dictionary<string, object>> DetectAsync(string baseUrl, HttpClient client, CancellationToken ct)
    {
        var tech = new Dictionary<string, object>
        {
            ["server"] = new List<string>(),
            ["backend"] = new List<string>(),
            ["cms"] = new List<string>()
        };

        try
        {
            var response = await client.GetAsync(baseUrl, ct);
            var html = await response.Content.ReadAsStringAsync(ct);
            var headers = response.Headers.ToDictionary(h => h.Key.ToLower(), h => string.Join(",", h.Value));

            // Header Analysis
            if (headers.TryGetValue("server", out var s)) ((List<string>)tech["server"]).Add(s);
            if (headers.TryGetValue("x-powered-by", out var p)) ((List<string>)tech["backend"]).Add(p);

            // HTML Fingerprinting
            if (html.Contains("wp-content/")) ((List<string>)tech["cms"]).Add("WordPress");
            if (html.Contains("drupal")) ((List<string>)tech["cms"]).Add("Drupal");
            if (html.Contains("_NEXT_DATA_")) ((List<string>)tech["backend"]).Add("Next.js");
        }
        catch { }
        return tech;
    }

    public async Task<(Dictionary<string, object> WafInfo, bool Detected)> DetectWafAsync(string baseUrl, HttpClient client, CancellationToken ct)
    {
        // Implementação fiel ao Wafw00f original aqui
        return (new Dictionary<string, object> { ["detected"] = false }, false);
    }
}