using HtmlAgilityPack;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class CrawlerEngine : ICrawlerEngine
{
    public async Task<(List<string> Endpoints, List<Dictionary<string, string>> Forms)> CrawlAsync(string baseUrl, HttpClient client, int depth, CancellationToken ct)
    {
        var endpoints = new List<string> { baseUrl };
        var forms = new List<Dictionary<string, string>>();
        try
        {
            var response = await client.GetAsync(baseUrl, ct);
            var html = await response.Content.ReadAsStringAsync(ct);
            var doc = new HtmlDocument(); doc.LoadHtml(html);
            var nodes = doc.DocumentNode.SelectNodes("//a[@href]");
            if (nodes != null)
            {
                foreach (var n in nodes)
                {
                    var href = n.GetAttributeValue("href", "");
                    if (href.StartsWith("/")) endpoints.Add(baseUrl.TrimEnd('/') + href);
                }
            }
        }
        catch { }
        return (endpoints.Distinct().ToList(), forms);
    }
}