using System.Text.RegularExpressions;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public class ErrorAnalyzer
    {
        private static readonly Regex StackTraceRegex = new(@"(at\s+[\w\.]+\s+in\s+|Stack trace:|System\.Exception)", RegexOptions.Compiled | RegexOptions.IgnoreCase);

        public async Task<List<Finding>> AnalyzeAsync(string url, string body)
        {
            var findings = new List<Finding>();
            if (StackTraceRegex.IsMatch(body))
            {
                findings.Add(Finding.Create(Severity.Medium, FindingCategory.Web,
                    "Verbose Error Message / Stack Trace Disclosed",
                    url: url,
                    detail: "The application returned a technical stack trace which might leak internal file paths and logic."));
            }
            return findings;
        }
    }
}

