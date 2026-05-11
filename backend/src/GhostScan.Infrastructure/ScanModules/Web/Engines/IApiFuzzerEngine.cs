using System.Text.Json;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface IApiFuzzerEngine 
    { 
        Task<List<Finding>> FuzzAsync(List<string> endpoints, HttpClient client, CancellationToken ct); 
    }
}
