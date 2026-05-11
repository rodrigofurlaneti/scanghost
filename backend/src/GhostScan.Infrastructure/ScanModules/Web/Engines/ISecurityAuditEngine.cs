using GhostScan.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface ISecurityAuditEngine
    {
        Task<List<Finding>> AuditAsync(string baseUrl, HttpClient httpClient, CancellationToken ct);
    }
}
