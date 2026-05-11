using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines
{
    public interface IScreenshotEngine 
    { 
        Task<string?> CaptureAsync(string url, CancellationToken ct); 
    }
}
