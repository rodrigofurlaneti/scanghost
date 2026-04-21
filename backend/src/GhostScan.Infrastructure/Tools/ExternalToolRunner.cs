using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.Tools;

public sealed class ExternalToolRunner
{
    private readonly ILogger<ExternalToolRunner> _logger;

    public ExternalToolRunner(ILogger<ExternalToolRunner> logger)
    {
        _logger = logger;
    }

    public bool IsAvailable(string toolName)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = OperatingSystem.IsWindows() ? "where" : "which",
                Arguments = toolName,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            process?.WaitForExit(3000);
            return process?.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public async Task<(int ExitCode, string StdOut, string StdErr)> RunAsync(
        string toolName,
        string arguments,
        int timeoutSeconds = 300,
        CancellationToken cancellationToken = default)
    {
        var stdOut = new StringBuilder();
        var stdErr = new StringBuilder();

        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = toolName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            process.OutputDataReceived += (_, e) =>
            {
                if (e.Data is not null) stdOut.AppendLine(e.Data);
            };
            process.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is not null) stdErr.AppendLine(e.Data);
            };

            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));

            await process.WaitForExitAsync(cts.Token);

            return (process.ExitCode, stdOut.ToString(), stdErr.ToString());
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Tool {Tool} timed out after {Timeout}s", toolName, timeoutSeconds);
            return (-1, stdOut.ToString(), "Timed out");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to run tool {Tool}", toolName);
            return (-1, string.Empty, ex.Message);
        }
    }
}
