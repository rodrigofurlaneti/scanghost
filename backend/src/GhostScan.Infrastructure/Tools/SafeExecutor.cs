using GhostScan.Infrastructure.Scope;
using Microsoft.Extensions.Logging;

namespace GhostScan.Infrastructure.Tools;

// ── Task State ────────────────────────────────────────────────────────────────

public enum ToolTaskState
{
    Pending,
    Running,
    Success,
    Failed,
    Timeout,
    Skipped,
    Cancelled,
}

// ── Tool Result ───────────────────────────────────────────────────────────────

public sealed class ToolResult
{
    public string Tool      { get; init; } = "";
    public string[] Cmd     { get; init; } = [];
    public int ReturnCode   { get; set; } = -1;
    public string Stdout    { get; set; } = "";
    public string Stderr    { get; set; } = "";
    public ToolTaskState State   { get; set; } = ToolTaskState.Pending;
    public double Elapsed   { get; set; }
    public int Attempts     { get; set; }
    public string Error     { get; set; } = "";

    public bool Success    => State == ToolTaskState.Success;
    public bool TimedOut   => State == ToolTaskState.Timeout;
}

// ── Tool Task ─────────────────────────────────────────────────────────────────

public sealed class ToolTask
{
    public string   Name      { get; init; } = "";
    public string   Tool      { get; init; } = "";
    public string   Args      { get; init; } = "";
    public int      Timeout   { get; init; } = 300;
    public int      Retries   { get; init; } = 2;
    public string[] DependsOn { get; init; } = [];
    public bool     Critical  { get; init; }

    public Func<ToolResult, Task>? OnSuccess { get; init; }
    public Func<ToolResult, Task>? OnFailure { get; init; }
}

// ── Per-tool default timeouts (seconds) ──────────────────────────────────────

public static class ToolTimeouts
{
    private static readonly Dictionary<string, int> Defaults = new(StringComparer.OrdinalIgnoreCase)
    {
        ["nmap"]         = 600,
        ["masscan"]      = 180,
        ["gobuster"]     = 300,
        ["ffuf"]         = 300,
        ["nikto"]        = 600,
        ["sqlmap"]       = 480,
        ["hydra"]        = 600,
        ["nuclei"]       = 600,
        ["wpscan"]       = 300,
        ["dnsrecon"]     = 180,
        ["amass"]        = 300,
        ["sublist3r"]    = 180,
        ["theHarvester"] = 120,
        ["whatweb"]      =  60,
        ["wafw00f"]      =  60,
        ["sslscan"]      =  60,
        ["testssl.sh"]   = 120,
        ["dig"]          =  30,
        ["whois"]        =  30,
        ["commix"]       = 300,
    };

    public static int For(string tool) =>
        Defaults.TryGetValue(tool, out var t) ? t : 300;
}

/// <summary>
/// Fault-tolerant, parallel tool executor — mirrors executor.py from the Python POC.
/// Provides:
///   • Retry with exponential backoff (5s → 15s → 30s)
///   • Task state machine (PENDING → RUNNING → SUCCESS/FAILED/TIMEOUT/CANCELLED)
///   • Parallel execution with dependency graph
///   • Scope enforcement before each command
///   • Failure isolation — one tool crash never aborts the chain
/// </summary>
public sealed class SafeExecutor
{
    private readonly ExternalToolRunner _runner;
    private readonly ScopeEnforcer? _scope;
    private readonly ILogger<SafeExecutor> _logger;
    private readonly int _maxConcurrency;

    private static readonly int[] RetryBackoff = [5, 15, 30];  // seconds

    public SafeExecutor(
        ExternalToolRunner runner,
        ILogger<SafeExecutor> logger,
        ScopeEnforcer? scope = null,
        int maxConcurrency = 10)
    {
        _runner = runner;
        _logger = logger;
        _scope = scope;
        _maxConcurrency = maxConcurrency;
    }

    // ── Single tool execution ─────────────────────────────────────────────────

    /// <summary>
    /// Runs a single tool with retry/backoff. Never throws — always returns a ToolResult.
    /// </summary>
    public async Task<ToolResult> RunAsync(
        string tool, string args,
        int? timeout = null,
        int? retries = null,
        CancellationToken ct = default)
    {
        var effectiveTimeout = timeout ?? ToolTimeouts.For(tool);
        var effectiveRetries = retries ?? 2;

        var result = new ToolResult { Tool = tool, Cmd = [tool, .. args.Split(' ')] };

        // Scope check
        if (_scope is not null)
        {
            try { _scope.WrapCmd(result.Cmd); }
            catch (ScopeViolationException ex)
            {
                result.State = ToolTaskState.Cancelled;
                result.Error = ex.Message;
                _logger.LogWarning("[SafeExecutor] 🚫 Scope block: {Tool} — {Error}", tool, ex.Message);
                return result;
            }
        }

        for (var attempt = 0; attempt <= effectiveRetries; attempt++)
        {
            result.Attempts = attempt + 1;
            if (ct.IsCancellationRequested)
            {
                result.State = ToolTaskState.Cancelled;
                return result;
            }

            var t0 = DateTime.UtcNow;
            result.State = ToolTaskState.Running;

            try
            {
                var (exitCode, stdout, stderr) = await _runner.RunAsync(
                    tool, args, effectiveTimeout, ct);

                result.Elapsed    = (DateTime.UtcNow - t0).TotalSeconds;
                result.ReturnCode = exitCode;
                result.Stdout     = stdout;
                result.Stderr     = stderr;

                if (exitCode == 0 || stdout.Length > 0)
                {
                    result.State = ToolTaskState.Success;
                    _logger.LogDebug("[SafeExecutor] ✓ {Tool} done in {Elapsed:F1}s", tool, result.Elapsed);
                    return result;
                }

                // Non-zero exit
                result.State = ToolTaskState.Failed;
                result.Error = $"Exit code {exitCode}";
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                result.State = ToolTaskState.Cancelled;
                result.Elapsed = (DateTime.UtcNow - t0).TotalSeconds;
                return result;
            }
            catch (TimeoutException)
            {
                result.State = ToolTaskState.Timeout;
                result.Elapsed = effectiveTimeout;
                _logger.LogWarning("[SafeExecutor] ⏱ {Tool} timed out after {Timeout}s (attempt {A}/{B})",
                    tool, effectiveTimeout, attempt + 1, effectiveRetries + 1);
            }
            catch (Exception ex)
            {
                result.State = ToolTaskState.Failed;
                result.Error = ex.Message;
                result.Elapsed = (DateTime.UtcNow - t0).TotalSeconds;
                _logger.LogDebug("[SafeExecutor] ✗ {Tool} error: {Error}", tool, ex.Message);
            }

            if (attempt < effectiveRetries)
            {
                var wait = RetryBackoff[Math.Min(attempt, RetryBackoff.Length - 1)];
                _logger.LogDebug("[SafeExecutor] ↻ Retrying {Tool} in {Wait}s...", tool, wait);
                await Task.Delay(wait * 1000, ct);
            }
        }

        return result;
    }

    // ── Parallel execution with dependency graph ──────────────────────────────

    /// <summary>
    /// Execute a collection of ToolTasks in parallel, respecting DependsOn ordering.
    /// Returns dictionary keyed by task name.
    /// </summary>
    public async Task<Dictionary<string, ToolResult>> RunParallelAsync(
        IEnumerable<ToolTask> tasks,
        int? maxWorkers = null,
        CancellationToken ct = default)
    {
        var workers = maxWorkers ?? _maxConcurrency;
        var results = new Dictionary<string, ToolResult>(StringComparer.OrdinalIgnoreCase);
        var completed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var failedCritical = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allTasks = tasks.ToList();

        using var semaphore = new SemaphoreSlim(workers);
        var running = new Dictionary<string, Task<ToolResult>>(StringComparer.OrdinalIgnoreCase);
        var pending = new HashSet<string>(allTasks.Select(t => t.Name), StringComparer.OrdinalIgnoreCase);

        while (pending.Count > 0 || running.Count > 0)
        {
            if (ct.IsCancellationRequested) break;

            // Submit all tasks whose deps are satisfied
            foreach (var task in allTasks.Where(t => pending.Contains(t.Name)))
            {
                if (running.ContainsKey(task.Name)) continue;

                // Skip if a critical dependency failed
                if (task.DependsOn.Any(dep => failedCritical.Contains(dep)))
                {
                    _logger.LogDebug("[SafeExecutor] ⊘ Skipping {Name} (critical dep failed)", task.Name);
                    var skipped = new ToolResult { Tool = task.Tool, State = ToolTaskState.Skipped };
                    results[task.Name] = skipped;
                    pending.Remove(task.Name);
                    completed.Add(task.Name);
                    continue;
                }

                // Check all deps completed
                if (!task.DependsOn.All(dep => completed.Contains(dep))) continue;

                pending.Remove(task.Name);
                var capturedTask = task;

                running[task.Name] = Task.Run(async () =>
                {
                    await semaphore.WaitAsync(ct);
                    try
                    {
                        _logger.LogDebug("[SafeExecutor] ▶ Starting: {Name}", capturedTask.Name);
                        return await RunAsync(
                            capturedTask.Tool, capturedTask.Args,
                            capturedTask.Timeout, capturedTask.Retries, ct);
                    }
                    finally { semaphore.Release(); }
                }, ct);
            }

            if (running.Count == 0)
            {
                // Nothing is running and nothing can be submitted (deadlock guard)
                if (pending.Count > 0)
                {
                    _logger.LogWarning("[SafeExecutor] Dependency deadlock detected, forcing remaining tasks");
                    foreach (var stuck in pending.ToList())
                    {
                        results[stuck] = new ToolResult { Tool = stuck, State = ToolTaskState.Skipped };
                        pending.Remove(stuck);
                        completed.Add(stuck);
                    }
                }
                break;
            }

            // Wait for at least one task to complete
            var completedTask = await Task.WhenAny(running.Values);
            var finishedName  = running.First(kv => kv.Value == completedTask).Key;
            running.Remove(finishedName);

            var result = await completedTask;
            results[finishedName] = result;
            completed.Add(finishedName);

            if (result.Success)
            {
                _logger.LogInformation("[SafeExecutor] ✓ {Name} complete ({Elapsed:F1}s)",
                    finishedName, result.Elapsed);

                var task = allTasks.FirstOrDefault(t => t.Name == finishedName);
                if (task?.OnSuccess is not null)
                    try { await task.OnSuccess(result); } catch { }
            }
            else
            {
                _logger.LogWarning("[SafeExecutor] ✗ {Name} {State} ({Elapsed:F1}s)",
                    finishedName, result.State, result.Elapsed);

                var task = allTasks.FirstOrDefault(t => t.Name == finishedName);
                if (task?.Critical == true)
                    failedCritical.Add(finishedName);

                if (task?.OnFailure is not null)
                    try { await task.OnFailure(result); } catch { }
            }
        }

        return results;
    }

    // ── Parallel Recon Shortcut ───────────────────────────────────────────────

    /// <summary>
    /// Run nmap + masscan + amass + sublist3r + theHarvester simultaneously.
    /// Mirrors run_recon_parallel() from executor.py.
    /// </summary>
    public async Task<Dictionary<string, ToolResult>> RunReconParallelAsync(
        string target, string ports = "21,22,80,443,445,3306,3389,8080,8443",
        CancellationToken ct = default)
    {
        var reconTasks = new List<ToolTask>();

        if (_runner.IsAvailable("nmap"))
            reconTasks.Add(new ToolTask
            {
                Name = "nmap", Tool = "nmap",
                Args = $"-sT -sV --open -T4 -p {ports} --host-timeout 120s {target}",
                Timeout = 600, Retries = 1,
            });

        if (_runner.IsAvailable("masscan"))
            reconTasks.Add(new ToolTask
            {
                Name = "masscan", Tool = "masscan",
                Args = $"{target} -p0-65535 --rate=5000 -oJ -",
                Timeout = 180, Retries = 0,
            });

        if (_runner.IsAvailable("amass"))
            reconTasks.Add(new ToolTask
            {
                Name = "amass", Tool = "amass",
                Args = $"enum -passive -d {target}",
                Timeout = 300, Retries = 0,
            });

        if (_runner.IsAvailable("sublist3r"))
            reconTasks.Add(new ToolTask
            {
                Name = "sublist3r", Tool = "sublist3r",
                Args = $"-d {target} -n",
                Timeout = 180, Retries = 1,
            });

        if (_runner.IsAvailable("theHarvester"))
            reconTasks.Add(new ToolTask
            {
                Name = "theHarvester", Tool = "theHarvester",
                Args = $"-d {target} -b bing,certspotter,crtsh,hackertarget",
                Timeout = 120, Retries = 1,
            });

        if (reconTasks.Count == 0)
        {
            _logger.LogWarning("[SafeExecutor] No recon tools available for parallel execution");
            return [];
        }

        _logger.LogInformation("[SafeExecutor] Running {Count} recon tools in parallel for {Target}",
            reconTasks.Count, target);

        return await RunParallelAsync(reconTasks, ct: ct);
    }
}
