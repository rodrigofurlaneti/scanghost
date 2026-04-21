using GhostScan.Application.Commands.CancelScan;
using GhostScan.Application.Commands.StartScan;
using GhostScan.Application.DTOs;
using GhostScan.Application.Queries.GetScanHistory;
using GhostScan.Application.Queries.GetScanReport;
using GhostScan.Application.Queries.GetScanStatus;
using MediatR;
using Microsoft.AspNetCore.Mvc;

namespace GhostScan.Api.Controllers;

/// <summary>
/// GhostScan Vulnerability Scanner API.
/// Submit a target endpoint and retrieve a full vulnerability report.
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public sealed class ScansController : ControllerBase
{
    private readonly IMediator _mediator;

    public ScansController(IMediator mediator)
    {
        _mediator = mediator;
    }

    /// <summary>
    /// Start a new vulnerability scan.
    /// Returns a scan ID that you can poll for status and results.
    /// </summary>
    /// <param name="request">Scan configuration — target is required, all other options are optional.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Scan ID (GUID) — use it to poll status and retrieve the report.</returns>
    [HttpPost]
    [ProducesResponseType(typeof(StartScanResponse), StatusCodes.Status202Accepted)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> StartScan(
        [FromBody] StartScanRequest request,
        CancellationToken cancellationToken)
    {
        var command = new StartScanCommand(request);
        var scanId = await _mediator.Send(command, cancellationToken);

        return Accepted(new StartScanResponse
        {
            ScanId = scanId,
            StatusUrl = Url.Action(nameof(GetScanStatus), new { scanId }),
            ReportUrl = Url.Action(nameof(GetReport), new { scanId }),
            WebSocketUrl = $"/hubs/scan?scanId={scanId}",
            Message = $"Scan started. Poll {Url.Action(nameof(GetScanStatus), new { scanId })} for progress.",
        });
    }

    /// <summary>
    /// Get real-time status of a running or completed scan.
    /// </summary>
    [HttpGet("{scanId:guid}/status")]
    [ProducesResponseType(typeof(ScanStatusDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> GetScanStatus(
        Guid scanId, CancellationToken cancellationToken)
    {
        var status = await _mediator.Send(new GetScanStatusQuery(scanId), cancellationToken);
        if (status is null) return NotFound(new { Message = $"Scan {scanId} not found." });
        return Ok(status);
    }

    /// <summary>
    /// Get the full vulnerability report for a completed scan.
    /// </summary>
    /// <param name="scanId">Scan ID.</param>
    /// <param name="minSeverity">Filter findings by minimum severity: critical, high, medium, low, info.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    [HttpGet("{scanId:guid}/report")]
    [ProducesResponseType(typeof(VulnerabilityReportDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    public async Task<IActionResult> GetReport(
        Guid scanId,
        [FromQuery] string? minSeverity = null,
        CancellationToken cancellationToken = default)
    {
        var statusQuery = await _mediator.Send(new GetScanStatusQuery(scanId), cancellationToken);
        if (statusQuery is null) return NotFound(new { Message = $"Scan {scanId} not found." });

        if (statusQuery.Status == "Running" || statusQuery.Status == "Pending")
        {
            return Accepted(new
            {
                Message = "Scan still in progress.",
                PercentComplete = statusQuery.PercentComplete,
                CurrentPhase = statusQuery.CurrentPhase,
                CurrentActivity = statusQuery.CurrentActivity,
                FindingsSoFar = statusQuery.FindingsCount,
            });
        }

        var report = await _mediator.Send(
            new GetScanReportQuery(scanId, minSeverity), cancellationToken);

        if (report is null) return NotFound(new { Message = $"Report for scan {scanId} not found." });
        return Ok(report);
    }

    /// <summary>
    /// Cancel a running scan.
    /// </summary>
    [HttpDelete("{scanId:guid}")]
    [ProducesResponseType(StatusCodes.Status204NoContent)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    public async Task<IActionResult> CancelScan(
        Guid scanId, CancellationToken cancellationToken)
    {
        var cancelled = await _mediator.Send(new CancelScanCommand(scanId), cancellationToken);
        if (!cancelled) return NotFound(new { Message = $"Scan {scanId} not found or cannot be cancelled." });
        return NoContent();
    }

    /// <summary>
    /// List all scans (paginated).
    /// </summary>
    [HttpGet]
    [ProducesResponseType(typeof(IReadOnlyList<ScanStatusDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetHistory(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20,
        CancellationToken cancellationToken = default)
    {
        var history = await _mediator.Send(
            new GetScanHistoryQuery(page, pageSize), cancellationToken);
        return Ok(history);
    }

    /// <summary>
    /// Quick scan — single endpoint, returns report synchronously (waits for completion).
    /// Timeout: 5 minutes. Use async flow for long scans.
    /// </summary>
    [HttpPost("quick")]
    [ProducesResponseType(typeof(VulnerabilityReportDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status408RequestTimeout)]
    public async Task<IActionResult> QuickScan(
        [FromBody] StartScanRequest request,
        CancellationToken cancellationToken)
    {
        var command = new StartScanCommand(request);
        var scanId = await _mediator.Send(command, cancellationToken);

        // Poll until complete, max 5 minutes
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(TimeSpan.FromMinutes(5));

        while (!cts.Token.IsCancellationRequested)
        {
            await Task.Delay(3000, cts.Token);

            var status = await _mediator.Send(new GetScanStatusQuery(scanId), cts.Token);
            if (status is null) return NotFound();

            if (status.Status is "Completed" or "Failed" or "Cancelled")
            {
                var report = await _mediator.Send(new GetScanReportQuery(scanId), cts.Token);
                return Ok(report);
            }
        }

        return StatusCode(StatusCodes.Status408RequestTimeout, new
        {
            Message = "Scan is taking longer than 5 minutes. Use the async flow.",
            ScanId = scanId,
        });
    }
}

public sealed class StartScanResponse
{
    public Guid ScanId { get; init; }
    public string? StatusUrl { get; init; }
    public string? ReportUrl { get; init; }
    public string? WebSocketUrl { get; init; }
    public string Message { get; init; } = string.Empty;
}
