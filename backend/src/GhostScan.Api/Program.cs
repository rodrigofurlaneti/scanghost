using FluentValidation;
using GhostScan.Api.Hubs;
using GhostScan.Api.Middleware;
using GhostScan.Application.Behaviors;
using GhostScan.Application.Validators;
using GhostScan.Domain.Services;
using GhostScan.Infrastructure;
using MediatR;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// ── Logging ───────────────────────────────────────────────────────────────────
builder.Logging.ClearProviders();
builder.Logging.AddConsole();

// ── Controllers + JSON ────────────────────────────────────────────────────────
builder.Services.AddControllers()
    .AddJsonOptions(opts =>
    {
        opts.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
        opts.JsonSerializerOptions.WriteIndented = true;
    });

// ── MediatR ───────────────────────────────────────────────────────────────────
builder.Services.AddMediatR(cfg =>
{
    cfg.RegisterServicesFromAssembly(typeof(GhostScan.Application.Commands.StartScan.StartScanCommand).Assembly);
    cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(ValidationPipelineBehavior<,>));
});

// ── FluentValidation ──────────────────────────────────────────────────────────
builder.Services.AddValidatorsFromAssemblyContaining<StartScanCommandValidator>();

// ── SignalR ───────────────────────────────────────────────────────────────────
builder.Services.AddSignalR();
builder.Services.AddScoped<IScanProgressNotifier, SignalRScanProgressNotifier>();

// ── Infrastructure ────────────────────────────────────────────────────────────
builder.Services.AddInfrastructure();

// ── Swagger / OpenAPI ─────────────────────────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "GhostScan API",
        Version = "v1",
        Description = """
            ## GhostScan v3 — Elite Vulnerability Scanner API

            Submit a target (domain, IP, or CIDR) and receive a full vulnerability report.

            ### Quick Start
            1. **POST** `/api/scans` with your target to start a scan
            2. **GET** `/api/scans/{scanId}/status` to poll progress
            3. **GET** `/api/scans/{scanId}/report` to retrieve the report

            ### Scan Profiles
            | Profile | Threads | Rate | SQLi | XSS | Brute | WAF Bypass |
            |---------|---------|------|------|-----|-------|------------|
            | stealth | 5 | 2s | ✗ | ✗ | ✗ | ✗ |
            | standard | 20 | 0.1s | ✓ | ✓ | ✗ | auto |
            | aggressive | 50 | 0.05s | ✓ | ✓ | ✓ | ✓ |

            ### Scoring Formula
            ```
            score = (impact × 0.6) + (confidence × 0.4) × exploitability × businessImpact
            ```

            > ⚠️ **Authorized use only.** Unauthorized security testing is illegal.
            """,
        Contact = new OpenApiContact
        {
            Name = "GhostScan",
            Url = new Uri("https://github.com/rodrigofurlaneti/scanghost"),
        },
        License = new OpenApiLicense { Name = "MIT" },
    });

    // Include XML comments for better Swagger docs
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
        options.IncludeXmlComments(xmlPath);

    options.EnableAnnotations();
});

// ── CORS (for browser-based Swagger) ─────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

var app = builder.Build();

// ── Middleware Pipeline ────────────────────────────────────────────────────────
app.UseMiddleware<ValidationExceptionMiddleware>();

if (app.Environment.IsDevelopment() || app.Environment.IsProduction())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("swagger/v1/swagger.json", "GhostScan API v1");
        options.RoutePrefix = string.Empty; // Swagger at root "/"
        options.DocumentTitle = "GhostScan API";
        options.DefaultModelsExpandDepth(-1);
        options.DisplayRequestDuration();
    });
}

app.UseCors();
app.UseRouting();
app.MapControllers();
app.MapHub<ScanProgressHub>("/hubs/scan");

// ── Health Check ──────────────────────────────────────────────────────────────
app.MapGet("/health", () => Results.Ok(new
{
    Status = "Healthy",
    Version = "3.0.0",
    Timestamp = DateTime.UtcNow,
    Message = "GhostScan API is running.",
})).WithTags("Health");

app.Run();
