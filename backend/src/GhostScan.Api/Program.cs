using FluentValidation;
using GhostScan.Api.Hubs;
using GhostScan.Api.Middleware;
using GhostScan.Application.Behaviors;
using GhostScan.Application.Validators;
using GhostScan.Domain.Services;
using GhostScan.Infrastructure;
using MediatR;
using Microsoft.AspNetCore.HttpOverrides;
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
        Description = "## GhostScan v3 — Elite Vulnerability Scanner API",
        Contact = new OpenApiContact
        {
            Name = "GhostScan",
            Url = new Uri("https://github.com/rodrigofurlaneti/scanghost"),
        },
        License = new OpenApiLicense { Name = "MIT" },
    });

    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
        options.IncludeXmlComments(xmlPath);

    options.EnableAnnotations();
});

// ── ForwardedHeaders (must be configured before app.Build()) ──────────────────
// Clear the default whitelist so Azure's load-balancer IPs are trusted.
// Without this, UseForwardedHeaders() ignores the X-Forwarded-Proto header
// because Azure's IPs are not loopback addresses.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownNetworks.Clear();
    options.KnownProxies.Clear();
});

// ── CORS ──────────────────────────────────────────────────────────────────────
var allowedOrigins = builder.Configuration
    .GetSection("AllowedOrigins")
    .Get<string[]>() ?? [];

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        if (allowedOrigins.Length > 0)
        {
            // Production: specific origins (required for SignalR WebSocket + credentials)
            policy.WithOrigins(allowedOrigins)
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
        else
        {
            // Development fallback: allow any origin (no credentials)
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
    });
});

var app = builder.Build();

// ── Pipeline de Execução ─────────────────────────────────────────────────────

// ForwardedHeaders: necessário no Azure App Service (e qualquer reverse proxy).
// O Azure termina TLS no load balancer e encaminha internamente como HTTP.
// Sem isto, Request.Scheme = "http" mesmo quando o cliente usou HTTPS,
// o que quebra URLs geradas pelo Swagger UI e redirecionamentos.
// Uses the ForwardedHeadersOptions configured in the DI container above.
app.UseForwardedHeaders();

// NÃO usar UseHttpsRedirection() no Azure App Service.
// O redirect HTTP→HTTPS acontece no load balancer (ative "HTTPS Only" no portal Azure).
// Usar UseHttpsRedirection() aqui causaria loop de redirect no Azure.

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}

// Swagger disponível em todos os ambientes (protegido por rede no Azure)
app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "GhostScan API v1");
    // Rota padrão /swagger — NÃO usar string.Empty (causa conflito na raiz com HTTPS)
    options.RoutePrefix = "swagger";
    options.DocumentTitle = "GhostScan API";
});

// Health check na raiz — útil para Azure App Service health probe
app.MapGet("/", () => Results.Redirect("/swagger")).ExcludeFromDescription();

app.UseMiddleware<ValidationExceptionMiddleware>();
app.UseCors();       // CORS antes de routing
app.UseRouting();

app.MapControllers();
app.MapHub<ScanProgressHub>("/hubs/scan");

// ── Health Check ──────────────────────────────────────────────────────────────
app.MapGet("/health", () => Results.Ok(new
{
    Status = "Healthy",
    Version = "3.0.0",
    Timestamp = DateTime.UtcNow, // Use UtcNow para servidores
    Message = "GhostScan API is running.",
})).WithTags("Health");

app.Run();