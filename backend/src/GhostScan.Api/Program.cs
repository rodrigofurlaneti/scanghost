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

// ── CORS ──────────────────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader());
});

var app = builder.Build();

// ── Pipeline de Execução ─────────────────────────────────────────────────────

// IMPORTANTE: Em Produção no Azure, nunca use app.UseHttpsRedirection() 
// se estiver tendo problemas de certificado no container.

if (app.Environment.IsDevelopment() || app.Environment.IsProduction())
{
    // Ativa para ver o erro real na tela enquanto debuga o deploy
    app.UseDeveloperExceptionPage();

    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "GhostScan API v1");
        options.RoutePrefix = string.Empty; // Swagger na raiz
        options.DocumentTitle = "GhostScan API";
    });
}

app.UseMiddleware<ValidationExceptionMiddleware>();
app.UseCors();
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