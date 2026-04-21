using FluentValidation;
using System.Text.Json;

namespace GhostScan.Api.Middleware;

public sealed class ValidationExceptionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ValidationExceptionMiddleware> _logger;

    public ValidationExceptionMiddleware(
        RequestDelegate next,
        ILogger<ValidationExceptionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (ValidationException ex)
        {
            await HandleValidationExceptionAsync(context, ex);
        }
        catch (InvalidOperationException ex)
        {
            await HandleInvalidOperationAsync(context, ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "Unhandled exception in request pipeline");
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(new
            {
                Status = 500,
                Message = "An internal server error occurred.",
                Detail = ex.Message,
            }));
        }
    }

    private static async Task HandleValidationExceptionAsync(HttpContext context, ValidationException ex)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";

        var errors = ex.Errors
            .GroupBy(e => e.PropertyName)
            .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage).ToArray());

        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            Status = 400,
            Title = "Validation failed.",
            Errors = errors,
        }));
    }

    private static async Task HandleInvalidOperationAsync(HttpContext context, InvalidOperationException ex)
    {
        context.Response.StatusCode = StatusCodes.Status400BadRequest;
        context.Response.ContentType = "application/json";

        await context.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            Status = 400,
            Title = "Invalid operation.",
            Detail = ex.Message,
        }));
    }
}
