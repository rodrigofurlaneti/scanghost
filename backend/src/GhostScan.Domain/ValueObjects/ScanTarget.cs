using System.Net;
using System.Text.RegularExpressions;
using GhostScan.Domain.Common;

namespace GhostScan.Domain.ValueObjects;

public sealed class ScanTarget : ValueObject
{
    private static readonly Regex DomainPattern = new(
        @"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
        RegexOptions.Compiled);

    private static readonly Regex CidrPattern = new(
        @"^(\d{1,3}\.){3}\d{1,3}\/(\d|[1-2]\d|3[0-2])$",
        RegexOptions.Compiled);

    public string Value { get; }
    public TargetType Type { get; }

    private ScanTarget(string value, TargetType type)
    {
        Value = value;
        Type = type;
    }

    public static Result<ScanTarget> Create(string rawTarget)
    {
        if (string.IsNullOrWhiteSpace(rawTarget))
            return Result<ScanTarget>.Failure("Target cannot be empty.");

        var normalized = rawTarget.Trim()
            .Replace("https://", "")
            .Replace("http://", "")
            .TrimEnd('/');

        // Remove path, query if present — keep just host
        var hostPart = normalized.Split('/')[0].Split('?')[0].Split('#')[0];

        if (IPAddress.TryParse(hostPart, out _))
            return Result<ScanTarget>.Success(new ScanTarget(hostPart, TargetType.IpAddress));

        if (CidrPattern.IsMatch(hostPart))
            return Result<ScanTarget>.Success(new ScanTarget(hostPart, TargetType.Cidr));

        if (DomainPattern.IsMatch(hostPart))
            return Result<ScanTarget>.Success(new ScanTarget(hostPart, TargetType.Domain));

        return Result<ScanTarget>.Failure($"'{rawTarget}' is not a valid domain, IP address, or CIDR range.");
    }

    public bool IsIpAddress => Type == TargetType.IpAddress;
    public bool IsDomain => Type == TargetType.Domain;
    public bool IsCidr => Type == TargetType.Cidr;

    public string ToBaseUrl(bool useHttps = true) =>
        IsCidr ? Value : $"{(useHttps ? "https" : "http")}://{Value}";

    protected override IEnumerable<object?> GetEqualityComponents()
    {
        yield return Value.ToLowerInvariant();
    }

    public override string ToString() => Value;
}

public enum TargetType { Domain, IpAddress, Cidr }
