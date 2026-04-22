using FluentAssertions;
using FluentValidation;
using GhostScan.Application.Commands.StartScan;
using GhostScan.Application.DTOs;
using GhostScan.Application.Validators;
using Xunit;

namespace GhostScan.Application.Tests;

public sealed class StartScanCommandValidatorTests
{
    private readonly StartScanCommandValidator _validator = new();

    [Fact]
    public void Validate_WithValidRequest_ShouldPass()
    {
        var command = new StartScanCommand(new StartScanRequest
        {
            Target = "example.com",
            Profile = "standard",
            MinSeverity = "info",
        });

        var result = _validator.Validate(command);
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Validate_WithEmptyTarget_ShouldFail()
    {
        var command = new StartScanCommand(new StartScanRequest { Target = "" });
        var result = _validator.Validate(command);
        result.IsValid.Should().BeFalse();
        result.Errors.Should().Contain(e => e.PropertyName.Contains("Target"));
    }

    [Fact]
    public void Validate_WithInvalidProfile_ShouldFail()
    {
        var command = new StartScanCommand(new StartScanRequest
        {
            Target = "example.com",
            Profile = "ultra-aggressive",
        });
        var result = _validator.Validate(command);
        result.IsValid.Should().BeFalse();
    }

    [Theory]
    [InlineData("stealth")]
    [InlineData("standard")]
    [InlineData("aggressive")]
    [InlineData("ghost")]
    public void Validate_WithValidProfile_ShouldPass(string profile)
    {
        var command = new StartScanCommand(new StartScanRequest
        {
            Target = "example.com",
            Profile = profile,
        });
        var result = _validator.Validate(command);
        result.IsValid.Should().BeTrue();
    }

    [Fact]
    public void Validate_WithCrawlDepthOutOfRange_ShouldFail()
    {
        var command = new StartScanCommand(new StartScanRequest
        {
            Target = "example.com",
            CrawlDepth = 99,
        });
        var result = _validator.Validate(command);
        result.IsValid.Should().BeFalse();
    }
}
