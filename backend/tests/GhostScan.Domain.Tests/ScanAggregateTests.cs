using FluentAssertions;
using GhostScan.Domain.Aggregates.Scans;
using GhostScan.Domain.Entities;
using GhostScan.Domain.ValueObjects;

namespace GhostScan.Domain.Tests;

public sealed class ScanAggregateTests
{
    [Fact]
    public void Create_WithValidTarget_ShouldBeInPendingStatus()
    {
        // Arrange
        var target = ScanTarget.Create("example.com").Value!;
        var config = ScanConfiguration.CreateDefault();

        // Act
        var scan = Scan.Create(target, config);

        // Assert
        scan.Status.Should().Be(ScanStatus.Pending);
        scan.FindingsCount.Should().Be(0);
        scan.IsComplete().Should().BeFalse();
    }

    [Fact]
    public void Start_FromPending_ShouldTransitionToRunning()
    {
        // Arrange
        var scan = CreateScan();

        // Act
        var result = scan.Start();

        // Assert
        result.IsSuccess.Should().BeTrue();
        scan.Status.Should().Be(ScanStatus.Running);
        scan.IsRunning().Should().BeTrue();
    }

    [Fact]
    public void Complete_FromRunning_ShouldTransitionToCompleted()
    {
        // Arrange
        var scan = CreateScan();
        scan.Start();

        // Act
        var result = scan.Complete();

        // Assert
        result.IsSuccess.Should().BeTrue();
        scan.Status.Should().Be(ScanStatus.Completed);
        scan.IsComplete().Should().BeTrue();
        scan.CompletedAt.Should().NotBeNull();
    }

    [Fact]
    public void AddFinding_WhenRunning_ShouldIncreaseCount()
    {
        // Arrange
        var scan = CreateScan();
        scan.Start();
        var finding = Finding.Create(
            Severity.High, FindingCategory.Web, "Test finding");

        // Act
        var result = scan.AddFinding(finding);

        // Assert
        result.IsSuccess.Should().BeTrue();
        scan.FindingsCount.Should().Be(1);
    }

    [Fact]
    public void AddFinding_WhenNotRunning_ShouldFail()
    {
        // Arrange
        var scan = CreateScan(); // still pending
        var finding = Finding.Create(Severity.High, FindingCategory.Web, "Test");

        // Act
        var result = scan.AddFinding(finding);

        // Assert
        result.IsFailure.Should().BeTrue();
    }

    [Fact]
    public void Cancel_FromPending_ShouldSucceed()
    {
        // Arrange
        var scan = CreateScan();

        // Act
        var result = scan.Cancel();

        // Assert
        result.IsSuccess.Should().BeTrue();
        scan.Status.Should().Be(ScanStatus.Cancelled);
    }

    [Fact]
    public void HasCriticalFindings_WithCriticalFinding_ShouldReturnTrue()
    {
        // Arrange
        var scan = CreateScan();
        scan.Start();
        scan.AddFinding(Finding.Create(
            Severity.Critical, FindingCategory.SQLi, "SQL Injection found",
            impact: 10.0, confidence: 0.95, isConfirmed: true));

        // Assert
        scan.HasCriticalFindings().Should().BeTrue();
    }

    private static Scan CreateScan() =>
        Scan.Create(
            ScanTarget.Create("example.com").Value!,
            ScanConfiguration.CreateDefault());
}

public sealed class ScanTargetTests
{
    [Theory]
    [InlineData("example.com")]
    [InlineData("sub.example.com")]
    [InlineData("https://example.com")]
    [InlineData("http://example.com/path?q=1")]
    public void Create_WithValidDomain_ShouldSucceed(string input)
    {
        var result = ScanTarget.Create(input);
        result.IsSuccess.Should().BeTrue();
        result.Value!.IsDomain.Should().BeTrue();
    }

    [Theory]
    [InlineData("192.168.1.1")]
    [InlineData("10.0.0.1")]
    public void Create_WithValidIp_ShouldSucceed(string input)
    {
        var result = ScanTarget.Create(input);
        result.IsSuccess.Should().BeTrue();
        result.Value!.IsIpAddress.Should().BeTrue();
    }

    [Theory]
    [InlineData("10.0.0.0/24")]
    [InlineData("192.168.0.0/16")]
    public void Create_WithValidCidr_ShouldSucceed(string input)
    {
        var result = ScanTarget.Create(input);
        result.IsSuccess.Should().BeTrue();
        result.Value!.IsCidr.Should().BeTrue();
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a valid target!!")]
    public void Create_WithInvalidInput_ShouldFail(string input)
    {
        var result = ScanTarget.Create(input);
        result.IsFailure.Should().BeTrue();
    }
}

public sealed class VulnerabilityScoreTests
{
    [Fact]
    public void Calculate_SqliConfirmed_ShouldBeCritical()
    {
        // score = (10 × 0.6) + (0.9 × 10 × 0.4) = 6 + 3.6 = 9.6
        var score = VulnerabilityScore.Calculate(10.0, 0.90);
        score.FinalScore.Should().BeApproximately(9.6, 0.1);
        score.DerivedSeverity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Calculate_MissingHeader_ShouldBeAtLeastMedium()
    {
        // score = (3 × 0.6) + (0.99 × 10 × 0.4) = 1.8 + 3.96 = 5.76
        var score = VulnerabilityScore.Calculate(3.0, 0.99);
        score.FinalScore.Should().BeGreaterThan(5.0);
        score.DerivedSeverity.IsAtLeast(Severity.Medium).Should().BeTrue();
    }

    [Fact]
    public void WithContextMultiplier_LoginSqli_ShouldEscalateToCritical()
    {
        var score = VulnerabilityScore.Calculate(8.0, 0.90);
        var boosted = score.WithContextMultiplier(1.50, "SQLi on auth endpoint");
        boosted.FinalScore.Should().BeGreaterThanOrEqualTo(9.0);
        boosted.DerivedSeverity.Should().Be(Severity.Critical);
    }
}
