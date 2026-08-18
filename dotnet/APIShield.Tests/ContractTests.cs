using System.Text.Json;
using APIShield.Client;

namespace APIShield.Tests;

public sealed class ContractTests
{
    [Fact]
    public void RepresentativeFastApiFixture_DeserializesIntoCSharpModels()
    {
        var json = File.ReadAllText(Path.Combine(
            AppContext.BaseDirectory,
            "Fixtures",
            "passive-scan-report.json"));

        var report = JsonSerializer.Deserialize<ScanReport>(
            json,
            ApiShieldJson.SerializerOptions);

        Assert.NotNull(report);
        Assert.Equal("APIShield Agent", report.Project);
        Assert.Equal(1, report.Summary.TotalFindings);
        Assert.Equal("missing-referrer-policy", report.RemediationReport[0].Category);
        Assert.Equal("needs-review", report.Findings[0].Status);
    }
}
