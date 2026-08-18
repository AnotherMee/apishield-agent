using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using APIShield.Client;
using APIShield.Gateway;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;

namespace APIShield.Tests;

public sealed class GatewayTests
{
    [Fact]
    public async Task Health_ReturnsGatewayAndBackendStatus()
    {
        await using var factory = CreateFactory(new FakeApiShieldClient());
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health");
        var health = await response.Content.ReadFromJsonAsync<GatewayHealthResponse>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("healthy", health!.Gateway);
        Assert.Equal("healthy", health.ApiShieldBackend);
    }

    [Fact]
    public async Task Health_ReturnsUsefulStatusWhenBackendIsUnavailable()
    {
        var fake = new FakeApiShieldClient
        {
            HealthException = new ApiShieldConnectionException(
                "backend unavailable",
                new HttpRequestException("connection refused")),
        };
        await using var factory = CreateFactory(fake);
        using var client = factory.CreateClient();

        var response = await client.GetAsync("/health");
        var health = await response.Content.ReadFromJsonAsync<GatewayHealthResponse>();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("healthy", health!.Gateway);
        Assert.Equal("unavailable", health.ApiShieldBackend);
    }

    [Fact]
    public async Task AnalyzeUrl_ProxiesSuccessfulTypedRequestAndResponse()
    {
        var fake = new FakeApiShieldClient();
        await using var factory = CreateFactory(fake);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/security/analyze-url",
            new PassiveDiscoveryRequest(new Uri("https://example.test/"), true),
            ApiShieldJson.SerializerOptions);
        var report = await response.Content.ReadFromJsonAsync<ScanReport>(
            ApiShieldJson.SerializerOptions);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("https://example.test/", fake.LastRequest!.Target.ToString());
        Assert.True(fake.LastRequest.UseAi);
        Assert.Single(report!.Findings);
    }

    [Fact]
    public async Task AnalyzeUrl_MapsBackendFailureWithoutLeakingInternalDetails()
    {
        var fake = new FakeApiShieldClient
        {
            AnalyzeException = new ApiShieldConnectionException(
                "sensitive internal diagnostic",
                new HttpRequestException("connection refused")),
        };
        await using var factory = CreateFactory(fake);
        using var client = factory.CreateClient();

        var response = await client.PostAsJsonAsync(
            "/api/security/analyze-url",
            new PassiveDiscoveryRequest(new Uri("https://example.test/")),
            ApiShieldJson.SerializerOptions);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Contains("APIShield backend is unavailable", content);
        Assert.DoesNotContain("sensitive internal diagnostic", content);
    }

    private static WebApplicationFactory<Program> CreateFactory(IApiShieldClient client) =>
        new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.ConfigureLogging(logging => logging.ClearProviders());
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IApiShieldClient>();
                services.AddSingleton(client);
            });
        });

    private sealed class FakeApiShieldClient : IApiShieldClient
    {
        public PassiveDiscoveryRequest? LastRequest { get; private set; }

        public ApiShieldException? AnalyzeException { get; init; }

        public ApiShieldException? HealthException { get; init; }

        public Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken = default)
        {
            if (HealthException is not null)
            {
                throw HealthException;
            }

            return Task.FromResult(new HealthResponse("ok"));
        }

        public Task<ScanReport> AnalyzeUrlAsync(
            PassiveDiscoveryRequest request,
            CancellationToken cancellationToken = default)
        {
            LastRequest = request;
            if (AnalyzeException is not null)
            {
                throw AnalyzeException;
            }

            var json = File.ReadAllText(Path.Combine(
                AppContext.BaseDirectory,
                "Fixtures",
                "passive-scan-report.json"));
            return Task.FromResult(JsonSerializer.Deserialize<ScanReport>(
                json,
                ApiShieldJson.SerializerOptions)!);
        }
    }
}
