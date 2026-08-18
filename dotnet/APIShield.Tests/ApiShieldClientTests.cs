using System.Net;
using System.Text;
using System.Text.Json;
using APIShield.Client;

namespace APIShield.Tests;

public sealed class ApiShieldClientTests
{
    [Fact]
    public async Task GetHealthAsync_ReturnsSuccessfulResponse()
    {
        var client = CreateClient((request, _) =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("/health", request.RequestUri!.AbsolutePath);
            return JsonResponse("{\"status\":\"ok\"}");
        });

        var response = await client.GetHealthAsync();

        Assert.Equal("ok", response.Status);
    }

    [Fact]
    public async Task AnalyzeUrlAsync_SerializesTheFastApiRequestContract()
    {
        string? body = null;
        var client = CreateClient(async (request, cancellationToken) =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal("/discovery/passive", request.RequestUri!.AbsolutePath);
            body = await request.Content!.ReadAsStringAsync(cancellationToken);
            return await JsonResponseAsync(FixtureJson());
        });

        await client.AnalyzeUrlAsync(new PassiveDiscoveryRequest(
            new Uri("https://example.test/api"),
            UseAi: true));

        using var document = JsonDocument.Parse(body!);
        Assert.Equal("https://example.test/api", document.RootElement.GetProperty("target").GetString());
        Assert.True(document.RootElement.GetProperty("use_ai").GetBoolean());
    }

    [Fact]
    public async Task AnalyzeUrlAsync_DeserializesTheFastApiResponseContract()
    {
        var client = CreateClient((_, _) => JsonResponse(FixtureJson()));

        var report = await client.AnalyzeUrlAsync(
            new PassiveDiscoveryRequest(new Uri("https://example.test/")));

        Assert.Equal("passive", report.ScanMode);
        Assert.Single(report.Findings);
        Assert.Equal(Severity.Low, report.Findings[0].Severity);
        Assert.Equal("planner.create_plan", report.Timeline[0].ToolInvocations[0].Name);
        Assert.Equal(200, report.Observations[0].Value.GetInt32());
    }

    [Fact]
    public async Task AnalyzeUrlAsync_ThrowsForNonSuccessResponse()
    {
        var client = CreateClient((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.UnprocessableEntity)
        {
            Content = new StringContent("{\"detail\":\"Target is not allowed.\"}", Encoding.UTF8, "application/json"),
        }));

        var exception = await Assert.ThrowsAsync<ApiShieldApiException>(() =>
            client.AnalyzeUrlAsync(new PassiveDiscoveryRequest(new Uri("https://example.test/"))));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, exception.StatusCode);
        Assert.Contains("Target is not allowed", exception.Message);
    }

    [Fact]
    public async Task AnalyzeUrlAsync_MapsBackendNetworkFailure()
    {
        var client = CreateClient((_, _) =>
            throw new HttpRequestException("Connection refused."));

        await Assert.ThrowsAsync<ApiShieldConnectionException>(() =>
            client.AnalyzeUrlAsync(new PassiveDiscoveryRequest(new Uri("https://example.test/"))));
    }

    [Fact]
    public async Task AnalyzeUrlAsync_MapsTimeoutWithoutMisclassifyingCancellation()
    {
        var client = CreateClient((_, _) => throw new TaskCanceledException("Timeout."));

        await Assert.ThrowsAsync<ApiShieldTimeoutException>(() =>
            client.AnalyzeUrlAsync(new PassiveDiscoveryRequest(new Uri("https://example.test/"))));
    }

    [Fact]
    public async Task AnalyzeUrlAsync_PropagatesCallerCancellation()
    {
        var client = CreateClient(async (_, cancellationToken) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK);
        });
        using var source = new CancellationTokenSource();
        await source.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.AnalyzeUrlAsync(
                new PassiveDiscoveryRequest(new Uri("https://example.test/")),
                source.Token));
    }

    [Fact]
    public async Task AnalyzeUrlAsync_RejectsInvalidJsonResponse()
    {
        var client = CreateClient((_, _) => JsonResponse("not-json"));

        await Assert.ThrowsAsync<ApiShieldSerializationException>(() =>
            client.AnalyzeUrlAsync(new PassiveDiscoveryRequest(new Uri("https://example.test/"))));
    }

    private static ApiShieldClient CreateClient(
        Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
    {
        var httpClient = new HttpClient(new TestHttpMessageHandler(handler))
        {
            BaseAddress = new Uri("http://apishield.test/"),
        };
        return new ApiShieldClient(httpClient);
    }

    private static Task<HttpResponseMessage> JsonResponse(string content) =>
        Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(content, Encoding.UTF8, "application/json"),
        });

    private static Task<HttpResponseMessage> JsonResponseAsync(string content) => JsonResponse(content);

    private static string FixtureJson() =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "passive-scan-report.json"));
}
