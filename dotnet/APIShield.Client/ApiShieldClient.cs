using System.Net.Http.Json;
using System.Text.Json;

namespace APIShield.Client;

public sealed class ApiShieldClient : IApiShieldClient
{
    private readonly HttpClient _httpClient;

    public ApiShieldClient(HttpClient httpClient)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
    }

    public Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken = default) =>
        SendAsync<HealthResponse>(HttpMethod.Get, "health", null, cancellationToken);

    public Task<ScanReport> AnalyzeUrlAsync(
        PassiveDiscoveryRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.Target.IsAbsoluteUri || request.Target.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("Target must be an absolute HTTP or HTTPS URI.", nameof(request));
        }

        return SendAsync<ScanReport>(HttpMethod.Post, "discovery/passive", request, cancellationToken);
    }

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        object? body,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body, options: ApiShieldJson.SerializerOptions);
        }

        try
        {
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                var detail = await ReadErrorDetailAsync(response, cancellationToken);
                throw new ApiShieldApiException(
                    response.StatusCode,
                    $"APIShield backend returned {(int)response.StatusCode}: {detail}");
            }

            try
            {
                var result = await response.Content.ReadFromJsonAsync<T>(
                    ApiShieldJson.SerializerOptions,
                    cancellationToken);
                return result ?? throw new JsonException("The response body was empty.");
            }
            catch (JsonException exception)
            {
                throw new ApiShieldSerializationException(
                    "APIShield backend returned an invalid response payload.",
                    exception);
            }
        }
        catch (OperationCanceledException exception) when (!cancellationToken.IsCancellationRequested)
        {
            throw new ApiShieldTimeoutException(
                "The APIShield backend request timed out.",
                exception);
        }
        catch (HttpRequestException exception)
        {
            throw new ApiShieldConnectionException(
                "The APIShield backend could not be reached.",
                exception);
        }
    }

    private static async Task<string> ReadErrorDetailAsync(
        HttpResponseMessage response,
        CancellationToken cancellationToken)
    {
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (content.Length > 2_000)
        {
            content = content[..2_000];
        }

        try
        {
            using var document = JsonDocument.Parse(content);
            if (document.RootElement.TryGetProperty("detail", out var detail))
            {
                return detail.ValueKind == JsonValueKind.String
                    ? detail.GetString() ?? "Request failed."
                    : detail.GetRawText();
            }
        }
        catch (JsonException)
        {
            // Use the bounded plain-text response below.
        }

        return string.IsNullOrWhiteSpace(content) ? "Request failed." : content;
    }
}
