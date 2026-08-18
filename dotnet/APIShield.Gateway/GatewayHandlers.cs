using APIShield.Client;
using Microsoft.AspNetCore.Http.HttpResults;
using System.Text.Json.Serialization;

namespace APIShield.Gateway;

public static class GatewayHandlers
{
    public static async Task<IResult> HealthAsync(
        IApiShieldClient client,
        ILogger<GatewayLog> logger,
        CancellationToken cancellationToken)
    {
        try
        {
            var backend = await client.GetHealthAsync(cancellationToken);
            return TypedResults.Ok(new GatewayHealthResponse(
                "healthy",
                backend.Status.Equals("ok", StringComparison.OrdinalIgnoreCase) ? "healthy" : "degraded"));
        }
        catch (ApiShieldException exception)
        {
            logger.LogWarning(exception, "APIShield backend health check failed.");
            return TypedResults.Json(
                new GatewayHealthResponse("healthy", "unavailable"),
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }
    }

    public static async Task<IResult> AnalyzeUrlAsync(
        PassiveDiscoveryRequest request,
        IApiShieldClient client,
        ILogger<GatewayLog> logger,
        CancellationToken cancellationToken)
    {
        try
        {
            return TypedResults.Ok(await client.AnalyzeUrlAsync(request, cancellationToken));
        }
        catch (ApiShieldApiException exception)
        {
            logger.LogWarning(
                "APIShield backend rejected a passive analysis request with status {StatusCode}.",
                (int)exception.StatusCode);
            var backendStatus = (int)exception.StatusCode;
            var gatewayStatus = backendStatus is >= 400 and < 500
                ? backendStatus
                : StatusCodes.Status502BadGateway;
            return SafeProblem(gatewayStatus, "APIShield backend rejected the analysis request.");
        }
        catch (ApiShieldTimeoutException exception)
        {
            logger.LogWarning(exception, "APIShield backend passive analysis timed out.");
            return SafeProblem(StatusCodes.Status504GatewayTimeout, "APIShield backend timed out.");
        }
        catch (ApiShieldConnectionException exception)
        {
            logger.LogWarning(exception, "APIShield backend was unavailable for passive analysis.");
            return SafeProblem(StatusCodes.Status503ServiceUnavailable, "APIShield backend is unavailable.");
        }
        catch (ApiShieldSerializationException exception)
        {
            logger.LogWarning(exception, "APIShield backend returned an invalid passive analysis response.");
            return SafeProblem(StatusCodes.Status502BadGateway, "APIShield backend returned an invalid response.");
        }
    }

    private static ProblemHttpResult SafeProblem(int statusCode, string detail) =>
        TypedResults.Problem(
            statusCode: statusCode,
            title: "APIShield gateway request failed",
            detail: detail);
}

public sealed record GatewayHealthResponse(
    [property: JsonPropertyName("gateway")] string Gateway,
    [property: JsonPropertyName("apiShieldBackend")] string ApiShieldBackend);

public sealed class GatewayLog;
