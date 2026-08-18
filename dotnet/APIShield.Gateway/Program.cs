using APIShield.Client;
using APIShield.Gateway;
using System.Text.Json;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

var backendUrl = builder.Configuration["APISHIELD_BACKEND_URL"]
    ?? builder.Configuration["ApiShield:BackendUrl"]
    ?? "http://127.0.0.1:8000/";

if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backendUri)
    || backendUri.Scheme is not ("http" or "https"))
{
    throw new InvalidOperationException(
        "APISHIELD_BACKEND_URL must be an absolute HTTP or HTTPS URL.");
}

builder.Services.AddHttpClient<IApiShieldClient, ApiShieldClient>(client =>
{
    client.BaseAddress = new Uri(backendUri.ToString().TrimEnd('/') + "/");
    client.Timeout = TimeSpan.FromSeconds(30);
});
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower;
    options.SerializerOptions.Converters.Add(
        new JsonStringEnumConverter(JsonNamingPolicy.SnakeCaseLower));
});

var app = builder.Build();

app.MapGet("/health", GatewayHandlers.HealthAsync);
app.MapPost("/api/security/analyze-url", GatewayHandlers.AnalyzeUrlAsync);

app.Run();

public partial class Program;
