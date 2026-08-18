namespace APIShield.Client;

public interface IApiShieldClient
{
    Task<HealthResponse> GetHealthAsync(CancellationToken cancellationToken = default);

    Task<ScanReport> AnalyzeUrlAsync(
        PassiveDiscoveryRequest request,
        CancellationToken cancellationToken = default);
}
