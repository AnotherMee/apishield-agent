using System.Text.Json;

namespace APIShield.Client;

public enum Severity
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

public sealed record PassiveDiscoveryRequest(Uri Target, bool UseAi = false);

public sealed record HealthResponse(string Status);

public sealed record Observation(
    string Category,
    string Source,
    string Url,
    JsonElement Value,
    IReadOnlyDictionary<string, JsonElement> Metadata);

public sealed record Finding(
    string Id,
    string? Source,
    string Method,
    string Endpoint,
    string Category,
    Severity Severity,
    double Confidence,
    IReadOnlyList<string> Evidence,
    IReadOnlyList<string> SourceTools,
    string PotentialImpact,
    string Remediation,
    string Status,
    IReadOnlyDictionary<string, JsonElement>? Correlation);

public sealed record ToolInvocation(string Name, string Status, string Summary);

public sealed record TimelineItem(
    string Node,
    string Step,
    string Detail,
    string Status,
    IReadOnlyList<ToolInvocation> ToolInvocations);

public sealed record ReviewStep(
    Severity Priority,
    string Title,
    string Rationale,
    IReadOnlyList<string> Endpoints);

public sealed record RemediationItem(
    string Category,
    Severity Severity,
    string Recommendation,
    IReadOnlyList<string> AffectedEndpoints,
    int FindingCount);

public sealed record ScanSummary(
    int TotalFindings,
    IReadOnlyDictionary<string, int> BySeverity);

public sealed record ScanReport(
    string Project,
    string ScanMode,
    string? Target,
    string PlanningMode,
    string? PlanningFallbackReason,
    int EndpointCount,
    IReadOnlyList<ReviewStep> Plan,
    IReadOnlyList<TimelineItem> Timeline,
    IReadOnlyList<Observation> Observations,
    ScanSummary Summary,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<RemediationItem> RemediationReport,
    string Disclaimer);
