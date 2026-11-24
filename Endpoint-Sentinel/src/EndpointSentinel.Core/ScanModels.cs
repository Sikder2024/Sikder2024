namespace EndpointSentinel.Core;

public sealed record ScanFinding(string FilePath, string Rule, string Sha256, DateTimeOffset DetectedAt);

public sealed record ScanIssue(string Path, string Message);

public sealed record ScanProgress(string CurrentPath, int FilesProcessed);

public sealed record ScanResult(
    string RootPath,
    DateTimeOffset StartedAt,
    DateTimeOffset CompletedAt,
    int FilesProcessed,
    IReadOnlyList<ScanFinding> Findings,
    IReadOnlyList<ScanIssue> Issues)
{
    public bool IsComplete => Issues.Count == 0;
}
