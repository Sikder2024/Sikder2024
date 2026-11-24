using System.Security.Cryptography;
using System.Text;

namespace EndpointSentinel.Core;

/// <summary>
/// Bounded, read-only scanner. It never executes, modifies, or removes scanned files.
/// </summary>
public sealed class LocalScanner
{
    public const string HarmlessTestMarker = "ENDPOINT_SENTINEL_TEST_MARKER";
    public const int MaximumFilesPerScan = 10_000;
    public const int MaximumDirectoriesPerScan = 10_000;
    public const int MaximumEntriesPerScan = 20_000;
    public const long MaximumFileBytes = 32 * 1024 * 1024;
    private const int BufferSize = 64 * 1024;
    private static readonly byte[] MarkerBytes = Encoding.ASCII.GetBytes(HarmlessTestMarker);

    public async Task<ScanResult> ScanDirectoryAsync(
        string rootPath,
        IProgress<ScanProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootPath);
        var started = DateTimeOffset.UtcNow;
        var findings = new List<ScanFinding>();
        var issues = new List<ScanIssue>();
        var filesProcessed = 0;
        string fullRoot;

        try
        {
            fullRoot = Path.GetFullPath(rootPath);
            if (!Directory.Exists(fullRoot))
            {
                issues.Add(new ScanIssue(fullRoot, "The selected directory does not exist or is inaccessible."));
                return Finish(fullRoot, started, filesProcessed, findings, issues);
            }
            if ((File.GetAttributes(fullRoot) & FileAttributes.ReparsePoint) != 0)
            {
                issues.Add(new ScanIssue(fullRoot, "The selected directory is a reparse point; it was not followed."));
                return Finish(fullRoot, started, filesProcessed, findings, issues);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            issues.Add(new ScanIssue(rootPath, $"Unable to access the selected directory: {ex.Message}"));
            return Finish(rootPath, started, filesProcessed, findings, issues);
        }

        var pendingDirectories = new Stack<string>();
        pendingDirectories.Push(fullRoot);
        var directoriesVisited = 0;
        var entriesVisited = 0;
        while (pendingDirectories.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (directoriesVisited >= MaximumDirectoriesPerScan)
            {
                issues.Add(new ScanIssue(fullRoot, $"Scan stopped at the safety limit of {MaximumDirectoriesPerScan:N0} directories."));
                break;
            }
            var directory = pendingDirectories.Pop();
            directoriesVisited++;
            var stopAtEntryLimit = false;
            try
            {
                foreach (var entry in Directory.EnumerateFileSystemEntries(directory))
                {
                    if (++entriesVisited > MaximumEntriesPerScan)
                    {
                        issues.Add(new ScanIssue(directory, $"Scan stopped at the safety limit of {MaximumEntriesPerScan:N0} directory entries."));
                        pendingDirectories.Clear();
                        stopAtEntryLimit = true;
                        break;
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    FileAttributes attributes;
                    try
                    {
                        attributes = File.GetAttributes(entry);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        issues.Add(new ScanIssue(entry, $"Unable to inspect entry: {ex.Message}"));
                        continue;
                    }

                    if ((attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        issues.Add(new ScanIssue(entry, "Reparse point skipped by default; its target was not inspected."));
                        continue;
                    }

                    if ((attributes & FileAttributes.Directory) != 0)
                    {
                        if (directoriesVisited + pendingDirectories.Count >= MaximumDirectoriesPerScan)
                        {
                            issues.Add(new ScanIssue(entry, $"Directory was not scanned because the safety limit of {MaximumDirectoriesPerScan:N0} directories was reached."));
                            continue;
                        }
                        pendingDirectories.Push(entry);
                        continue;
                    }

                    if (filesProcessed >= MaximumFilesPerScan)
                    {
                        issues.Add(new ScanIssue(fullRoot, $"Scan stopped at the safety limit of {MaximumFilesPerScan:N0} files."));
                        pendingDirectories.Clear();
                        stopAtEntryLimit = true;
                        break;
                    }

                    cancellationToken.ThrowIfCancellationRequested();
                    var (finding, issue) = await InspectFileAsync(entry, cancellationToken).ConfigureAwait(false);
                    filesProcessed++;
                    if (finding is not null)
                        findings.Add(finding);
                    if (issue is not null)
                        issues.Add(issue);
                    progress?.Report(new ScanProgress(entry, filesProcessed));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                issues.Add(new ScanIssue(directory, $"Unable to enumerate directory: {ex.Message}"));
            }
            if (stopAtEntryLimit)
                break;
        }

        return Finish(fullRoot, started, filesProcessed, findings, issues);
    }

    public async Task<ScanResult> ScanFileAsync(string filePath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var started = DateTimeOffset.UtcNow;
        var findings = new List<ScanFinding>();
        var issues = new List<ScanIssue>();
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(filePath);
            var attributes = File.GetAttributes(fullPath);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
            {
                issues.Add(new ScanIssue(fullPath, "The path is a directory or reparse point; it was not inspected."));
                return Finish(fullPath, started, 0, findings, issues);
            }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            issues.Add(new ScanIssue(filePath, $"Unable to access file; not classified: {ex.Message}"));
            return Finish(filePath, started, 0, findings, issues);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var (finding, issue) = await InspectFileAsync(fullPath, cancellationToken).ConfigureAwait(false);
        if (finding is not null)
            findings.Add(finding);
        if (issue is not null)
            issues.Add(issue);
        return Finish(fullPath, started, 1, findings, issues);
    }

    private static async Task<(ScanFinding? Finding, ScanIssue? Issue)> InspectFileAsync(
        string path, CancellationToken cancellationToken)
    {
        try
        {
            var before = new FileInfo(path);
            var originalLength = before.Length;
            var originalWriteTime = before.LastWriteTimeUtc;
            if (originalLength > MaximumFileBytes)
                return (null, new ScanIssue(path, $"File exceeds the {MaximumFileBytes / (1024 * 1024)} MiB inspection limit; not classified."));

            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, BufferSize, useAsync: true);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[BufferSize];
            var carry = Array.Empty<byte>();
            var markerFound = false;
            long totalRead = 0;
            int read;
            while ((read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false)) > 0)
            {
                totalRead += read;
                if (totalRead > MaximumFileBytes)
                    return (null, new ScanIssue(path, $"File grew beyond the {MaximumFileBytes / (1024 * 1024)} MiB inspection limit; not classified."));
                hash.AppendData(buffer, 0, read);

                if (!markerFound)
                {
                    var search = new byte[carry.Length + read];
                    Buffer.BlockCopy(carry, 0, search, 0, carry.Length);
                    Buffer.BlockCopy(buffer, 0, search, carry.Length, read);
                    markerFound = search.AsSpan().IndexOf(MarkerBytes) >= 0;
                    var carryLength = Math.Min(MarkerBytes.Length - 1, search.Length);
                    carry = search.AsSpan(search.Length - carryLength, carryLength).ToArray();
                }
            }

            var after = new FileInfo(path);
            if (totalRead != originalLength || after.Length != originalLength || after.LastWriteTimeUtc != originalWriteTime)
                return (null, new ScanIssue(path, "File changed while being scanned; result is inconclusive."));

            if (!markerFound)
                return (null, null);

            var digest = Convert.ToHexString(hash.GetHashAndReset());
            return (new ScanFinding(path, "Harmless test marker detected (EndpointSentinel.TestMarker.v1)", digest, DateTimeOffset.UtcNow), null);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return (null, new ScanIssue(path, $"Unable to inspect file; not classified: {ex.Message}"));
        }
    }

    private static ScanResult Finish(
        string root,
        DateTimeOffset started,
        int filesProcessed,
        IReadOnlyList<ScanFinding> findings,
        IReadOnlyList<ScanIssue> issues) =>
        new(root, started, DateTimeOffset.UtcNow, filesProcessed, findings, issues);
}
