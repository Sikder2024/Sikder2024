using System.Collections.Concurrent;
using System.Text.Json;
using EndpointSentinel.Core;

namespace EndpointSentinel.Service;

internal sealed record MonitorConfiguration(string[] Paths);

internal static class MonitorHost
{
    private const int MaximumConfiguredPaths = 5;
    private const int MaximumEventsPerMinute = 100;
    private static readonly object LogLock = new();
    private static readonly ConcurrentDictionary<string, DateTimeOffset> LastEventByPath = new(StringComparer.OrdinalIgnoreCase);
    private static readonly SemaphoreSlim ScanSlots = new(4, 4);
    private static readonly LocalScanner Scanner = new();
    private static readonly string DataDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EndpointSentinel");
    private static readonly string ConfigurationPath = Path.Combine(DataDirectory, "monitor-paths.json");
    private static readonly string LogPath = Path.Combine(DataDirectory, "monitor-events.log");

    public static async Task RunAsync(CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(DataDirectory);
        if (!File.Exists(ConfigurationPath))
        {
            WriteLog("Monitoring is disabled: no explicit monitor-paths.json configuration exists.");
            return;
        }

        MonitorConfiguration? configuration;
        try
        {
            await using var stream = File.OpenRead(ConfigurationPath);
            configuration = await JsonSerializer.DeserializeAsync<MonitorConfiguration>(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            WriteLog($"Configuration could not be read; monitoring disabled: {ex.Message}");
            return;
        }

        var paths = ValidatePaths(configuration?.Paths ?? Array.Empty<string>());
        if (paths.Count == 0)
        {
            WriteLog("Monitoring is disabled: no valid, existing, explicitly configured directories were found.");
            return;
        }

        using var stopped = new ManualResetEventSlim(false);
        using var registration = cancellationToken.Register(stopped.Set);
        var watchers = new List<FileSystemWatcher>();
        try
        {
            foreach (var path in paths)
            {
                var watcher = new FileSystemWatcher(path)
                {
                    IncludeSubdirectories = false,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 8192,
                    EnableRaisingEvents = false
                };
                watcher.Created += (_, e) => OnEvent("created", e.FullPath);
                watcher.Changed += (_, e) => OnEvent("changed", e.FullPath);
                watcher.Deleted += (_, e) => OnEvent("deleted", e.FullPath);
                watcher.Renamed += (_, e) => OnEvent("renamed", e.FullPath);
                watcher.Error += (_, e) => WriteLog($"Watcher overflow/error for '{path}'; some file events may have been missed: {e.GetException().Message}");
                watcher.EnableRaisingEvents = true;
                watchers.Add(watcher);
            }

            WriteLog($"Monitoring started for {paths.Count} explicitly configured directory/directories; top-level only.");
            stopped.Wait(cancellationToken);
        }
        finally
        {
            foreach (var watcher in watchers)
                watcher.Dispose();
            WriteLog("Monitoring stopped.");
        }
    }

    private static List<string> ValidatePaths(IEnumerable<string> configuredPaths)
    {
        var result = new List<string>();
        var configuredArray = configuredPaths.ToArray();
        if (configuredArray.Length > MaximumConfiguredPaths)
            WriteLog($"Only the first {MaximumConfiguredPaths} configured paths are considered; remaining entries were ignored.");
        foreach (var configured in configuredArray.Take(MaximumConfiguredPaths))
        {
            if (string.IsNullOrWhiteSpace(configured) || !Path.IsPathFullyQualified(configured))
            {
                WriteLog("Ignored a configured path that was empty or not absolute.");
                continue;
            }

            try
            {
                var fullPath = Path.GetFullPath(configured);
                var root = Path.GetPathRoot(fullPath);
                if (string.Equals(fullPath.TrimEnd(Path.DirectorySeparatorChar), root?.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase))
                {
                    WriteLog($"Ignored drive/share root '{fullPath}'; configure a narrower directory.");
                    continue;
                }
                if (!Directory.Exists(fullPath))
                {
                    WriteLog($"Ignored missing/inaccessible configured directory '{fullPath}'.");
                    continue;
                }
                if ((File.GetAttributes(fullPath) & FileAttributes.ReparsePoint) != 0)
                {
                    WriteLog($"Ignored reparse-point configured directory '{fullPath}'.");
                    continue;
                }
                if (!result.Contains(fullPath, StringComparer.OrdinalIgnoreCase))
                    result.Add(fullPath);
            }
            catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
            {
                WriteLog($"Ignored invalid configured path '{configured}': {ex.Message}");
            }
        }
        return result;
    }

    private static void OnEvent(string eventName, string path)
    {
        var now = DateTimeOffset.UtcNow;
        var minuteAgo = now.AddMinutes(-1);
        if (Interlocked.Read(ref _minuteWindowTicks) < minuteAgo.UtcTicks)
        {
            Interlocked.Exchange(ref _eventsThisMinute, 0);
            Interlocked.Exchange(ref _throttleReported, 0);
            Interlocked.Exchange(ref _minuteWindowTicks, now.UtcTicks);
        }
        if (Interlocked.Increment(ref _eventsThisMinute) > MaximumEventsPerMinute)
        {
            if (Interlocked.CompareExchange(ref _throttleReported, 1, 0) == 0)
                WriteLog($"File events are being rate-limited to {MaximumEventsPerMinute} per minute.");
            return;
        }

        if (LastEventByPath.TryGetValue(path, out var previous) && now - previous < TimeSpan.FromSeconds(2))
            return;
        LastEventByPath[path] = now;

        foreach (var stale in LastEventByPath.Where(pair => now - pair.Value > TimeSpan.FromMinutes(2)).Select(pair => pair.Key).Take(100).ToArray())
            LastEventByPath.TryRemove(stale, out _);

        WriteLog($"File event '{eventName}': {path}");
        if (eventName is "created" or "changed" or "renamed")
            QueueFileInspection(path);
    }

    private static void QueueFileInspection(string path)
    {
        if (!ScanSlots.Wait(0))
        {
            WriteLog($"Inspection skipped because the bounded inspection queue is full: {path}");
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                var result = await Scanner.ScanFileAsync(path).ConfigureAwait(false);
                foreach (var finding in result.Findings)
                    WriteLog($"ALERT [{finding.Rule}] {finding.FilePath} SHA-256={finding.Sha256}");
                foreach (var issue in result.Issues)
                    WriteLog($"INCONCLUSIVE inspection for '{issue.Path}': {issue.Message}");
            }
            catch (Exception ex)
            {
                WriteLog($"INCONCLUSIVE inspection for '{path}' failed: {ex.Message}");
            }
            finally
            {
                ScanSlots.Release();
            }
        });
    }

    private static long _minuteWindowTicks = DateTimeOffset.UtcNow.UtcTicks;
    private static int _eventsThisMinute;
    private static int _throttleReported;

    private static void WriteLog(string message)
    {
        var line = $"{DateTimeOffset.UtcNow:O} {message}";
        lock (LogLock)
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                File.AppendAllText(LogPath, line + Environment.NewLine);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"{line} (log write failed: {ex.Message})");
            }
        }
    }

    public static void WriteFatalError(Exception exception) =>
        WriteLog($"Service stopped after an unhandled error: {exception}");
}
