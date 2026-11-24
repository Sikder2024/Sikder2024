using System.Text.Json;

namespace EndpointSentinel.Core;

/// <summary>Stores scan summaries in the current user's local application-data directory.</summary>
public sealed class LocalHistoryStore
{
    private const int HistoryLimit = 50;
    private readonly string _filePath;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public LocalHistoryStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "EndpointSentinel", "scan-history.json");
    }

    public async Task<IReadOnlyList<ScanResult>> ReadAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(_filePath))
                return Array.Empty<ScanResult>();
            await using var stream = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return await JsonSerializer.DeserializeAsync<List<ScanResult>>(stream, JsonOptions, cancellationToken).ConfigureAwait(false)
                ?? new List<ScanResult>();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task SaveAsync(ScanResult result, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_filePath) ?? throw new InvalidOperationException("History path has no parent directory.");
            Directory.CreateDirectory(directory);
            var records = new List<ScanResult>();
            if (File.Exists(_filePath))
            {
                await using var existing = new FileStream(_filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                records = await JsonSerializer.DeserializeAsync<List<ScanResult>>(existing, JsonOptions, cancellationToken).ConfigureAwait(false)
                    ?? new List<ScanResult>();
            }
            records.Insert(0, result);
            if (records.Count > HistoryLimit)
                records.RemoveRange(HistoryLimit, records.Count - HistoryLimit);

            var temporary = _filePath + ".tmp";
            await using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
                await JsonSerializer.SerializeAsync(stream, records, JsonOptions, cancellationToken).ConfigureAwait(false);
            File.Move(temporary, _filePath, overwrite: true);
        }
        finally
        {
            _gate.Release();
        }
    }
}
