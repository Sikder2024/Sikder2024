using EndpointSentinel.Core;

var temporaryRoot = Path.Combine(Path.GetTempPath(), "EndpointSentinel.Tests", Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temporaryRoot);
try
{
    var markerPath = Path.Combine(temporaryRoot, "harmless-marker.txt");
    var ordinaryPath = Path.Combine(temporaryRoot, "ordinary.txt");
    await File.WriteAllTextAsync(markerPath, $"This is a harmless scanner test fixture: {LocalScanner.HarmlessTestMarker}");
    await File.WriteAllTextAsync(ordinaryPath, "An ordinary local test fixture.");

    var scanner = new LocalScanner();
    var result = await scanner.ScanDirectoryAsync(temporaryRoot);
    Assert(result.FilesProcessed == 2, $"Expected 2 scanned files; got {result.FilesProcessed}.");
    Assert(result.Findings.Count == 1, $"Expected one marker finding; got {result.Findings.Count}.");
    Assert(result.Findings[0].FilePath == markerPath, "The marker finding must reference the harmless marker fixture.");
    Assert(result.Findings[0].Sha256.Length == 64, "A marker finding should have a SHA-256 digest.");
    Assert(result.Issues.Count == 0, "The fixture scan should not have scan issues.");
    Assert(result.IsComplete, "The fixture scan should be complete.");

    var missing = await scanner.ScanDirectoryAsync(Path.Combine(temporaryRoot, "missing-directory"));
    Assert(!missing.IsComplete && missing.Issues.Count > 0, "An inaccessible/missing directory must be reported as incomplete.");

    var missingFile = await scanner.ScanFileAsync(Path.Combine(temporaryRoot, "missing-file.txt"));
    Assert(!missingFile.IsComplete && missingFile.Issues.Count == 1, "A missing file must be reported as incomplete.");

    var oversizedPath = Path.Combine(temporaryRoot, "oversized.txt");
    await using (var oversized = new FileStream(oversizedPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
    {
        oversized.SetLength(LocalScanner.MaximumFileBytes + 1);
    }
    var oversizedResult = await scanner.ScanFileAsync(oversizedPath);
    Assert(!oversizedResult.IsComplete && oversizedResult.Issues.Count == 1, "A file over the inspection limit must be inconclusive.");

    var storePath = Path.Combine(temporaryRoot, "history", "history.json");
    var store = new LocalHistoryStore(storePath);
    await store.SaveAsync(result);
    var history = await store.ReadAsync();
    Assert(history.Count == 1 && history[0].Findings.Count == 1, "Local history round trip failed.");
    Console.WriteLine("PASS: harmless marker, ordinary file, missing path/file issues, oversized-file limit, and local history.");
}
finally
{
    try { Directory.Delete(temporaryRoot, recursive: true); }
    catch (IOException) { Console.Error.WriteLine($"Test cleanup could not remove temporary data: {temporaryRoot}"); }
    catch (UnauthorizedAccessException) { Console.Error.WriteLine($"Test cleanup could not remove temporary data: {temporaryRoot}"); }
}

static void Assert(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}
