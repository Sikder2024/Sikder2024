using System.Diagnostics;
using System.Text.Json;

namespace EndpointSentinel.Core;

public sealed class WindowsDefenderStatus
{
    public string? AMRunningMode { get; init; }
    public bool? AMServiceEnabled { get; init; }
    public bool? AntivirusEnabled { get; init; }
    public bool? AntispywareEnabled { get; init; }
    public bool? RealTimeProtectionEnabled { get; init; }
    public bool? BehaviorMonitorEnabled { get; init; }
    public bool? OnAccessProtectionEnabled { get; init; }
    public bool? IoavProtectionEnabled { get; init; }
    public int? AntivirusSignatureAge { get; init; }
    public string? AntivirusSignatureLastUpdated { get; init; }
    public string? AntivirusSignatureVersion { get; init; }
    public int? QuickScanAge { get; init; }
    public int? FullScanAge { get; init; }
}

public sealed class WindowsDefenderStatusProvider
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(15);

    public async Task<WindowsDefenderStatus> ReadAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Defender status is available only on Windows.");

        var executable = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(executable))
            throw new FileNotFoundException("Windows PowerShell was not found; Defender status could not be queried.", executable);

        const string script = "$ErrorActionPreference = 'Stop'; " +
            "$s = Get-MpComputerStatus; " +
            "$signatureUpdated = if ($s.AntivirusSignatureLastUpdated) { $s.AntivirusSignatureLastUpdated.ToString('o') } else { $null }; " +
            "[ordered]@{ " +
            "AMRunningMode = $s.AMRunningMode; " +
            "AMServiceEnabled = $s.AMServiceEnabled; " +
            "AntivirusEnabled = $s.AntivirusEnabled; " +
            "AntispywareEnabled = $s.AntispywareEnabled; " +
            "RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled; " +
            "BehaviorMonitorEnabled = $s.BehaviorMonitorEnabled; " +
            "OnAccessProtectionEnabled = $s.OnAccessProtectionEnabled; " +
            "IoavProtectionEnabled = $s.IoavProtectionEnabled; " +
            "AntivirusSignatureAge = $s.AntivirusSignatureAge; " +
            "AntivirusSignatureLastUpdated = $signatureUpdated; " +
            "AntivirusSignatureVersion = $s.AntivirusSignatureVersion; " +
            "QuickScanAge = $s.QuickScanAge; " +
            "FullScanAge = $s.FullScanAge " +
            "} | ConvertTo-Json -Compress";

        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        using var process = new Process { StartInfo = startInfo };
        cancellationToken.ThrowIfCancellationRequested();
        if (!process.Start())
            throw new InvalidOperationException("Windows PowerShell could not be started.");

        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(QueryTimeout);
        try
        {
            await process.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
            if (cancellationToken.IsCancellationRequested)
                throw;
            throw new TimeoutException($"Defender status query exceeded {QueryTimeout.TotalSeconds:N0} seconds.");
        }

        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);
        if (process.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(error) ? output.Trim() : error.Trim();
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(detail)
                    ? $"Defender status query failed with exit code {process.ExitCode}."
                    : $"Defender status query failed: {detail}");
        }

        try
        {
            return JsonSerializer.Deserialize<WindowsDefenderStatus>(
                    output,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? throw new JsonException("Defender returned an empty status response.");
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException("Defender returned status data that could not be interpreted.", ex);
        }
    }
}
