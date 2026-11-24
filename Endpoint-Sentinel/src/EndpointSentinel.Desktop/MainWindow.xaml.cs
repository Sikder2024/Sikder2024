using System.Diagnostics;
using System.IO;
using System.Text;
using System.Windows;
using EndpointSentinel.Core;

namespace EndpointSentinel.Desktop;

public partial class MainWindow : Window
{
    private readonly LocalScanner _scanner = new();
    private readonly LocalHistoryStore _history = new();
    private readonly WindowsDefenderStatusProvider _defenderStatusProvider = new();
    private CancellationTokenSource? _scanCancellation;

    public MainWindow()
    {
        InitializeComponent();
        _ = LoadHistoryAsync();
    }

    private void BrowseFolder_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new System.Windows.Forms.FolderBrowserDialog
        {
            Description = "Choose a directory for the harmless test-marker check",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };

        if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
        {
            PathBox.Text = dialog.SelectedPath;
            PathBox.CaretIndex = PathBox.Text.Length;
        }
    }

    private async void RefreshDefenderStatus_Click(object sender, RoutedEventArgs e)
    {
        RefreshDefenderButton.IsEnabled = false;
        DefenderStatusText.Text = "Querying read-only Defender status...";
        try
        {
            var status = await _defenderStatusProvider.ReadAsync();
            DefenderStatusText.Text = FormatDefenderStatus(status);
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException or IOException
            or UnauthorizedAccessException or PlatformNotSupportedException
            or System.ComponentModel.Win32Exception or InvalidDataException)
        {
            DefenderStatusText.Text = $"Defender status is UNKNOWN; this is not evidence that protection is healthy.{Environment.NewLine}{ex.Message}";
        }
        finally
        {
            RefreshDefenderButton.IsEnabled = true;
        }
    }

    private void OpenWindowsSecurity_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "ms-settings:windowsdefender",
                UseShellExecute = true
            });
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            DefenderStatusText.Text = $"Windows Security could not be opened: {ex.Message}";
        }
    }

    private static string FormatDefenderStatus(WindowsDefenderStatus status)
    {
        static string Enabled(bool? value) => value switch
        {
            true => "Enabled",
            false => "Disabled",
            null => "Unknown"
        };

        static string Age(int? days) => days switch
        {
            null => "Unknown",
            < 0 => "Never reported",
            0 => "Today",
            1 => "1 day ago",
            _ => $"{days} days ago"
        };

        return string.Join(Environment.NewLine,
            $"Antivirus: {Enabled(status.AntivirusEnabled)}",
            $"Antispyware: {Enabled(status.AntispywareEnabled)}",
            $"Antimalware service: {Enabled(status.AMServiceEnabled)}",
            $"Real-time protection: {Enabled(status.RealTimeProtectionEnabled)}",
            $"Behavior monitoring: {Enabled(status.BehaviorMonitorEnabled)}",
            $"On-access protection: {Enabled(status.OnAccessProtectionEnabled)}",
            $"Downloaded-file/attachment scanning: {Enabled(status.IoavProtectionEnabled)}",
            $"Security intelligence: {status.AntivirusSignatureVersion ?? "Unknown"}",
            $"Intelligence age: {Age(status.AntivirusSignatureAge)}",
            $"Last intelligence update: {status.AntivirusSignatureLastUpdated ?? "Unknown"}",
            $"Last quick scan: {Age(status.QuickScanAge)}",
            $"Last full scan: {Age(status.FullScanAge)}",
            $"Reported Defender mode: {status.AMRunningMode ?? "Unknown"}",
            "Note: these are Windows-reported status values, not an independent security assessment.");
    }

    private async void ScanButton_Click(object sender, RoutedEventArgs e)
    {
        var path = PathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            StatusText.Text = "Choose or enter a directory path before scanning.";
            PathBox.Focus();
            return;
        }

        var cancellation = new CancellationTokenSource();
        _scanCancellation = cancellation;
        ScanButton.IsEnabled = false;
        CancelButton.IsEnabled = true;
        ScanProgressBar.IsIndeterminate = true;
        ReportBox.Clear();
        StatusText.Text = "Scanning. Accessibility errors and changing files will be reported as inconclusive, not clean.";
        var progress = new Progress<ScanProgress>(value =>
        {
            StatusText.Text = $"Scanning {value.FilesProcessed:N0} file(s): {value.CurrentPath}";
        });

        try
        {
            var result = await _scanner.ScanDirectoryAsync(path, progress, cancellation.Token);
            await _history.SaveAsync(result);
            ShowResult(result);
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled. Partial results are not recorded as a clean scan.";
            ReportBox.Text = "Scan was cancelled; no clean result is asserted.";
        }
        catch (Exception ex)
        {
            StatusText.Text = "Scan could not be completed. This is not a clean result.";
            ReportBox.Text = $"Unexpected scan or local-history error:{Environment.NewLine}{ex.Message}";
        }
        finally
        {
            ScanProgressBar.IsIndeterminate = false;
            ScanProgressBar.Value = 0;
            ScanButton.IsEnabled = true;
            CancelButton.IsEnabled = false;
            cancellation.Dispose();
            _scanCancellation = null;
        }
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => _scanCancellation?.Cancel();

    private void ShowResult(ScanResult result)
    {
        var report = new StringBuilder();
        report.AppendLine($"Directory: {result.RootPath}");
        report.AppendLine($"Files inspected: {result.FilesProcessed:N0}");
        report.AppendLine($"Findings: {result.Findings.Count:N0}");
        report.AppendLine($"Issues/inconclusive: {result.Issues.Count:N0}");
        report.AppendLine(result.IsComplete
            ? "Status: Complete under the configured limits; no broader protection claim is made."
            : "Status: INCOMPLETE — one or more files/directories could not be fully inspected; do not treat as clean.");

        foreach (var finding in result.Findings)
            report.AppendLine($"FINDING [{finding.Rule}]{Environment.NewLine}  {finding.FilePath}{Environment.NewLine}  SHA-256: {finding.Sha256}");
        foreach (var issue in result.Issues)
            report.AppendLine($"INCONCLUSIVE [{issue.Path}]{Environment.NewLine}  {issue.Message}");

        ReportBox.Text = report.ToString();
        StatusText.Text = result.IsComplete
            ? $"Scan completed: {result.FilesProcessed:N0} files, {result.Findings.Count:N0} finding(s)."
            : $"Scan incomplete: {result.Issues.Count:N0} issue(s); results are not clean.";
    }

    private async Task LoadHistoryAsync()
    {
        try
        {
            var history = await _history.ReadAsync();
            if (history.Count == 0)
            {
                ReportBox.Text = "No local test-marker history yet. Select a directory to check for the documented harmless marker.";
                return;
            }

            var text = new StringBuilder("Recent local test-marker history (newest first):");
            foreach (var item in history.Take(10))
            {
                text.AppendLine();
                text.AppendLine($"{item.CompletedAt.LocalDateTime:g} | {item.RootPath} | files {item.FilesProcessed} | findings {item.Findings.Count} | issues {item.Issues.Count}");
            }
            ReportBox.Text = text.ToString();
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Unable to read local scan history; history is unavailable: {ex.Message}";
            ReportBox.Text = "Local history could not be read. The app will not represent unavailable history as empty or clean.";
        }
    }
}
