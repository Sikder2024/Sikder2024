# Endpoint Sentinel

> **Warning:** Endpoint Sentinel is a prototype and does not provide antivirus protection or guarantee device safety. Review the [Terms and Software Disclaimer](TERMS.md) before use; continue using trusted endpoint protection such as Microsoft Defender.

Windows-only, offline-first security companion prototype. This is a local C#/.NET solution with a WPF desktop client, a read-only Microsoft Defender status view, a shared test-marker scanner core, an optional Windows Service monitor, and a dependency-free focused test harness. It is not a replacement for Microsoft Defender, another security product, or professional incident response.

## Requirements and build

- Windows 10/11
- .NET 8 SDK (the .NET runtime alone is not sufficient to build)
- No cloud account, service, network connection, or third-party NuGet package is required by this solution.

From this directory:

```powershell
dotnet build .\EndpointSentinel.sln
dotnet run --project .\tests\EndpointSentinel.Tests\EndpointSentinel.Tests.csproj
dotnet run --project .\src\EndpointSentinel.Desktop\EndpointSentinel.Desktop.csproj
```

The test harness creates and removes its own temporary harmless fixtures. It checks detection of `ENDPOINT_SENTINEL_TEST_MARKER`, a normal file, missing-path and missing-file reporting, the 32 MiB file limit, and local history persistence.

## First vertical slice

1. Launch the WPF app and select **Refresh Defender status** to query Windows-reported protection and signature status. A failed query is shown as unknown, not healthy.
2. Select **Open Windows Security** to review or change protection using Windows' own interface.
3. The separate test-marker check can check a directory for the documented harmless marker. It is not a malware scan or threat-detection engine.
4. Findings, access errors, scan-limit errors, and files that change during inspection are reported distinctly. Any issue makes a check incomplete; incomplete results are never described as clean.
5. The dashboard keeps up to 50 test-marker check summaries in the current user's `%LOCALAPPDATA%\EndpointSentinel\scan-history.json`. Records contain paths, finding rule labels, hashes, timestamps, and issue messages—not copies of checked files.

The Defender view invokes the built-in `Get-MpComputerStatus` cmdlet through Windows PowerShell with a fixed, read-only query. It does not change Defender settings or initiate scans. Values reflect what Windows reports to the current user, can be unavailable depending on Windows configuration/policy, and do not guarantee that the device is safe.

The test-marker scanner reads files only. It caps each file at 32 MiB, each check at 10,000 files, 10,000 directories, and 20,000 total entries; it skips reparse points and reports skipped reparse points and oversized files as inconclusive. The only included rule is the transparent harmless test marker, not a malware signature or general threat detector.

## Optional Windows Service monitor

The service is manual-start and monitors nothing unless an administrator creates:

`%ProgramData%\EndpointSentinel\monitor-paths.json`

Example (edit to selected, existing directories; paths must be absolute):

```json
{
  "Paths": [
    "C:\\Users\\Public\\Documents"
  ]
}
```

Configure no more than five narrow directories. Drive/share roots and invalid paths are rejected. Monitoring is top-level only (no recursion), uses a bounded watcher buffer, debounces repeated events, limits accepted events, and limits concurrent file inspections to four. It uses the shared read-only scanner for created/changed/renamed files. Events, harmless-marker alerts, watcher overflows, and inconclusive inspections are written to `%ProgramData%\EndpointSentinel\monitor-events.log`. A full inspection queue drops new inspections with an explicit log message.

Create the config directory/file with permissions restricted to `SYSTEM`, `Administrators`, and the service identity (`NT AUTHORITY\LOCAL SERVICE` in the example below); grant no write access to ordinary users. For example, an elevated PowerShell session can create the directory and set its ACL before placing the JSON file there:

```powershell
New-Item -ItemType Directory -Force "$env:ProgramData\EndpointSentinel"
icacls "$env:ProgramData\EndpointSentinel" /inheritance:r
icacls "$env:ProgramData\EndpointSentinel" /grant:r "SYSTEM:(OI)(CI)F" "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\LOCAL SERVICE:(OI)(CI)M"
```

The service identity also needs read access to the config and access only to the specifically selected monitored locations. Do not grant broad write access to untrusted users. Service installation/start/stop requires an elevated terminal and is intentionally not automated:

```powershell
$serviceExe = '"C:\path\to\Endpoint Sentinel\EndpointSentinel.Service.exe"'
sc.exe create EndpointSentinelMonitor binPath= $serviceExe start= demand obj= 'NT AUTHORITY\LocalService'
sc.exe start EndpointSentinelMonitor
sc.exe stop EndpointSentinelMonitor
sc.exe delete EndpointSentinelMonitor
```

For local observation without installing the service, run `EndpointSentinel.Service.exe --console` and stop it with Ctrl+C. The Windows Service reports lifecycle state to SCM. This initial version does **not** implement desktop/service IPC or show service status in the desktop UI; monitor events and findings are available only in the local service log. The configuration setup and ACLs must be reviewed before enabling it.

## Safety and limitations

- Alert and record only; there is no delete, quarantine, remediation, execution, or upload path.
- Does not disable, replace, or interfere with Microsoft Defender or other endpoint-security products.
- No cloud lookup, account, telemetry, exploit defense, kernel component, or comprehensive antivirus capability.
- Monitoring is explicitly configured, non-recursive, and best effort. File-system watcher overflow can lose events; read permissions and safety bounds can leave files uninspected.
- The test-marker scanner detects only its harmless test marker. A clean/complete check is not proof that a device is safe. Findings can be false positives; threats can be missed. Continue using trusted endpoint protection.
- Defender status is a read-only view of Windows-reported values, not a full security audit and not a guarantee of effective protection.
- Service event history lives in a machine-wide data folder and must be protected by appropriate Windows ACLs. The app and service do not share a database.
