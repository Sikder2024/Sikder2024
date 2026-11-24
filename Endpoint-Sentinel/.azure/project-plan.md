# Endpoint Sentinel — Project Plan

## Goal

Create a Windows-only defensive security companion for the user's personal Windows PC. The first useful phase is a read-only dashboard of Windows-reported Microsoft Defender status, with a shortcut to Windows Security. The existing file check remains only a harmless test-marker demonstration; the application is not a replacement for Microsoft Defender, commercial antivirus, or endpoint detection and response (EDR) software. No “military grade” or protection guarantee is implied.

## Approved requirements

- **Name:** Endpoint Sentinel
- **Platform:** Windows only
- **Stack:** C#/.NET, WPF desktop UI, and a Windows Service
- **Monitoring:** Read-only Defender status check; optional bounded service file-event monitoring remains experimental
- **Initial detection:** Windows-reported Defender status plus a separate harmless test-marker demonstration; no original malware-detection engine
- **Response:** Alert and record findings only; no automatic deletion or quarantine
- **Connectivity:** Offline-first; no cloud reputation lookups or sign-in
- **Persistence:** Local settings, scan history, and findings

## First-version scope

1. A WPF dashboard showing read-only Defender protection and signature status, a Windows Security shortcut, and clear unknown/error states.
2. A background Windows Service with explicit start/stop status and bounded monitoring of configured locations. Monitoring must not silently expand to every drive or perform destructive actions.
3. A separate bounded test-marker check that enumerates files safely, reports progress, and records errors for inaccessible or changing files without presenting the check as antivirus.
4. No original malware detection layer in the initial useful phase. Any included test signature must be a harmless marker or EICAR-compatible test input; it must not contain malware.
5. Local persistence for settings, scan runs, and findings. Keep data local and restrict access to the service/UI communication channel and stored data.
6. User-visible explanations that results are indicative, may include false positives or miss threats, and should be reviewed with trusted endpoint protection.

## Safety and security boundaries

- Do not disable, replace, or interfere with Microsoft Defender or other security products.
- Do not add kernel drivers, stealth, process injection, persistence evasion, exploit behavior, or automated destructive remediation.
- Do not run scans with elevated privileges unless required and explicitly configured; explain any required service permissions.
- Restrict monitoring to selected paths, avoid following reparse points by default, and guard against unbounded recursion and symlink loops.
- Treat scanned files as untrusted data. Do not execute, upload, or open them.
- Alert-only behavior is the default. Any later quarantine feature requires a separate explicit decision and safe restore/audit design.

## Architecture outline

- **Desktop UI:** WPF client for user-initiated scans, status, findings, history, and settings.
- **Defender status:** Query built-in `Get-MpComputerStatus` using a fixed read-only command; report query failures as unknown and direct users to Windows Security for actions.
- **Monitor service:** Windows Service for scoped file-system event observation and scan scheduling. It reports events/results to the client through an authenticated local IPC mechanism (for example, named pipes with restrictive ACLs).
- **Scanning core:** Shared .NET library for safe file enumeration, metadata/hash collection, bounded content inspection, and deterministic local rules.
- **Storage:** Local database or repository selected during implementation; store only data needed for settings and results, not copies of scanned files.
- **Testing:** Unit tests for scan rules, path handling, event/debounce behavior, persistence, access failures, and IPC authorization; a harmless test fixture validates detection/reporting.

## Out of scope for the MVP

- Cross-platform/macOS support, cloud analysis, accounts, remote fleet management, kernel-level protection, exploit prevention, automated remediation, and claims of comprehensive malware detection.
- Production-grade antivirus certification or a claim that the prototype can protect users as a primary security product.

## Delivery sequence

1. Scaffold a Windows .NET solution with WPF UI, Windows Service, shared core, and focused tests.
2. Provide the read-only Defender status dashboard and Windows Security shortcut as the primary user value.
3. Keep the harmless test-marker check and local history clearly separate from Defender's protection.
4. Validate scoped event monitoring, service/UI communication, and local history before enabling background monitoring for users.
5. Run available build and test commands; document Windows-specific run/debug and service-install steps.

## Acceptance criteria

- The solution builds with the documented .NET SDK on Windows.
- A user can start an on-demand scan of a selected path and see progress, findings, and explicit access/scan errors.
- A harmless known test marker produces a finding; an ordinary fixture does not.
- The monitor observes only configured locations and can be stopped; event storms are bounded/debounced.
- No scanned file is executed, uploaded, deleted, or quarantined by the MVP.
- Defender status query failures display as unavailable/unknown rather than a healthy state, and the app does not alter Defender configuration.
- Scan history and findings persist locally, and communication/storage access is appropriately restricted.
- Documentation clearly states the prototype’s limitations and does not present it as a replacement for established endpoint protection.
