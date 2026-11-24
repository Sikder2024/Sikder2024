# Local integration hand-off (no Azure/cloud integration)

This approved project is a Windows-only offline desktop/service prototype. Do not add Azure, cloud services, sign-in, networking, package dependencies, database migrations, or seed data.

## Components and commands

- **Core:** `src/EndpointSentinel.Core`; build with `dotnet build .\EndpointSentinel.sln`; scanner and local history library.
- **Desktop:** `src/EndpointSentinel.Desktop`; WPF read-only Defender status dashboard and harmless test-marker check; launch with `dotnet run --project .\src\EndpointSentinel.Desktop\EndpointSentinel.Desktop.csproj`; API routes/port/dev server: none.
- **Monitor:** `src/EndpointSentinel.Service`; Windows Service executable; local test with `dotnet run --project .\src\EndpointSentinel.Service\EndpointSentinel.Service.csproj -- --console`. Production service install is manual/elevated. Health endpoint: none; service lifecycle is reported to Windows SCM.
- **API routes:** none (desktop application; no HTTP backend).
- **Persistence:** local JSON history at `%LOCALAPPDATA%\EndpointSentinel\scan-history.json`; service configuration and event log at `%ProgramData%\EndpointSentinel\`. Database/migration tool/directory: not applicable. Seed data: none.
- **Shared types:** `src/EndpointSentinel.Core`; consume through the project reference, no package alias.
- **Essential:** WPF on-demand scan, shared scanner, explicit error/findings reporting, local scan history.
- **Defender status:** Fixed read-only `Get-MpComputerStatus` query; errors are explicitly unknown; Windows Security shortcut opens the OS settings UI. No Defender settings are changed.
- **Enhancement:** opt-in bounded service file monitoring; monitor status is not yet surfaced in the desktop UI.

## Remaining local integration work

- No frontend-to-live-API wiring or endpoint smoke tests apply; there is no API or web frontend.
- No database schema or migrations apply; persistence is local JSON.
- Validate the Windows Service installation identity, config-file ACL, and selected-path ACL on a dedicated Windows test machine before enabling monitoring.
- Verify service lifecycle, event storms, filesystem watcher overflow reporting, access-denied paths, and desktop/service IPC (IPC is not implemented in this slice).
