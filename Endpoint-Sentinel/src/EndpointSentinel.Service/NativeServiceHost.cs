using System.Runtime.InteropServices;

namespace EndpointSentinel.Service;

/// <summary>Minimal native SCM host avoids adding an external Windows-service package.</summary>
internal static class NativeServiceHost
{
    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceStartPending = 0x00000002;
    private const uint ServiceRunning = 0x00000004;
    private const uint ServiceStopPending = 0x00000003;
    private const uint ServiceStopped = 0x00000001;
    private const uint ServiceAcceptStop = 0x00000001;
    private const uint ControlStop = 0x00000001;
    private const string ServiceName = "EndpointSentinelMonitor";
    private static readonly CancellationTokenSource StopToken = new();
    private static ServiceStatusHandle? _statusHandle;

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void ServiceMainCallback(uint argumentCount, IntPtr arguments);

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate uint HandlerExCallback(uint control, uint eventType, IntPtr eventData, IntPtr context);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? ServiceName;
        public ServiceMainCallback? ServiceProc;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    private sealed class ServiceStatusHandle { public IntPtr Value; }

    private static readonly ServiceMainCallback MainCallback = ServiceMain;
    private static readonly HandlerExCallback ControlCallback = HandleControl;

    public static int Run()
    {
        var table = new[]
        {
            new ServiceTableEntry { ServiceName = ServiceName, ServiceProc = MainCallback },
            new ServiceTableEntry { ServiceName = null, ServiceProc = null }
        };
        if (StartServiceCtrlDispatcherW(table))
            return 0;
        var error = Marshal.GetLastWin32Error();
        Console.Error.WriteLine($"Windows Service Control Manager could not start the service dispatcher (Win32 error {error}). Run --console for local testing, or install/start the service through the SCM.");
        return error;
    }

    private static void ServiceMain(uint argumentCount, IntPtr arguments)
    {
        var statusHandle = new ServiceStatusHandle
        {
            Value = RegisterServiceCtrlHandlerExW(ServiceName, ControlCallback, IntPtr.Zero)
        };
        _statusHandle = statusHandle;
        if (statusHandle.Value == IntPtr.Zero)
            return;

        SetState(ServiceStartPending, 0, 3000);
        try
        {
            SetState(ServiceRunning, ServiceAcceptStop, 0);
            MonitorHost.RunAsync(StopToken.Token).GetAwaiter().GetResult();
            SetState(ServiceStopped, 0, 0);
        }
        catch (OperationCanceledException)
        {
            SetState(ServiceStopped, 0, 0);
        }
        catch (Exception ex)
        {
            MonitorHost.WriteFatalError(ex);
            SetState(ServiceStopped, 0, 0, win32ExitCode: 1);
        }
    }

    private static uint HandleControl(uint control, uint eventType, IntPtr eventData, IntPtr context)
    {
        if (control == ControlStop)
        {
            SetState(ServiceStopPending, 0, 3000);
            StopToken.Cancel();
        }
        return 0;
    }

    private static void SetState(uint state, uint acceptedControls, uint waitHint, uint win32ExitCode = 0)
    {
        if (_statusHandle is null || _statusHandle.Value == IntPtr.Zero)
            return;
        var status = new ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = acceptedControls,
            Win32ExitCode = win32ExitCode,
            WaitHint = waitHint,
            CheckPoint = state is ServiceStartPending or ServiceStopPending ? 1u : 0u
        };
        _ = SetServiceStatus(_statusHandle.Value, ref status);
    }

    [DllImport("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool StartServiceCtrlDispatcherW([In] ServiceTableEntry[] serviceTable);

    [DllImport("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerExW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr RegisterServiceCtrlHandlerExW(string serviceName, HandlerExCallback callback, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetServiceStatus(IntPtr serviceStatusHandle, ref ServiceStatus serviceStatus);
}
