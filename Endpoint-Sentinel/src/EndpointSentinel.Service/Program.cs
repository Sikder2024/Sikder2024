namespace EndpointSentinel.Service;

internal static class Program
{
    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("Endpoint Sentinel Monitor is Windows-only.");
            return 1;
        }

        if (args.Length == 1 && string.Equals(args[0], "--console", StringComparison.OrdinalIgnoreCase))
        {
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };
            try
            {
                MonitorHost.RunAsync(cancellation.Token).GetAwaiter().GetResult();
                return 0;
            }
            catch (OperationCanceledException)
            {
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Monitor failed: {ex.Message}");
                return 1;
            }
        }

        return NativeServiceHost.Run();
    }
}
