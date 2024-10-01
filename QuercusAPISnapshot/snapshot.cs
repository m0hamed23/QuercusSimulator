using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        string cameraIp = "10.0.0.110";
        string password = "quercus2";
        string flash = "yes";
        string trigger = "no";
        string time = "-1";
        string exposure = "75000";

        var lprCapture = new LPRSnapshotCapture(cameraIp, password, flash, trigger, time, exposure);

        Console.WriteLine("Starting LPR Snapshot Capture");
        Console.WriteLine("Press 't' to take a snapshot. Press 'q' to quit.");

        while (true)
        {
            var key = Console.ReadKey(true);
            if (key.KeyChar == 't')
            {
                Console.WriteLine("Taking snapshot...");
                string snapshotPath = await lprCapture.TakeSnapshot();
                if (string.IsNullOrEmpty(snapshotPath))
                {
                    Console.WriteLine("Failed to save snapshot");
                }
                else
                {
                    Console.WriteLine($"Snapshot saved at: {snapshotPath}");
                }
            }
            else if (key.KeyChar == 'q')
            {
                break;
            }
        }

        Console.WriteLine("Program ended");
    }
}

class LPRSnapshotCapture
{
    private readonly string url;
    private readonly HttpClient client;

    public LPRSnapshotCapture(string cameraIp, string password, string flash, string trigger, string time, string exposure)
    {
        url = $"http://{cameraIp}/LiveImage?password={password}&flash={flash}&trigger={trigger}&time={time}&exposure={exposure}";
        client = new HttpClient();
        client.Timeout = TimeSpan.FromSeconds(30);  // Set a reasonable timeout
    }

    public async Task<string> TakeSnapshot()
    {
        try
        {
            Console.WriteLine($"Requesting image from: {url}");
            var response = await client.GetAsync(url);
            response.EnsureSuccessStatusCode();

            var contentType = response.Content.Headers.ContentType?.ToString();
            Console.WriteLine($"Received response with content type: {contentType}");

            if (string.IsNullOrEmpty(contentType) || !contentType.StartsWith("image/"))
            {
                Console.WriteLine("Unexpected content type. Expected an image.");
                return null;
            }

            var imageData = await response.Content.ReadAsByteArrayAsync();
            if (imageData.Length == 0)
            {
                Console.WriteLine("Received empty image data");
                return null;
            }

            string timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string filename = $"D:/lpr_snapshot_{timestamp}.jpg";

            await File.WriteAllBytesAsync(filename, imageData);

            Console.WriteLine($"Image saved. Size: {imageData.Length} bytes");
            return filename;
        }
        catch (HttpRequestException e)
        {
            Console.WriteLine($"HTTP Request failed: {e.Message}");
            return null;
        }
        catch (TaskCanceledException)
        {
            Console.WriteLine("Request timed out");
            return null;
        }
        catch (Exception e)
        {
            Console.WriteLine($"Unexpected error: {e.Message}");
            return null;
        }
    }
}