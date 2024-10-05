using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

class LPRCameraImageCaptureAndBrightness
{
    private static string ConfigFile = @"D:\config.json";
    private static Config config;

    private class Config
    {
        public string DataLogFile { get; set; }
        public int MaxUdpSize { get; set; }
        public List<CameraInfo> Cameras { get; set; }
        public int[] ExposureTimes { get; set; }
        public int[] Ids { get; set; }
        public int DelayMinutes { get; set; }
    }

    private class CameraInfo
    {
        public int UnitId { get; set; }
        public string IP { get; set; }
        public int SendPort { get; set; }
        public int ReceivePort { get; set; }
        public string OutputDirectory { get; set; }
    }

    static async Task Main(string[] args)
    {
        Console.WriteLine("Multi-Camera LPR Image Capture and Brightness Calculation starting...");

        LoadConfig();

        while (true)
        {
            Stopwatch stopwatch = new Stopwatch();
            stopwatch.Start();

            try
            {
                foreach (var camera in config.Cameras)
                {
                    if (await PingCamera(camera.IP))
                    {
                        await ProcessCamera(camera, config.ExposureTimes, config.Ids);
                    }
                    else
                    {
                        Console.WriteLine($"Skipping camera {camera.UnitId} as it's not responding to ping.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
            finally
            {
                stopwatch.Stop();
                Console.WriteLine($"Total time taken for all cameras: {stopwatch.Elapsed}");
            }

            await Task.Delay(TimeSpan.FromMinutes(config.DelayMinutes));
        }
    }

    private static void LoadConfig()
    {
        string jsonString = File.ReadAllText(ConfigFile);
        config = JsonSerializer.Deserialize<Config>(jsonString);
    }

    private static async Task<bool> PingCamera(string ip)
    {
        using (Ping ping = new Ping())
        {
            try
            {
                PingReply reply = await ping.SendPingAsync(ip, 1000);
                return reply.Status == IPStatus.Success;
            }
            catch
            {
                return false;
            }
        }
    }

    private static async Task ProcessCamera(CameraInfo camera, int[] exposureTimes, int[] ids)
    {
        Console.WriteLine($"Processing camera {camera.UnitId}...");

        try
        {
            using (UdpClient udpClient = new UdpClient(camera.ReceivePort))
            {
                udpClient.Client.ReceiveTimeout = 5000;
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(camera.IP), camera.SendPort);

                Directory.CreateDirectory(camera.OutputDirectory);

                for (int i = 0; i < exposureTimes.Length; i++)
                {
                    DateTime currentTime = DateTime.Now;
                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");

                    byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], camera.UnitId);
                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                    Console.WriteLine($"Request sent to camera {camera.UnitId} for image {i + 1}");

                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
                    Console.WriteLine($"Received {imageData.Length} bytes of image data for camera {camera.UnitId}, image {i + 1}");

                    string outputPath = await SaveImageAndCalculateBrightness(imageData, timestamp, exposureTimes[i], camera);
                    Console.WriteLine($"Image {i + 1} processed and saved for camera {camera.UnitId}");

                    Console.WriteLine();
                }
            }
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"SocketException for camera {camera.UnitId}: {ex.Message}");
            Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
        }
    }

    private static byte[] CreateCurrentFrameRequest(int exposureTime, int id, int unitId)
    {
        byte[] request = new byte[23];

        request[0] = 0x02; // STX

        byte[] unitIdBytes = BitConverter.GetBytes(unitId);
        byte[] sizeBytes = BitConverter.GetBytes(23);
        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
        byte[] idBytes = BitConverter.GetBytes(id);
        byte[] exposureTimeBytes = BitConverter.GetBytes(exposureTime);

        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(unitIdBytes);
            Array.Reverse(sizeBytes);
            Array.Reverse(typeBytes);
            Array.Reverse(versionBytes);
            Array.Reverse(idBytes);
            Array.Reverse(exposureTimeBytes);
        }

        unitIdBytes.CopyTo(request, 1);
        sizeBytes.CopyTo(request, 5);
        typeBytes.CopyTo(request, 9);
        versionBytes.CopyTo(request, 11);
        idBytes.CopyTo(request, 13);
        exposureTimeBytes.CopyTo(request, 17);

        request[21] = CalculateXOR(request, 0, 21);
        request[22] = 0x03; // ETX

        return request;
    }

    private static async Task<byte[]> ReceiveCurrentFrameResponseAsync(UdpClient udpClient)
    {
        UdpReceiveResult result = await udpClient.ReceiveAsync();
        byte[] response = result.Buffer;

        if (response.Length < 21)
            throw new Exception("Incomplete response received");

        if (response[0] != 0x02)
            throw new Exception("Invalid STX in response");

        int totalSize = BitConverter.ToInt32(response, 5);
        ushort messageType = BitConverter.ToUInt16(response, 9);
        int imageSize = BitConverter.ToInt32(response, 17);

        if (messageType != 136)
            throw new Exception($"Unexpected message type: {messageType}");

        if (imageSize <= 0 || imageSize > config.MaxUdpSize)
            throw new Exception("Invalid or corrupted image size");

        if (response.Length < totalSize)
            throw new Exception("Incomplete message received");

        byte[] imageData = new byte[imageSize];
        Buffer.BlockCopy(response, 21, imageData, 0, imageSize);

        return imageData;
    }

    private static byte CalculateXOR(byte[] data, int start, int length)
    {
        byte xor = 0;
        for (int i = start; i < start + length; i++)
        {
            xor ^= data[i];
        }
        return xor;
    }

    private static async Task<string> SaveImageAndCalculateBrightness(byte[] imageData, string timestamp, int exposureTime, CameraInfo camera)
    {
        using (MemoryStream ms = new MemoryStream(imageData))
        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
        {
            double brightness = CalculateImageBrightness(image);

            string fileName = $"{camera.UnitId}_{timestamp}_{exposureTime}_{brightness:F4}.jpg";
            string outputPath = Path.Combine(camera.OutputDirectory, fileName);

            await image.SaveAsJpegAsync(outputPath);

            string logEntry = $"{camera.UnitId},{timestamp},{exposureTime},{brightness:F4},{outputPath}\n";
            await File.AppendAllTextAsync(config.DataLogFile, logEntry);

            return outputPath;
        }
    }

    private static double CalculateImageBrightness(Image<Rgba32> image)
    {
        double totalBrightness = 0;
        int pixelCount = image.Width * image.Height;

        image.ProcessPixelRows(accessor =>
        {
            for (int y = 0; y < accessor.Height; y++)
            {
                Span<Rgba32> pixelRow = accessor.GetRowSpan(y);
                for (int x = 0; x < pixelRow.Length; x++)
                {
                    ref Rgba32 pixel = ref pixelRow[x];
                    double pixelBrightness = (0.299 * pixel.R + 0.587 * pixel.G + 0.114 * pixel.B) / 255.0;
                    totalBrightness += pixelBrightness;
                }
            }
        });

        return totalBrightness / pixelCount;
    }
}