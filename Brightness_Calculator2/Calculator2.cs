using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using static System.Net.Mime.MediaTypeNames;

class LPRCameraImageCaptureAndBrightness
{
    private const string CameraIP = "10.0.0.110";
    private const int CameraSendPort = 6051;
    private const int CameraReceivePort = 6050;
    private const string OutputDirectory = @"D:\frames";
    private const string DataLogFile = @"D:\image_data_log2.txt";
    private const int MaxUdpSize = 65507;
    private const int UnitId = 1;
    private const int MaxRetries = 5;
    private const int RetryDelayMs = 200;

    static async Task Main(string[] args)
    {
        Console.WriteLine("LPR Camera Image Capture and Brightness Calculation starting...");

        int[] exposureTimes = { 75000, 500000 };
        int[] ids = { 120, 122 };

        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        try
        {
            Directory.CreateDirectory(OutputDirectory);
            File.WriteAllText(DataLogFile, "UnitID,Timestamp,ExposureTime,Brightness,FilePath\n");

            for (int i = 0; i < exposureTimes.Length; i++)
            {
                await CaptureAndProcessImage(exposureTimes[i], ids[i]);
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
            Console.WriteLine($"Total time taken: {stopwatch.Elapsed}");
        }
    }

    private static async Task CaptureAndProcessImage(int exposureTime, int id)
    {
        using (UdpClient udpClient = new UdpClient())
        {
            udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, CameraReceivePort));
            udpClient.Client.ReceiveTimeout = 300;
            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraSendPort);

            for (int retry = 0; retry < MaxRetries; retry++)
            {
                try
                {
                    DateTime currentTime = DateTime.Now;
                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");

                    byte[] request = CreateCurrentFrameRequest(exposureTime, id);
                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                    Console.WriteLine($"Request sent to camera for image with exposure time {exposureTime}");

                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
                    Console.WriteLine($"Received {imageData.Length} bytes of image data for exposure time {exposureTime}");

                    string outputPath = await SaveImageAndCalculateBrightness(imageData, timestamp, exposureTime);
                    Console.WriteLine($"Image with exposure time {exposureTime} processed and saved");

                    break; // Success, exit retry loop
                }
                catch (Exception ex) when (ex is SocketException || ex is TimeoutException)
                {
                    if (retry < MaxRetries - 1)
                    {
                        Console.WriteLine($"Attempt {retry + 1} failed for exposure time {exposureTime}. Retrying in {RetryDelayMs}ms...");
                        await Task.Delay(RetryDelayMs);
                    }
                    else
                    {
                        Console.WriteLine($"All attempts failed for exposure time {exposureTime}. Error: {ex.Message}");
                    }
                }
            }
        }
    }

    private static byte[] CreateCurrentFrameRequest(int exposureTime, int id)
    {
        byte[] request = new byte[23];

        request[0] = 0x02; // STX

        byte[] unitIdBytes = BitConverter.GetBytes(UnitId);
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

        if (imageSize <= 0 || imageSize > MaxUdpSize)
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

    private static async Task<string> SaveImageAndCalculateBrightness(byte[] imageData, string timestamp, int exposureTime)
    {
        using (MemoryStream ms = new MemoryStream(imageData))
        using (Image<Rgba32> image = SixLabors.ImageSharp.Image.Load<Rgba32>(ms))
        {
            double brightness = CalculateImageBrightness(image);

            string fileName = $"{UnitId}_{timestamp}_{exposureTime}_{brightness:F4}.jpg";
            string outputPath = Path.Combine(OutputDirectory, fileName);

            await image.SaveAsJpegAsync(outputPath);

            string logEntry = $"{UnitId},{timestamp},{exposureTime},{brightness:F4},{outputPath}\n";
            await File.AppendAllTextAsync(DataLogFile, logEntry);

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

