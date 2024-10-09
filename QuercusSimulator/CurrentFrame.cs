//using SixLabors.ImageSharp.PixelFormats;
//using SixLabors.ImageSharp;
//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net.Sockets;
//using System.Text;
//using System.Threading.Tasks;
//using System.Diagnostics;
//using System.Net;
//using static QuercusSimulator.MessageBuilder;
//namespace QuercusSimulator
//{
//    internal class CurrentFrame
//    {
//        private const int MaxUdpSize = 65507;
//        private const string OutputDirectory = @"D:\LPR\EventImages";

//    public static async Task GetAndSaveImages(
//    int cameraId,
//    string cameraIP,
//    int[] exposureTimes,
//    int[] ids,
//    string outputDirectory,
//    string dataLogFile,
//    int cameraSendPort = 6051,
//    int cameraReceivePort = 6050)
//        {
//            Console.WriteLine("LPR Camera Image Capture and Brightness Calculation starting...");
//            Stopwatch stopwatch = new Stopwatch();
//            stopwatch.Start();

//            try
//            {
//                using (UdpClient udpClient = new UdpClient(cameraReceivePort))
//                {
//                    udpClient.Client.ReceiveTimeout = 5000;
//                    IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(cameraIP), cameraSendPort);
//                    Directory.CreateDirectory(OutputDirectory);
//                    //File.WriteAllText(dataLogFile, "UnitID,Timestamp,ExposureTime,Brightness,FilePath\n");

//                    for (int i = 0; i < exposureTimes.Length; i++)
//                    {
//                        DateTime currentTime = DateTime.Now;
//                        string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");
//                        byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], cameraId);
//                        await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//                        Console.WriteLine($"Request sent to camera for image {i + 1}");

//                        byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//                        Console.WriteLine($"Received {imageData.Length} bytes of image data for image {i + 1}");

//                        string outputPath = await SaveImageAndCalculateBrightness(imageData, timestamp, exposureTimes[i], cameraId, cameraIP, OutputDirectory);
//                        Console.WriteLine($"Image {i + 1} processed and saved");
//                        Console.WriteLine();
//                    }
//                }
//            }
//            catch (SocketException ex)
//            {
//                Console.WriteLine($"SocketException: {ex.Message}");
//                Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
//                Console.WriteLine($"Stack trace: {ex.StackTrace}");
//            }
//            finally
//            {
//                stopwatch.Stop();
//                Console.WriteLine($"Total time taken: {stopwatch.Elapsed}");
//            }
//        }

//        private static async Task<string> SaveImageAndCalculateBrightness(byte[] imageData, string timestamp, int exposureTime, int UnitId,string CameraIP, string OutputDirectory)
//        {
//            using (MemoryStream ms = new MemoryStream(imageData))
//            using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
//            {
//                double brightness = CalculateImageBrightness(image);

//                // Split the CameraIP by dots and get the last octet
//                string lastOctet = CameraIP.Split('.').Last();

//                // Use the last octet in the file name
//                string fileName = $"lastimage_{lastOctet}.jpg";

//                string outputPath = Path.Combine(OutputDirectory, fileName);

//                await image.SaveAsJpegAsync(outputPath);

//                //string logEntry = $"{UnitId},{timestamp},{exposureTime},{brightness:F4},{outputPath}\n";
//                //await File.AppendAllTextAsync(DataLogFile, logEntry);

//                return outputPath;
//            }
//        }





//        private static double CalculateImageBrightness(Image<Rgba32> image)
//        {
//            double totalBrightness = 0;
//            int pixelCount = image.Width * image.Height;

//            image.ProcessPixelRows(accessor =>
//            {
//                for (int y = 0; y < accessor.Height; y++)
//                {
//                    Span<Rgba32> pixelRow = accessor.GetRowSpan(y);
//                    for (int x = 0; x < pixelRow.Length; x++)
//                    {
//                        ref Rgba32 pixel = ref pixelRow[x];
//                        double pixelBrightness = (0.299 * pixel.R + 0.587 * pixel.G + 0.114 * pixel.B) / 255.0;
//                        totalBrightness += pixelBrightness;
//                    }
//                }
//            });

//            return totalBrightness / pixelCount;
//        }
//    }
//}
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp;
using System.Diagnostics;
using System.Net.Sockets;
using System.Net;
using static QuercusSimulator.MessageBuilder;
public static class CurrentFrame
{
    private const int MaxUdpSize = 65507;
    private const string OutputDirectory = @"D:\LPR\EventImages";

    public static async Task GetAndSaveImages(
        uint cameraId,
        string cameraIP,
        int[] exposureTimes,
        int[] ids,
        string outputDirectory,
        int cameraSendPort = 6051,
        int cameraReceivePort = 6050)
    {
        Console.WriteLine("LPR Camera Image Capture and Brightness Calculation starting...");
        Stopwatch stopwatch = new Stopwatch();
        stopwatch.Start();

        try
        {
            using (UdpClient udpClient = new UdpClient(cameraReceivePort))
            {
                udpClient.Client.ReceiveTimeout = 5000;
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(cameraIP), cameraSendPort);
                Directory.CreateDirectory(OutputDirectory);

                List<(byte[] imageData, double brightness, int exposureTime)> images = new List<(byte[], double, int)>();

                for (int i = 0; i < exposureTimes.Length; i++)
                {
                    DateTime currentTime = DateTime.Now;
                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");
                    byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], cameraId);
                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                    Console.WriteLine($"Request sent to camera for image {i + 1}");

                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
                    Console.WriteLine($"Received {imageData.Length} bytes of image data for image {i + 1}");

                    double brightness = await CalculateImageBrightness(imageData);
                    images.Add((imageData, brightness, exposureTimes[i]));
                    Console.WriteLine($"Image {i + 1} processed");
                    Console.WriteLine();
                }

                var bestImage = GetBestImage(images);
                string outputPath = await SaveImage(bestImage.imageData, DateTime.Now.ToString("yyyyMMdd_HHmmss"), bestImage.exposureTime, cameraId, cameraIP, OutputDirectory);
                Console.WriteLine($"Best image saved: {outputPath}");
            }
        }
        catch (SocketException ex)
        {
            Console.WriteLine($"SocketException: {ex.Message}");
            Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
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

    private static (byte[] imageData, int exposureTime) GetBestImage(List<(byte[] imageData, double brightness, int exposureTime)> images)
    {
        const double targetBrightness = 0.35;
        var bestImage = images.OrderBy(img => Math.Abs(img.brightness - targetBrightness)).First();
        return (bestImage.imageData, bestImage.exposureTime);
    }


    private static async Task<string> SaveImage(byte[] imageData, string timestamp, int exposureTime, uint UnitId, string CameraIP, string OutputDirectory)
    {
        using (MemoryStream ms = new MemoryStream(imageData))
        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
        {
            string lastOctet = CameraIP.Split('.').Last();
            string fileName = $"lastimage_{lastOctet}.jpg";
            string outputPath = Path.Combine(OutputDirectory, fileName);
            await image.SaveAsJpegAsync(outputPath);
            return outputPath;
        }
    }

    private static async Task<double> CalculateImageBrightness(byte[] imageData)
    {
        using (MemoryStream ms = new MemoryStream(imageData))
        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
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
}