//using System;
//using System.Diagnostics;
//using System.IO;
//using System.Net;
//using System.Net.Sockets;
//using System.Threading.Tasks;
//using SixLabors.ImageSharp;
//using SixLabors.ImageSharp.PixelFormats;
//using SixLabors.ImageSharp.Processing;

//class ContinuousCameraCapture
//{
//    private const string CameraIP = "10.0.0.110";
//    private const int CameraSendPort = 6051;
//    private const int CameraReceivePort = 6050;
//    private const string OutputDirectory = @"D:\frames";
//    private const string DataLogFile = @"D:\image_data_log.txt";
//    private const int MaxUdpSize = 65507;
//    private const int UnitId = 1;
//    private const double TargetBrightness = 0.35;
//    private const int InitialExposureTime = 1000;
//    private const int MinExposureTime = 100;
//    private const int MaxExposureTime = 250000;

//    private static Image<Rgba32> LastImage;
//    private static int CurrentExposureTime = InitialExposureTime;

//    static async Task Main(string[] args)
//    {
//        Console.WriteLine("Continuous Camera Capture starting...");

//        try
//        {
//            using (UdpClient udpClient = new UdpClient(CameraReceivePort))
//            {
//                udpClient.Client.ReceiveTimeout = 5000;
//                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraSendPort);

//                Directory.CreateDirectory(OutputDirectory);
//                File.WriteAllText(DataLogFile, "UnitID,Timestamp,ExposureTime,Brightness,FilePath\n");

//                while (true)
//                {
//                    DateTime currentTime = DateTime.Now;
//                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");

//                    byte[] request = CreateCurrentFrameRequest(CurrentExposureTime);
//                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//                    Console.WriteLine($"Request sent to camera with exposure time: {CurrentExposureTime}");

//                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//                    Console.WriteLine($"Received {imageData.Length} bytes of image data");

//                    double brightness = await ProcessImageAndAdjustExposure(imageData, timestamp);
//                    Console.WriteLine($"Image processed. Brightness: {brightness:F4}, Next exposure time: {CurrentExposureTime}");

//                    Console.WriteLine("Press 'Q' to quit or any other key to continue...");
//                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Q)
//                    {
//                        break;
//                    }

//                    // Add a delay to avoid overwhelming the camera
//                    await Task.Delay(1000);
//                }
//            }
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"An error occurred: {ex.Message}");
//            Console.WriteLine($"Stack trace: {ex.StackTrace}");
//        }
//    }

//    private static byte[] CreateCurrentFrameRequest(int exposureTime)
//    {
//        byte[] request = new byte[23];

//        request[0] = 0x02; // STX

//        byte[] unitIdBytes = BitConverter.GetBytes(UnitId);
//        byte[] sizeBytes = BitConverter.GetBytes(23);
//        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
//        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
//        byte[] idBytes = BitConverter.GetBytes(0); // Using 0 as we don't need different IDs
//        byte[] exposureTimeBytes = BitConverter.GetBytes(exposureTime);

//        if (!BitConverter.IsLittleEndian)
//        {
//            Array.Reverse(unitIdBytes);
//            Array.Reverse(sizeBytes);
//            Array.Reverse(typeBytes);
//            Array.Reverse(versionBytes);
//            Array.Reverse(idBytes);
//            Array.Reverse(exposureTimeBytes);
//        }

//        unitIdBytes.CopyTo(request, 1);
//        sizeBytes.CopyTo(request, 5);
//        typeBytes.CopyTo(request, 9);
//        versionBytes.CopyTo(request, 11);
//        idBytes.CopyTo(request, 13);
//        exposureTimeBytes.CopyTo(request, 17);

//        request[21] = CalculateXOR(request, 0, 21);
//        request[22] = 0x03; // ETX

//        return request;
//    }

//    private static async Task<byte[]> ReceiveCurrentFrameResponseAsync(UdpClient udpClient)
//    {
//        UdpReceiveResult result = await udpClient.ReceiveAsync();
//        byte[] response = result.Buffer;

//        if (response.Length < 21)
//            throw new Exception("Incomplete response received");

//        if (response[0] != 0x02)
//            throw new Exception("Invalid STX in response");

//        int totalSize = BitConverter.ToInt32(response, 5);
//        ushort messageType = BitConverter.ToUInt16(response, 9);
//        int imageSize = BitConverter.ToInt32(response, 17);

//        if (messageType != 136)
//            throw new Exception($"Unexpected message type: {messageType}");

//        if (imageSize <= 0 || imageSize > MaxUdpSize)
//            throw new Exception("Invalid or corrupted image size");

//        if (response.Length < totalSize)
//            throw new Exception("Incomplete message received");

//        byte[] imageData = new byte[imageSize];
//        Buffer.BlockCopy(response, 21, imageData, 0, imageSize);

//        return imageData;
//    }

//    private static byte CalculateXOR(byte[] data, int start, int length)
//    {
//        byte xor = 0;
//        for (int i = start; i < start + length; i++)
//        {
//            xor ^= data[i];
//        }
//        return xor;
//    }

//    private static async Task<double> ProcessImageAndAdjustExposure(byte[] imageData, string timestamp)
//    {
//        using (MemoryStream ms = new MemoryStream(imageData))
//        {
//            LastImage = Image.Load<Rgba32>(ms);
//            double brightness = CalculateImageBrightness(LastImage);

//            string fileName = $"{UnitId}_{timestamp}_{CurrentExposureTime}_{brightness:F4}.jpg";
//            string outputPath = Path.Combine(OutputDirectory, fileName);

//            await LastImage.SaveAsJpegAsync(outputPath);

//            string logEntry = $"{UnitId},{timestamp},{CurrentExposureTime},{brightness:F4},{outputPath}\n";
//            await File.AppendAllTextAsync(DataLogFile, logEntry);

//            // Adjust exposure time for the next capture
//            int previousExposureTime = CurrentExposureTime;
//            CurrentExposureTime = CalculateNextExposureTime(brightness, previousExposureTime);

//            Console.WriteLine($"Exposure adjustment: {previousExposureTime} -> {CurrentExposureTime}");

//            return brightness;
//        }
//    }

//    private static double CalculateImageBrightness(Image<Rgba32> image)
//    {
//        double totalBrightness = 0;
//        int pixelCount = image.Width * image.Height;

//        image.ProcessPixelRows(accessor =>
//        {
//            for (int y = 0; y < accessor.Height; y++)
//            {
//                Span<Rgba32> pixelRow = accessor.GetRowSpan(y);
//                for (int x = 0; x < pixelRow.Length; x++)
//                {
//                    ref Rgba32 pixel = ref pixelRow[x];
//                    double pixelBrightness = (0.299 * pixel.R + 0.587 * pixel.G + 0.114 * pixel.B) / 255.0;
//                    totalBrightness += pixelBrightness;
//                }
//            }
//        });

//        return totalBrightness / pixelCount;
//    }

//    private static int CalculateNextExposureTime(double currentBrightness, int previousExposureTime)
//    {
//        double brightnessRatio = TargetBrightness / currentBrightness;
//        double adjustmentFactor = Math.Sqrt(brightnessRatio); // Use square root for more gradual adjustment

//        int nextExposureTime = (int)(previousExposureTime * adjustmentFactor);

//        // Limit the adjustment to prevent extreme changes
//        int maxChange = previousExposureTime / 2;
//        nextExposureTime = Math.Clamp(nextExposureTime, previousExposureTime - maxChange, previousExposureTime + maxChange);

//        // Ensure the exposure time is within the allowed range
//        nextExposureTime = Math.Clamp(nextExposureTime, MinExposureTime, MaxExposureTime);

//        Console.WriteLine($"Brightness ratio: {brightnessRatio:F4}, Adjustment factor: {adjustmentFactor:F4}");

//        return nextExposureTime;
//    }
//}
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

class ContinuousCameraCapture
{
    private const string CameraIP = "10.0.0.110";
    private const int CameraSendPort = 6051;
    private const int CameraReceivePort = 6050;
    private const string OutputDirectory = @"D:\frames";
    private const string DataLogFile = @"D:\image_data_log.txt";
    private const int MaxUdpSize = 65507;
    private const int UnitId = 1;
    private const double MinTargetBrightness = 0.3;
    private const double MaxTargetBrightness = 0.4;
    private const int MinExposureTime = 1000;
    private const int MaxExposureTime = 50000;

    private static Image<Rgba32> LastImage;
    private static int CurrentExposureTime = MinExposureTime;

    static async Task Main(string[] args)
    {
        Console.WriteLine("Continuous Camera Capture starting...");

        try
        {
            using (UdpClient udpClient = new UdpClient(CameraReceivePort))
            {
                udpClient.Client.ReceiveTimeout = 5000;
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraSendPort);

                Directory.CreateDirectory(OutputDirectory);
                File.WriteAllText(DataLogFile, "UnitID,Timestamp,ExposureTime,Brightness,FilePath\n");

                while (true)
                {
                    DateTime currentTime = DateTime.Now;
                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");

                    byte[] request = CreateCurrentFrameRequest(CurrentExposureTime);
                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                    Console.WriteLine($"Request sent to camera with exposure time: {CurrentExposureTime}");

                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
                    Console.WriteLine($"Received {imageData.Length} bytes of image data");

                    double brightness = await ProcessImageAndAdjustExposure(imageData, timestamp);
                    Console.WriteLine($"Image processed. Brightness: {brightness:F4}, Next exposure time: {CurrentExposureTime}");

                    Console.WriteLine("Press 'Q' to quit or any other key to continue...");
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Q)
                    {
                        break;
                    }

                    // Add a delay to avoid overwhelming the camera
                    await Task.Delay(4000);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred: {ex.Message}");
            Console.WriteLine($"Stack trace: {ex.StackTrace}");
        }
    }

    private static byte[] CreateCurrentFrameRequest(int exposureTime)
    {
        byte[] request = new byte[23];

        request[0] = 0x02; // STX

        byte[] unitIdBytes = BitConverter.GetBytes(UnitId);
        byte[] sizeBytes = BitConverter.GetBytes(23);
        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
        byte[] idBytes = BitConverter.GetBytes(0); // Using 0 as we don't need different IDs
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

    private static async Task<double> ProcessImageAndAdjustExposure(byte[] imageData, string timestamp)
    {
        using (MemoryStream ms = new MemoryStream(imageData))
        {
            LastImage = Image.Load<Rgba32>(ms);
            double brightness = CalculateImageBrightness(LastImage);

            string fileName = $"{UnitId}_{timestamp}_{CurrentExposureTime}_{brightness:F4}.jpg";
            string outputPath = Path.Combine(OutputDirectory, fileName);

            await LastImage.SaveAsJpegAsync(outputPath);

            string logEntry = $"{UnitId},{timestamp},{CurrentExposureTime},{brightness:F4},{outputPath}\n";
            await File.AppendAllTextAsync(DataLogFile, logEntry);

            // Adjust exposure time for the next capture
            CurrentExposureTime = CalculateNextExposureTime(brightness);

            return brightness;
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

    private static int CalculateNextExposureTime(double currentBrightness)
    {
        if (currentBrightness < MinTargetBrightness)
        {
            // Increase exposure time
            CurrentExposureTime += 2000; // Adjust step size as needed
        }
        else if (currentBrightness > MaxTargetBrightness)
        {
            // Decrease exposure time
            CurrentExposureTime -= 2000; // Adjust step size as needed
        }

        // Ensure the exposure time stays within the defined bounds
        CurrentExposureTime = Math.Clamp(CurrentExposureTime, MinExposureTime, MaxExposureTime);

        return CurrentExposureTime;
    }
}
