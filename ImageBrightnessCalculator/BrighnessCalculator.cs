using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

class LPRCameraImageCaptureAndBrightness
{
    private const string CameraIP = "10.0.0.110";
    private const int CameraSendPort = 6051;
    private const int CameraReceivePort = 6050;
    private const string OutputDirectory = @"D:\frames";
    private const string DataLogFile = @"D:\image_data_log2.txt";
    private const int MaxUdpSize = 65507;
    private const int UnitId = 1;

    static async Task Main(string[] args)
    {
        Console.WriteLine("LPR Camera Image Capture and Brightness Calculation starting...");

        //int[] exposureTimes = { 1000, 4000, 8000, 16000, 20000, 23000, 26000, 30000, 60000, 75000, 100000, 110000, 125000, 150000, 175000, 200000, 225000, 250000 };
        //int[] ids = { 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154 };
        int[] exposureTimes = { 75000,200000, 500000 };
        int[] ids = { 120, 122, 124 };

        Stopwatch stopwatch = new Stopwatch(); // Add this line
        stopwatch.Start(); // Add this line

        try
        {
            using (UdpClient udpClient = new UdpClient(CameraReceivePort))
            {
                udpClient.Client.ReceiveTimeout = 5000;
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraSendPort);

                Directory.CreateDirectory(OutputDirectory);
                File.WriteAllText(DataLogFile, "UnitID,Timestamp,ExposureTime,Brightness,FilePath\n");

                for (int i = 0; i < 18; i++)
                {
                    DateTime currentTime = DateTime.Now;
                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");

                    byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i]);
                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                    Console.WriteLine($"Request sent to camera for image {i + 1}");

                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
                    Console.WriteLine($"Received {imageData.Length} bytes of image data for image {i + 1}");

                    string outputPath = await SaveImageAndCalculateBrightness(imageData, timestamp, exposureTimes[i]);
                    Console.WriteLine($"Image {i + 1} processed and saved");

                    Console.WriteLine();
                }
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
            stopwatch.Stop(); // Add this line
            Console.WriteLine($"Total time taken: {stopwatch.Elapsed}"); // Add this line
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
        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
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

//using System;
//using System.Collections.Generic;
//using System.Diagnostics;
//using System.IO;
//using System.Net;
//using System.Net.Sockets;
//using System.Threading.Tasks;
//using SixLabors.ImageSharp;
//using SixLabors.ImageSharp.PixelFormats;
//using SixLabors.ImageSharp.Processing;

//class LPRCameraImageCaptureAndBrightness
//{
//    private const string DataLogFile = @"D:\image_data_log2.txt";
//    private const int MaxUdpSize = 65507;

//    private class CameraInfo
//    {
//        public int UnitId { get; set; }
//        public string IP { get; set; }
//        public int SendPort { get; set; }
//        public int ReceivePort { get; set; }
//        public string OutputDirectory { get; set; }
//    }

//    private static List<CameraInfo> cameras = new List<CameraInfo>
//    {
//        new CameraInfo { UnitId = 1, IP = "10.0.0.101", SendPort = 7051, ReceivePort = 7050, OutputDirectory = @"D:\frames1" },
//        new CameraInfo { UnitId = 2, IP = "10.0.0.181", SendPort = 7051, ReceivePort = 7050, OutputDirectory = @"D:\frames2" },
//        new CameraInfo { UnitId = 3, IP = "10.0.0.182", SendPort = 6051, ReceivePort = 6050, OutputDirectory = @"D:\frames3" }
//    };

//    static async Task Main(string[] args)
//    {
//        Console.WriteLine("Multi-Camera LPR Image Capture and Brightness Calculation starting...");

//        int[] exposureTimes = { 1000, 4000, 8000, 16000, 20000, 23000, 26000, 30000, 60000, 75000, 100000, 150000, 175000, 200000, 250000, 300000, 400000, 500000 };
//        int[] ids = { 120, 122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154 };

//        while (true)
//        {
//            Stopwatch stopwatch = new Stopwatch();
//            stopwatch.Start();

//            try
//            {
//                foreach (var camera in cameras)
//                {
//                    await ProcessCamera(camera, exposureTimes, ids);
//                }
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
//                Console.WriteLine($"Stack trace: {ex.StackTrace}");
//            }
//            finally
//            {
//                stopwatch.Stop();
//                Console.WriteLine($"Total time taken for all cameras: {stopwatch.Elapsed}");
//            }

//            // Wait for 15 minutes before the next round
//            await Task.Delay(TimeSpan.FromMinutes(15));
//        }
//    }

//    private static async Task ProcessCamera(CameraInfo camera, int[] exposureTimes, int[] ids)
//    {
//        Console.WriteLine($"Processing camera {camera.UnitId}...");

//        try
//        {
//            using (UdpClient udpClient = new UdpClient(camera.ReceivePort))
//            {
//                udpClient.Client.ReceiveTimeout = 5000;
//                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(camera.IP), camera.SendPort);

//                Directory.CreateDirectory(camera.OutputDirectory);

//                for (int i = 0; i < 18; i++)
//                {
//                    DateTime currentTime = DateTime.Now;
//                    string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");

//                    byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], camera.UnitId);
//                    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//                    Console.WriteLine($"Request sent to camera {camera.UnitId} for image {i + 1}");

//                    byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//                    Console.WriteLine($"Received {imageData.Length} bytes of image data for camera {camera.UnitId}, image {i + 1}");

//                    string outputPath = await SaveImageAndCalculateBrightness(imageData, timestamp, exposureTimes[i], camera);
//                    Console.WriteLine($"Image {i + 1} processed and saved for camera {camera.UnitId}");

//                    Console.WriteLine();
//                }
//            }
//        }
//        catch (SocketException ex)
//        {
//            Console.WriteLine($"SocketException for camera {camera.UnitId}: {ex.Message}");
//            Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
//        }
//    }

//    private static byte[] CreateCurrentFrameRequest(int exposureTime, int id, int unitId)
//    {
//        byte[] request = new byte[23];

//        request[0] = 0x02; // STX

//        byte[] unitIdBytes = BitConverter.GetBytes(unitId);
//        byte[] sizeBytes = BitConverter.GetBytes(23);
//        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
//        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
//        byte[] idBytes = BitConverter.GetBytes(id);
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

//    private static async Task<string> SaveImageAndCalculateBrightness(byte[] imageData, string timestamp, int exposureTime, CameraInfo camera)
//    {
//        using (MemoryStream ms = new MemoryStream(imageData))
//        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
//        {
//            double brightness = CalculateImageBrightness(image);

//            string fileName = $"{camera.UnitId}_{timestamp}_{exposureTime}_{brightness:F4}.jpg";
//            string outputPath = Path.Combine(camera.OutputDirectory, fileName);

//            await image.SaveAsJpegAsync(outputPath);

//            string logEntry = $"{camera.UnitId},{timestamp},{exposureTime},{brightness:F4},{outputPath}\n";
//            await File.AppendAllTextAsync(DataLogFile, logEntry);

//            return outputPath;
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
//}

