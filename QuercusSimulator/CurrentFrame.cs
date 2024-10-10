//using SixLabors.ImageSharp.PixelFormats;
//using SixLabors.ImageSharp;
//using System.Diagnostics;
//using System.Net.Sockets;
//using System.Net;
//using static QuercusSimulator.MessageBuilder;
//using Serilog;
//public static class CurrentFrame
//{
//    private const int MaxUdpSize = 65507;


//    //public static async Task GetAndSaveImages(
//    //uint cameraId,
//    //string cameraIP,
//    //int[] exposureTimes,
//    //int[] ids,
//    //string outputDirectory,
//    //int cameraSendPort = 6051,
//    //int cameraReceivePort = 6050)
//    //{
//    //    Log.Information("LPR Camera Image Capture and Brightness Calculation starting...");
//    //    Stopwatch stopwatch = new Stopwatch();
//    //    stopwatch.Start();

//    //    try
//    //    {
//    //        using (UdpClient udpClient = new UdpClient(new IPEndPoint(IPAddress.Any, cameraReceivePort)))
//    //        {
//    //            udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
//    //            udpClient.Client.ReceiveTimeout = 5000;
//    //            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(cameraIP), cameraSendPort);
//    //            Directory.CreateDirectory(outputDirectory);

//    //            List<(byte[] imageData, double brightness, int exposureTime)> images = new List<(byte[], double, int)>();

//    //            for (int i = 0; i < exposureTimes.Length; i++)
//    //            {
//    //                DateTime currentTime = DateTime.Now;
//    //                string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");
//    //                byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], cameraId);
//    //                await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//    //                Log.Information($"Request sent to camera for image {i + 1}");

//    //                byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//    //                Log.Information($"Received {imageData.Length} bytes of image data for image {i + 1}");

//    //                double brightness = await CalculateImageBrightness(imageData);
//    //                images.Add((imageData, brightness, exposureTimes[i]));
//    //                Log.Information($"Image {i + 1} processed");
//    //            }

//    //            var bestImage = GetBestImage(images);
//    //            string outputPath = await SaveImage(bestImage.imageData, DateTime.Now.ToString("yyyyMMdd_HHmmss"), bestImage.exposureTime, cameraId, cameraIP, outputDirectory);
//    //            Log.Information($"Best image saved: {outputPath}");
//    //        }
//    //    }
//    //    catch (SocketException ex)
//    //    {
//    //        Log.Error($"SocketException: {ex.Message}");
//    //        Log.Error($"ErrorCode: {ex.ErrorCode}");
//    //    }
//    //    catch (Exception ex)
//    //    {
//    //        Log.Error($"An unexpected error occurred: {ex.Message}");
//    //        Log.Error($"Stack trace: {ex.StackTrace}");
//    //    }
//    //    finally
//    //    {
//    //        stopwatch.Stop();
//    //        Log.Information($"Total time taken: {stopwatch.Elapsed}");
//    //    }
//    //}
//    public static async Task GetAndSaveImages(
//    uint cameraId,
//    string cameraIP,
//    int[] exposureTimes,
//    int[] ids,
//    string outputDirectory,
//    int cameraSendPort = 6051,
//    int cameraReceivePort = 6050)
//    {
//        Log.Information("LPR Camera Image Capture and Brightness Calculation starting...");
//        Stopwatch stopwatch = new Stopwatch();
//        stopwatch.Start();

//        const int maxRetries = 2;
//        const int retryDelay = 1000; // 1 second
//        const int overallTimeout = 1000; // 30 seconds

//        try
//        {
//            using (var cts = new CancellationTokenSource(overallTimeout))
//            using (UdpClient udpClient = new UdpClient())
//            {
//                udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
//                udpClient.Client.ReceiveTimeout = 5000;
//                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(cameraIP), cameraSendPort);
//                IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, cameraReceivePort);
//                udpClient.Client.Bind(localEndPoint);
//                Directory.CreateDirectory(outputDirectory);

//                List<(byte[] imageData, double brightness, int exposureTime)> images = new List<(byte[], double, int)>();

//                for (int i = 0; i < exposureTimes.Length; i++)
//                {
//                    bool success = false;
//                    for (int retry = 0; retry <= maxRetries && !success; retry++)
//                    {
//                        try
//                        {
//                            DateTime currentTime = DateTime.Now;
//                            string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");
//                            byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], cameraId);

//                            await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//                            Log.Information($"Request sent to camera for image {i + 1}, attempt {retry + 1}");

//                            byte[] imageData = await ReceiveCurrentFrameResponseAsyncWithTimeout(udpClient, cts.Token);
//                            Log.Information($"Received {imageData.Length} bytes of image data for image {i + 1}");

//                            double brightness = await CalculateImageBrightness(imageData);
//                            images.Add((imageData, brightness, exposureTimes[i]));
//                            Log.Information($"Image {i + 1} processed");

//                            success = true;
//                        }
//                        catch (OperationCanceledException)
//                        {
//                            Log.Warning("Operation timed out");
//                            throw;
//                        }
//                        catch (Exception ex)
//                        {
//                            Log.Warning($"Error occurred. Retrying. Attempt {retry + 1}. Error: {ex.Message}");
//                            if (retry == maxRetries)
//                            {
//                                throw;
//                            }
//                            await Task.Delay(retryDelay, cts.Token);
//                        }
//                    }

//                    if (!success)
//                    {
//                        Log.Error($"Failed to capture image {i + 1} after {maxRetries + 1} attempts");
//                    }
//                }

//                if (images.Count > 0)
//                {
//                    var bestImage = GetBestImage(images);
//                    string outputPath = await SaveImage(bestImage.imageData, DateTime.Now.ToString("yyyyMMdd_HHmmss"), bestImage.exposureTime, cameraId, cameraIP, outputDirectory);
//                    Log.Information($"Best image saved: {outputPath}");
//                }
//                else
//                {
//                    Log.Error("No images were successfully captured");
//                }
//            }
//        }
//        catch (OperationCanceledException)
//        {
//            Log.Error("The operation timed out");
//        }
//        catch (Exception ex)
//        {
//            Log.Error($"An unexpected error occurred: {ex.Message}");
//            Log.Error($"Stack trace: {ex.StackTrace}");
//        }
//        finally
//        {
//            stopwatch.Stop();
//            Log.Information($"Total time taken: {stopwatch.Elapsed}");
//        }
//    }

//    private static async Task<byte[]> ReceiveCurrentFrameResponseAsyncWithTimeout(UdpClient udpClient, CancellationToken cancellationToken)
//    {
//        var receiveTask = udpClient.ReceiveAsync(cancellationToken);

//        try
//        {
//            var result = await receiveTask;
//            byte[] response = result.Buffer;

//            if (response.Length < 21)
//                throw new Exception("Incomplete response received");
//            if (response[0] != 0x02)
//                throw new Exception("Invalid STX in response");

//            int totalSize = BitConverter.ToInt32(response, 5);
//            ushort messageType = BitConverter.ToUInt16(response, 9);
//            int imageSize = BitConverter.ToInt32(response, 17);

//            if (messageType != 136)
//                throw new Exception($"Unexpected message type: {messageType}");
//            if (imageSize <= 0 || imageSize > MaxUdpSize)
//                throw new Exception("Invalid or corrupted image size");
//            if (response.Length < totalSize)
//                throw new Exception("Incomplete message received");

//            byte[] imageData = new byte[imageSize];
//            Buffer.BlockCopy(response, 21, imageData, 0, imageSize);
//            return imageData;
//        }
//        catch (OperationCanceledException)
//        {
//            Log.Warning("Receive operation timed out");
//            throw;
//        }
//    }
//    //public static async Task GetAndSaveImages(
//    //uint cameraId,
//    //string cameraIP,
//    //int[] exposureTimes,
//    //int[] ids,
//    //string outputDirectory,
//    //int cameraSendPort = 6051,
//    //int cameraReceivePort = 6050)
//    //{
//    //    Log.Information("LPR Camera Image Capture and Brightness Calculation starting...");
//    //    Stopwatch stopwatch = new Stopwatch();
//    //    stopwatch.Start();

//    //    const int maxRetries = 2;
//    //    const int retryDelay = 1000; // 1 second

//    //    try
//    //    {
//    //        using (UdpClient udpClient = new UdpClient())
//    //        {
//    //            udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
//    //            udpClient.Client.ReceiveTimeout = 5000;
//    //            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(cameraIP), cameraSendPort);
//    //            IPEndPoint localEndPoint = new IPEndPoint(IPAddress.Any, cameraReceivePort);
//    //            udpClient.Client.Bind(localEndPoint);
//    //            Directory.CreateDirectory(outputDirectory);

//    //            List<(byte[] imageData, double brightness, int exposureTime)> images = new List<(byte[], double, int)>();

//    //            for (int i = 0; i < exposureTimes.Length; i++)
//    //            {
//    //                bool success = false;
//    //                for (int retry = 0; retry <= maxRetries && !success; retry++)
//    //                {
//    //                    try
//    //                    {
//    //                        DateTime currentTime = DateTime.Now;
//    //                        string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");
//    //                        byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], cameraId);

//    //                        await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//    //                        Log.Information($"Request sent to camera for image {i + 1}, attempt {retry + 1}");

//    //                        byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//    //                        Log.Information($"Received {imageData.Length} bytes of image data for image {i + 1}");

//    //                        double brightness = await CalculateImageBrightness(imageData);
//    //                        images.Add((imageData, brightness, exposureTimes[i]));
//    //                        Log.Information($"Image {i + 1} processed");

//    //                        success = true;
//    //                    }
//    //                    catch (SocketException ex)
//    //                    {
//    //                        Log.Warning($"SocketException occurred. Retrying. Attempt {retry + 1}. Error: {ex.Message}");
//    //                        if (retry == maxRetries)
//    //                        {
//    //                            //throw;
//    //                        }
//    //                        await Task.Delay(retryDelay);
//    //                    }
//    //                    catch (TimeoutException)
//    //                    {
//    //                        Log.Warning($"Timeout occurred while waiting for camera response. Attempt {retry + 1}");
//    //                        if (retry == maxRetries)
//    //                        {
//    //                            //throw;
//    //                        }
//    //                        await Task.Delay(retryDelay);
//    //                    }
//    //                    catch (Exception ex)
//    //                    {
//    //                        Log.Error($"Unexpected error occurred: {ex.Message}");
//    //                        if (retry == maxRetries)
//    //                        {
//    //                            //throw;
//    //                        }
//    //                        await Task.Delay(retryDelay);
//    //                    }
//    //                }

//    //                if (!success)
//    //                {
//    //                    Log.Error($"Failed to capture image {i + 1} after {maxRetries + 1} attempts");
//    //                }
//    //            }

//    //            if (images.Count > 0)
//    //            {
//    //                var bestImage = GetBestImage(images);
//    //                string outputPath = await SaveImage(bestImage.imageData, DateTime.Now.ToString("yyyyMMdd_HHmmss"), bestImage.exposureTime, cameraId, cameraIP, outputDirectory);
//    //                Log.Information($"Best image saved: {outputPath}");
//    //            }
//    //            else
//    //            {
//    //                Log.Error("No images were successfully captured");
//    //            }
//    //        }
//    //    }
//    //    catch (SocketException ex)
//    //    {
//    //        Log.Error($"SocketException: {ex.Message}");
//    //        Log.Error($"ErrorCode: {ex.ErrorCode}");
//    //        // Handle or rethrow as needed
//    //    }
//    //    catch (TimeoutException ex)
//    //    {
//    //        Log.Error($"TimeoutException: {ex.Message}");
//    //        // Handle or rethrow as needed
//    //    }
//    //    catch (Exception ex)
//    //    {
//    //        Log.Error($"An unexpected error occurred: {ex.Message}");
//    //        Log.Error($"Stack trace: {ex.StackTrace}");
//    //        // Handle or rethrow as needed
//    //    }
//    //    finally
//    //    {
//    //        stopwatch.Stop();
//    //        Log.Information($"Total time taken: {stopwatch.Elapsed}");
//    //    }
//    //}
//    //public static async Task GetAndSaveImages(
//    //uint cameraId,
//    //string cameraIP,
//    //int[] exposureTimes,
//    //int[] ids,
//    //string outputDirectory,
//    //int cameraSendPort = 6051,
//    //int cameraReceivePort = 6050)
//    //{
//    //    Log.Information("LPR Camera Image Capture and Brightness Calculation starting...");
//    //    Stopwatch stopwatch = new Stopwatch();
//    //    stopwatch.Start();

//    //    const int maxRetries = 2;
//    //    const int retryDelay = 1000; // 1 second

//    //    try
//    //    {
//    //        using (UdpClient udpClient = new UdpClient())
//    //        {
//    //            udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
//    //            udpClient.Client.ReceiveTimeout = 5000;
//    //            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(cameraIP), cameraSendPort);
//    //            Directory.CreateDirectory(outputDirectory);

//    //            List<(byte[] imageData, double brightness, int exposureTime)> images = new List<(byte[], double, int)>();

//    //            for (int i = 0; i < exposureTimes.Length; i++)
//    //            {
//    //                bool success = false;
//    //                for (int retry = 0; retry <= maxRetries && !success; retry++)
//    //                {
//    //                    try
//    //                    {
//    //                        DateTime currentTime = DateTime.Now;
//    //                        string timestamp = currentTime.ToString("yyyyMMdd_HHmmss");
//    //                        byte[] request = CreateCurrentFrameRequest(exposureTimes[i], ids[i], cameraId);

//    //                        // Bind to a new port for each attempt
//    //                        udpClient.Client.Bind(new IPEndPoint(IPAddress.Any, 0));

//    //                        await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//    //                        Log.Information($"Request sent to camera for image {i + 1}, attempt {retry + 1}");

//    //                        byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//    //                        Log.Information($"Received {imageData.Length} bytes of image data for image {i + 1}");

//    //                        double brightness = await CalculateImageBrightness(imageData);
//    //                        images.Add((imageData, brightness, exposureTimes[i]));
//    //                        Log.Information($"Image {i + 1} processed");

//    //                        success = true;
//    //                    }
//    //                    catch (SocketException ex) when (ex.ErrorCode == 10048)
//    //                    {
//    //                        Log.Warning($"Port already in use. Retrying with a new port. Attempt {retry + 1}");
//    //                        if (retry == maxRetries)
//    //                        {
//    //                            throw;
//    //                        }
//    //                        await Task.Delay(retryDelay);
//    //                    }
//    //                    catch (TimeoutException)
//    //                    {
//    //                        Log.Warning($"Timeout occurred while waiting for camera response. Attempt {retry + 1}");
//    //                        if (retry == maxRetries)
//    //                        {
//    //                            throw;
//    //                        }
//    //                        await Task.Delay(retryDelay);
//    //                    }
//    //                }
//    //            }

//    //            var bestImage = GetBestImage(images);
//    //            string outputPath = await SaveImage(bestImage.imageData, DateTime.Now.ToString("yyyyMMdd_HHmmss"), bestImage.exposureTime, cameraId, cameraIP, outputDirectory);
//    //            Log.Information($"Best image saved: {outputPath}");
//    //        }
//    //    }
//    //    catch (SocketException ex)
//    //    {
//    //        Log.Error($"SocketException: {ex.Message}");
//    //        Log.Error($"ErrorCode: {ex.ErrorCode}");
//    //        // Handle or rethrow as needed
//    //    }
//    //    catch (TimeoutException ex)
//    //    {
//    //        Log.Error($"TimeoutException: {ex.Message}");
//    //        // Handle or rethrow as needed
//    //    }
//    //    catch (Exception ex)
//    //    {
//    //        Log.Error($"An unexpected error occurred: {ex.Message}");
//    //        Log.Error($"Stack trace: {ex.StackTrace}");
//    //        // Handle or rethrow as needed
//    //    }
//    //    finally
//    //    {
//    //        stopwatch.Stop();
//    //        Log.Information($"Total time taken: {stopwatch.Elapsed}");
//    //    }
//    //}


//    private static (byte[] imageData, int exposureTime) GetBestImage(List<(byte[] imageData, double brightness, int exposureTime)> images)
//    {
//        const double targetBrightness = 0.35;
//        var bestImage = images.OrderBy(img => Math.Abs(img.brightness - targetBrightness)).First();
//        return (bestImage.imageData, bestImage.exposureTime);
//    }


//    private static async Task<string> SaveImage(byte[] imageData, string timestamp, int exposureTime, uint UnitId, string CameraIP, string OutputDirectory)
//    {
//        using (MemoryStream ms = new MemoryStream(imageData))
//        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
//        {
//            string lastOctet = CameraIP.Split('.').Last();
//            string fileName = $"lastimage_{lastOctet}.jpg";
//            string outputPath = Path.Combine(OutputDirectory, fileName);
//            await image.SaveAsJpegAsync(outputPath);
//            return outputPath;
//        }
//    }

//    private static async Task<double> CalculateImageBrightness(byte[] imageData)
//    {
//        using (MemoryStream ms = new MemoryStream(imageData))
//        using (Image<Rgba32> image = Image.Load<Rgba32>(ms))
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