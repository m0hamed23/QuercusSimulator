
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class LPRCameraImageCapture
{
    private const string CameraIP = "10.0.0.110";
    private const int CameraSendPort = 6051; // Camera send port
    private const int CameraReceivePort = 6050; // Port to receive image
    private const string OutputPath = @"D:\currentimage.jpg";
    private const int MaxUdpSize = 65507; // Maximum UDP packet size
    static async Task Main(string[] args)
    {
        Console.WriteLine("LPR Camera Image Capture starting...");

        try
        {
            using (UdpClient udpClient = new UdpClient(CameraReceivePort)) // Bind to port 6050 for receiving
            {
                udpClient.Client.ReceiveTimeout = 5000; // 5 second timeout
                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraSendPort);

                Console.WriteLine($"Sending request to camera at {CameraIP}:{CameraSendPort}");

                // Create the request to get the current frame
                byte[] request = CreateCurrentFrameRequest();

                // Start the stopwatch to measure time
                Stopwatch stopwatch = Stopwatch.StartNew();

                // Send the request to the camera
                await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                Console.WriteLine("Request sent to camera");

                // Receive the image data
                byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);

                // Stop the stopwatch after receiving the response
                stopwatch.Stop();
                Console.WriteLine($"Received {imageData.Length} bytes of image data");

                // Calculate elapsed time
                long elapsedMilliseconds = stopwatch.ElapsedMilliseconds;
                Console.WriteLine($"Image retrieval took {elapsedMilliseconds} ms");

                // Save the image
                Directory.CreateDirectory(Path.GetDirectoryName(OutputPath));
                await File.WriteAllBytesAsync(OutputPath, imageData);
                Console.WriteLine($"Image saved to {OutputPath}");
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
    }

    private static byte[] CreateCurrentFrameRequest()
    {
        byte[] request = new byte[23];

        request[0] = 0x02; // STX (1 byte)

        byte[] unitIdBytes = BitConverter.GetBytes(1);
        byte[] sizeBytes = BitConverter.GetBytes(23);
        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
        byte[] idBytes = BitConverter.GetBytes(10);
        byte[] exposureTimeBytes = BitConverter.GetBytes(16000);

        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(unitIdBytes);
            Array.Reverse(sizeBytes);
            Array.Reverse(typeBytes);
            Array.Reverse(versionBytes);
            Array.Reverse(idBytes);
            Array.Reverse(exposureTimeBytes);
        }

        unitIdBytes.CopyTo(request, 1);       // Unit ID (4 bytes)
        sizeBytes.CopyTo(request, 5);         // Size (4 bytes)
        typeBytes.CopyTo(request, 9);         // Type (2 bytes)
        versionBytes.CopyTo(request, 11);     // Version (2 bytes)
        idBytes.CopyTo(request, 13);          // ID (4 bytes)
        exposureTimeBytes.CopyTo(request, 17);// Exposure Time (4 bytes)

        request[21] = CalculateXOR(request, 0, 21); // BCC (1 byte)
        request[22] = 0x03; // ETX (1 byte)

        return request;
    }

    private static async Task<byte[]> ReceiveCurrentFrameResponseAsync(UdpClient udpClient)
    {
        IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

        // Receive the response in one chunk (assuming the total response is less than MaxUdpSize)
        UdpReceiveResult result = await udpClient.ReceiveAsync();
        byte[] response = result.Buffer;

        // Ensure the response is at least 21 bytes (for the header)
        if (response.Length < 21)
        {
            throw new Exception("Incomplete response received");
        }

        // Validate the STX (Start of Text)
        if (response[0] != 0x02)
        {
            throw new Exception("Invalid STX in response");
        }

        // Extract and validate fields from the header using little-endian format
        int totalSize = BitConverter.ToInt32(response, 5);  // Total message size (offset 5-8)
        ushort messageType = BitConverter.ToUInt16(response, 9);  // Message type (offset 9-10)
        int imageSize = BitConverter.ToInt32(response, 17);  // Image size (offset 17-20)

        // Validate the message type and image size
        if (messageType != 136)
        {
            throw new Exception($"Unexpected message type: {messageType}");
        }

        if (imageSize <= 0 || imageSize > MaxUdpSize)
        {
            throw new Exception("Invalid or corrupted image size");
        }

        Console.WriteLine($"Total message size: {totalSize} bytes");
        Console.WriteLine($"Image size: {imageSize} bytes");

        // Ensure the response contains the expected amount of data
        if (response.Length < totalSize)
        {
            throw new Exception("Incomplete message received");
        }

        // Extract the image data (excluding the header and last 2 bytes BCC and ETX)
        byte[] imageData = new byte[imageSize];
        Buffer.BlockCopy(response, 21, imageData, 0, imageSize); // Copy image data starting at byte 21

        Console.WriteLine($"Total received: {response.Length} bytes, Image saved.");

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
}
