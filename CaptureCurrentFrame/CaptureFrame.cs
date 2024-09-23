////using System;
////using System.IO;
////using System.Net;
////using System.Net.Sockets;
////using System.Threading.Tasks;

////class LPRCameraImageCapture
////{
////    private const string CameraIP = "10.0.0.110";
////    private const int CameraPort = 6051;
////    private const string OutputPath = @"D:\currentimage.jpg";
////    private const int MaxUdpSize = 65507; // Maximum UDP packet size


////    static async Task Main(string[] args)
////    {
////        Console.WriteLine("LPR Camera Image Capture starting...");

////        try
////        {
////            using (UdpClient udpClient = new UdpClient())
////            {
////                udpClient.Client.ReceiveTimeout = 5000; // 5 second timeout
////                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraPort);
////                udpClient.Connect(remoteEndPoint);

////                Console.WriteLine($"Sending request to camera at {CameraIP}:{CameraPort}");

////                // Send CurrentFrame request
////                byte[] request = CreateCurrentFrameRequest();
////                await udpClient.SendAsync(request, request.Length);
////                Console.WriteLine("Request sent to camera");

////                // Receive and process the response
////                byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
////                Console.WriteLine($"Received {imageData.Length} bytes of image data");

////                // Save the image
////                Directory.CreateDirectory(Path.GetDirectoryName(OutputPath));
////                await File.WriteAllBytesAsync(OutputPath, imageData);
////                Console.WriteLine($"Image saved to {OutputPath}");
////            }
////        }
////        catch (SocketException ex)
////        {
////            Console.WriteLine($"SocketException: {ex.Message}");
////            Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
////        }
////        catch (Exception ex)
////        {
////            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
////            Console.WriteLine($"Stack trace: {ex.StackTrace}");
////        }
////    }
////    private static byte[] CreateCurrentFrameRequest()
////    {
////        byte[] request = new byte[23];

////        request[0] = 0x02; // STX (1 byte)

////        byte[] unitIdBytes = BitConverter.GetBytes(1);
////        byte[] sizeBytes = BitConverter.GetBytes(23);
////        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
////        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
////        byte[] idBytes = BitConverter.GetBytes(12);
////        byte[] exposureTimeBytes = BitConverter.GetBytes(1000);

////        if (!BitConverter.IsLittleEndian)
////        {
////            Array.Reverse(unitIdBytes);
////            Array.Reverse(sizeBytes);
////            Array.Reverse(typeBytes);
////            Array.Reverse(versionBytes);
////            Array.Reverse(idBytes);
////            Array.Reverse(exposureTimeBytes);
////        }

////        unitIdBytes.CopyTo(request, 1);       // Unit ID (4 bytes)
////        sizeBytes.CopyTo(request, 5);         // Size (4 bytes)
////        typeBytes.CopyTo(request, 9);         // Type (2 bytes)
////        versionBytes.CopyTo(request, 11);     // Version (2 bytes)
////        idBytes.CopyTo(request, 13);          // ID (4 bytes)
////        exposureTimeBytes.CopyTo(request, 17);// Exposure Time (4 bytes)

////        request[21] = CalculateXOR(request, 0, 21); // BCC (1 byte)
////        request[22] = 0x03; // ETX (1 byte)

////        return request;
////    }

////    private static async Task<byte[]> ReceiveCurrentFrameResponseAsync(UdpClient udpClient)
////    {
////        using (MemoryStream imageStream = new MemoryStream())
////        {
////            byte[] header = new byte[23]; // 23 bytes for the header up to Image Size
////            int receivedBytes = 0;

////            while (receivedBytes < header.Length)
////            {
////                UdpReceiveResult result = await udpClient.ReceiveAsync();
////                int bytesToCopy = Math.Min(header.Length - receivedBytes, result.Buffer.Length);
////                Buffer.BlockCopy(result.Buffer, 0, header, receivedBytes, bytesToCopy);
////                receivedBytes += bytesToCopy;

////                if (bytesToCopy < result.Buffer.Length)
////                {
////                    // If we have extra data beyond the header, start writing to the imageStream
////                    imageStream.Write(result.Buffer, bytesToCopy, result.Buffer.Length - bytesToCopy);
////                }
////            }

////            // Validate the header
////            if (header[0] != 0x02 || BitConverter.ToUInt16(header, 9) != 136)
////            {
////                throw new Exception("Invalid response format");
////            }

////            int totalSize = BitConverter.ToInt32(header, 5);
////            int imageSize = BitConverter.ToInt32(header, 19);
////            Console.WriteLine($"Total message size: {totalSize} bytes");
////            Console.WriteLine($"Image size: {imageSize} bytes");

////            // Continue receiving the rest of the image data
////            while (imageStream.Length < imageSize)
////            {
////                UdpReceiveResult result = await udpClient.ReceiveAsync();
////                imageStream.Write(result.Buffer, 0, result.Buffer.Length);
////                Console.WriteLine($"Received {result.Buffer.Length} bytes, total: {imageStream.Length}/{imageSize}");
////            }

////            // The last two bytes should be BCC and ETX, so we remove them
////            imageStream.SetLength(imageStream.Length - 2);

////            Console.WriteLine($"Total received: {imageStream.Length} bytes");

////            return imageStream.ToArray();
////        }
////    }
////    private static byte CalculateXOR(byte[] data, int start, int length)
////    {
////        byte xor = 0;
////        for (int i = start; i < start + length; i++)
////        {
////            xor ^= data[i];
////        }
////        return xor;
////    }
////}

//using System;
//using System.IO;
//using System.Net;
//using System.Net.Sockets;
//using System.Threading.Tasks;

//class LPRCameraImageCapture
//{
//    private const string CameraIP = "10.0.0.110";
//    private const int CameraSendPort = 6051; // Camera send port
//    private const int CameraReceivePort = 6050; // Port to receive image
//    private const string OutputPath = @"D:\currentimage.jpg";
//    private const int MaxUdpSize = 65507; // Maximum UDP packet size

//    static async Task Main(string[] args)
//    {
//        Console.WriteLine("LPR Camera Image Capture starting...");

//        try
//        {
//            using (UdpClient udpClient = new UdpClient(CameraReceivePort)) // Bind to port 6050 for receiving
//            {
//                udpClient.Client.ReceiveTimeout = 5000; // 5 second timeout
//                IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraSendPort);

//                Console.WriteLine($"Sending request to camera at {CameraIP}:{CameraSendPort}");

//                // Send CurrentFrame request
//                byte[] request = CreateCurrentFrameRequest();
//                await udpClient.SendAsync(request, request.Length, remoteEndPoint); // Send request to camera
//                Console.WriteLine("Request sent to camera");

//                // Receive and process the response
//                byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
//                Console.WriteLine($"Received {imageData.Length} bytes of image data");

//                // Save the image
//                Directory.CreateDirectory(Path.GetDirectoryName(OutputPath));
//                await File.WriteAllBytesAsync(OutputPath, imageData);
//                Console.WriteLine($"Image saved to {OutputPath}");
//            }
//        }
//        catch (SocketException ex)
//        {
//            Console.WriteLine($"SocketException: {ex.Message}");
//            Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
//        }
//        catch (Exception ex)
//        {
//            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
//            Console.WriteLine($"Stack trace: {ex.StackTrace}");
//        }
//    }

//    private static byte[] CreateCurrentFrameRequest()
//    {
//        byte[] request = new byte[23];

//        request[0] = 0x02; // STX (1 byte)

//        byte[] unitIdBytes = BitConverter.GetBytes(1);
//        byte[] sizeBytes = BitConverter.GetBytes(23);
//        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
//        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
//        byte[] idBytes = BitConverter.GetBytes(12);
//        byte[] exposureTimeBytes = BitConverter.GetBytes(1000);

//        if (!BitConverter.IsLittleEndian)
//        {
//            Array.Reverse(unitIdBytes);
//            Array.Reverse(sizeBytes);
//            Array.Reverse(typeBytes);
//            Array.Reverse(versionBytes);
//            Array.Reverse(idBytes);
//            Array.Reverse(exposureTimeBytes);
//        }

//        unitIdBytes.CopyTo(request, 1);       // Unit ID (4 bytes)
//        sizeBytes.CopyTo(request, 5);         // Size (4 bytes)
//        typeBytes.CopyTo(request, 9);         // Type (2 bytes)
//        versionBytes.CopyTo(request, 11);     // Version (2 bytes)
//        idBytes.CopyTo(request, 13);          // ID (4 bytes)
//        exposureTimeBytes.CopyTo(request, 17);// Exposure Time (4 bytes)

//        request[21] = CalculateXOR(request, 0, 21); // BCC (1 byte)
//        request[22] = 0x03; // ETX (1 byte)

//        return request;
//    }

//    private static async Task<byte[]> ReceiveCurrentFrameResponseAsync(UdpClient udpClient)
//    {
//        using (MemoryStream imageStream = new MemoryStream())
//        {
//            byte[] header = new byte[23]; // 23 bytes for the header up to Image Size
//            int receivedBytes = 0;

//            while (receivedBytes < header.Length)
//            {
//                UdpReceiveResult result = await udpClient.ReceiveAsync();
//                int bytesToCopy = Math.Min(header.Length - receivedBytes, result.Buffer.Length);
//                Buffer.BlockCopy(result.Buffer, 0, header, receivedBytes, bytesToCopy);
//                receivedBytes += bytesToCopy;

//                if (bytesToCopy < result.Buffer.Length)
//                {
//                    // If we have extra data beyond the header, start writing to the imageStream
//                    imageStream.Write(result.Buffer, bytesToCopy, result.Buffer.Length - bytesToCopy);
//                }
//            }

//            // Validate the header
//            if (header[0] != 0x02 || BitConverter.ToUInt16(header, 9) != 136)
//            {
//                throw new Exception("Invalid response format");
//            }

//            int totalSize = BitConverter.ToInt32(header, 5);
//            int imageSize = BitConverter.ToInt32(header, 19);
//            Console.WriteLine($"Total message size: {totalSize} bytes");
//            Console.WriteLine($"Image size: {imageSize} bytes");

//            // Continue receiving the rest of the image data
//            while (imageStream.Length < imageSize)
//            {
//                UdpReceiveResult result = await udpClient.ReceiveAsync();
//                imageStream.Write(result.Buffer, 0, result.Buffer.Length);
//                Console.WriteLine($"Received {result.Buffer.Length} bytes, total: {imageStream.Length}/{imageSize}");
//            }

//            // The last two bytes should be BCC and ETX, so we remove them
//            imageStream.SetLength(imageStream.Length - 2);

//            Console.WriteLine($"Total received: {imageStream.Length} bytes");

//            return imageStream.ToArray();
//        }
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
//}
using System;
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
                
                // Example usage for activating the LED
                //byte[] activateFocusRequest = CreateActivateFocusRequest(5);
                //await SendActivateFocusRequestAsync("10.0.0.110", 6051, activateFocusRequest);

                //// Activate the LED
                //Console.WriteLine("Activating the LED panel...");
                //byte[] activateFocusRequest = CreateActivateFocusRequest(2); // Activate for 5 seconds
                //await udpClient.SendAsync(activateFocusRequest, activateFocusRequest.Length);
                //Console.WriteLine("LED panel activated for 5 seconds");

                // Wait briefly to allow the LED to activate
                //await Task.Delay(500);

                // Send CurrentFrame request
                byte[] request = CreateCurrentFrameRequest();
                await udpClient.SendAsync(request, request.Length, remoteEndPoint); // Send request to camera
                Console.WriteLine("Request sent to camera");

                // Receive and process the response
                byte[] imageData = await ReceiveCurrentFrameResponseAsync(udpClient);
                Console.WriteLine($"Received {imageData.Length} bytes of image data");

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
    private static async Task SendActivateFocusRequestAsync(string ipAddress, int port, byte[] request)
    {
        using (UdpClient udpClient = new UdpClient())
        {
            // Send the request to the specified IP and port
            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(ipAddress), port);

            try
            {
                // Sending the request
                Console.WriteLine($"Sending ActivateFocusRequest to {ipAddress}:{port}...");
                await udpClient.SendAsync(request, request.Length, remoteEndPoint);
                Console.WriteLine("Request sent successfully.");
            }
            catch (SocketException ex)
            {
                Console.WriteLine($"SocketException: {ex.Message}");
                Console.WriteLine($"ErrorCode: {ex.ErrorCode}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An unexpected error occurred: {ex.Message}");
            }
        }
    }

    private static byte[] CreateActivateFocusRequest(int timeInSeconds)
    {
        byte[] request = new byte[21]; // Total size of the message

        request[0] = 0x02; // STX (1 byte)

        // Unit ID (4 bytes, little-endian)
        byte[] unitIdBytes = BitConverter.GetBytes(1);
        // Total Size (4 bytes, little-endian)
        byte[] sizeBytes = BitConverter.GetBytes(21);
        // Type (2 bytes, little-endian, type 73 for ActivateFocus)
        byte[] typeBytes = BitConverter.GetBytes((ushort)73);
        // Version (2 bytes, little-endian, version 0)
        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
        // ID (4 bytes, little-endian, unique ID for the message, e.g., 12)
        byte[] idBytes = BitConverter.GetBytes(2);
        // Time (4 bytes, little-endian, duration for LED activation in seconds)
        byte[] timeBytes = BitConverter.GetBytes(timeInSeconds);

        if (!BitConverter.IsLittleEndian)
        {
            Array.Reverse(unitIdBytes);
            Array.Reverse(sizeBytes);
            Array.Reverse(typeBytes);
            Array.Reverse(versionBytes);
            Array.Reverse(idBytes);
            Array.Reverse(timeBytes);
        }

        // Copy data to the request
        unitIdBytes.CopyTo(request, 1);       // Unit ID (4 bytes) at offset 1
        sizeBytes.CopyTo(request, 5);         // Size (4 bytes) at offset 5
        typeBytes.CopyTo(request, 9);         // Type (2 bytes) at offset 9
        versionBytes.CopyTo(request, 11);     // Version (2 bytes) at offset 11
        idBytes.CopyTo(request, 13);          // ID (4 bytes) at offset 13
        timeBytes.CopyTo(request, 17);        // Time (4 bytes) at offset 17

        // Calculate BCC (XOR of all bytes from STX to the last data byte)
        request[19] = CalculateXOR(request, 0, 19); // BCC at offset 19

        // ETX (1 byte) at offset 20
        request[20] = 0x03;

        return request;
    }

    private static byte[] CreateCurrentFrameRequest()
    {
        byte[] request = new byte[23];

        request[0] = 0x02; // STX (1 byte)

        byte[] unitIdBytes = BitConverter.GetBytes(1);
        byte[] sizeBytes = BitConverter.GetBytes(23);
        byte[] typeBytes = BitConverter.GetBytes((ushort)72);
        byte[] versionBytes = BitConverter.GetBytes((ushort)0);
        byte[] idBytes = BitConverter.GetBytes(98);
        byte[] exposureTimeBytes = BitConverter.GetBytes(100000);

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

    // Helper method to reverse byte order (endianness) for 4-byte integers
    private static int ReverseBytes(int value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        Array.Reverse(bytes);
        return BitConverter.ToInt32(bytes, 0);
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
