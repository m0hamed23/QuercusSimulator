using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class CameraGetPictureSender
{
    private const string CameraIP = "10.0.0.110";
    private const int CameraPort = 6051;
    private const int LocalPort = 6050;  // Using a different local port to avoid conflicts

    static async Task Main(string[] args)
    {
        Console.WriteLine("Camera GetPicture Sender");
        Console.WriteLine($"Target Camera: {CameraIP}:{CameraPort}");
        Console.WriteLine($"Listening for responses on local port: {LocalPort}");

        uint unitId = 1;
        uint id = 2; // Starting with 2 for messages sent by the central system
        uint carId = 50; // As per the request

        using var udpClient = new UdpClient(LocalPort);

        while (true)
        {
            Console.Write("Press Enter to send a GetPicture request (or type 'exit' to quit): ");
            string input = Console.ReadLine();

            if (input.ToLower() == "exit")
                break;

            try
            {
                IPEndPoint cameraEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraPort);
                await SendGetPictureRequestAsync(udpClient, cameraEndPoint, unitId, id, carId);
                Console.WriteLine($"GetPicture request sent for Car ID: {carId}");

                // Wait for and process the response
                var response = await ReceiveResponseAsync(udpClient);
                ProcessResponse(response);

                id += 2; // Increment by 2 for each new message
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        Console.WriteLine("Exiting program.");
    }

    private static async Task SendGetPictureRequestAsync(UdpClient udpClient, IPEndPoint remoteEndPoint, uint unitId, uint id, uint carId)
    {
        byte[] request = new byte[23];
        request[0] = 0x02; // STX

        // UnitId (4 bytes, little endian)
        BitConverter.GetBytes(unitId).CopyTo(request, 1);

        // Size (4 bytes, little endian, always 23)
        BitConverter.GetBytes(23).CopyTo(request, 5);

        // Type (2 bytes, little endian, 71 for GetPicture)
        BitConverter.GetBytes((ushort)71).CopyTo(request, 9);

        // Version (2 bytes, little endian, make it 0)
        BitConverter.GetBytes((ushort)0).CopyTo(request, 11);

        // ID (4 bytes, little endian, parameter)
        BitConverter.GetBytes(id).CopyTo(request, 13);

        // Car Id (4 bytes, little endian, parameter)
        BitConverter.GetBytes(carId).CopyTo(request, 17);

        // Calculate BCC (XOR from STX to the last data byte before ETX)
        request[21] = CalculateXOR(request, 0, 21);

        request[22] = 0x03; // ETX

        await udpClient.SendAsync(request, request.Length, remoteEndPoint);
        Console.WriteLine($"Raw request sent (hex): {BitConverter.ToString(request).Replace("-", "")}");
    }

    private static async Task<byte[]> ReceiveResponseAsync(UdpClient udpClient)
    {
        Console.WriteLine("Waiting for response...");
        UdpReceiveResult result = await udpClient.ReceiveAsync();
        Console.WriteLine($"Received {result.Buffer.Length} bytes from {result.RemoteEndPoint}");
        return result.Buffer;
    }

    //private static void ProcessResponse(byte[] response)
    //{
    //    if (response.Length < 23)
    //    {
    //        Console.WriteLine("Response too short to contain a valid image message.");
    //        return;
    //    }

    //    ushort messageType = BitConverter.ToUInt16(response, 9);
    //    Console.WriteLine($"Response Message Type: {messageType}");

    //    // Check if the message type is 135, which indicates a GetPicture response
    //    if (messageType == 135)
    //    {
    //        // Extract ROI coordinates
    //        ushort roiTop = BitConverter.ToUInt16(response, 13);
    //        ushort roiLeft = BitConverter.ToUInt16(response, 15);
    //        ushort roiBottom = BitConverter.ToUInt16(response, 17);
    //        ushort roiRight = BitConverter.ToUInt16(response, 19);

    //        Console.WriteLine($"ROI - Top: {roiTop}, Left: {roiLeft}, Bottom: {roiBottom}, Right: {roiRight}");

    //        // Extract Image Size
    //        uint imageSize = BitConverter.ToUInt32(response, 21);
    //        Console.WriteLine($"Image Size: {imageSize} bytes");

    //        if (imageSize > 0)
    //        {
    //            // Extract image data (starts at index 25, length is imageSize)
    //            byte[] imageData = new byte[imageSize];
    //            Array.Copy(response, 25, imageData, 0, imageSize);

    //            // Save image data to file on D: drive
    //            string filePath = $@"D:\CapturedImage_{DateTime.Now:yyyyMMdd_HHmmss}.jpg";
    //            System.IO.File.WriteAllBytes(filePath, imageData);

    //            Console.WriteLine($"Image data saved to: {filePath}");
    //        }
    //        else
    //        {
    //            Console.WriteLine("No image available in the response.");
    //        }
    //    }
    //    else
    //    {
    //        Console.WriteLine("Unexpected message type received.");
    //    }

    //    Console.WriteLine($"Raw response (hex): {BitConverter.ToString(response).Replace("-", "")}");
    //}
    private static void ProcessResponse(byte[] response)
    {
        if (response.Length < 23)
        {
            Console.WriteLine("Response too short to contain a valid message.");
            return;
        }

        uint unitId = BitConverter.ToUInt32(response, 1);
        uint size = BitConverter.ToUInt32(response, 5);
        ushort messageType = BitConverter.ToUInt16(response, 9);
        ushort version = BitConverter.ToUInt16(response, 11);
        uint id = BitConverter.ToUInt32(response, 13);

        Console.WriteLine($"Response Message Type: {messageType}");
        Console.WriteLine($"Unit ID: {unitId}, Size: {size}, Version: {version}, ID: {id}");

        // Check if the message type is 135, which indicates a GetPicture response
        if (messageType == 135)
        {
            // Extract ROI coordinates
            ushort roiTop = BitConverter.ToUInt16(response, 17);
            ushort roiLeft = BitConverter.ToUInt16(response, 19);
            ushort roiBottom = BitConverter.ToUInt16(response, 21);
            ushort roiRight = BitConverter.ToUInt16(response, 23);

            Console.WriteLine($"ROI - Top: {roiTop}, Left: {roiLeft}, Bottom: {roiBottom}, Right: {roiRight}");

            // Extract Image Size
            uint imageSize = BitConverter.ToUInt32(response, 25);
            Console.WriteLine($"Image Size: {imageSize} bytes");

            if (imageSize > 0)
            {
                // Extract image data (starts at index 29, length is imageSize)
                byte[] imageData = new byte[imageSize];
                Array.Copy(response, 29, imageData, 0, imageSize);

                // Save image data to file on D: drive
                string filePath = $@"D:\CapturedImage_{DateTime.Now:yyyyMMdd_HHmmss}.jpg";
                System.IO.File.WriteAllBytes(filePath, imageData);

                Console.WriteLine($"Image data saved to: {filePath}");
            }
            else
            {
                Console.WriteLine("No image available in the response.");
            }
        }
        else
        {
            Console.WriteLine("Unexpected message type received.");
        }

        Console.WriteLine($"Raw response (hex): {BitConverter.ToString(response).Replace("-", "")}");
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