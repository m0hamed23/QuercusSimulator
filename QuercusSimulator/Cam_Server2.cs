using QuercusSimulator;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class LPRSimulator
{
    private const int CameraPort = 7050;
    private const string CameraIP = "10.0.0.111";

    static async Task Main(string[] args)
    {
        Console.WriteLine("LPR Simulator starting...");

        //await SendTriggerRequestAsync(udpClient, remoteEndPoint, triggerId: 1);
        //await SendLPNImageRequestAsync(udpClient, remoteEndPoint, carId: 100);

        // Start the camera simulator
        await RunCameraSimulatorAsync();
    }

    private static async Task RunCameraSimulatorAsync()
    {
        var udpClient = new UdpClient(CameraPort);
        Console.WriteLine($"Camera simulator listening on {CameraIP}:{CameraPort}");

        while (true)
        {
            Console.WriteLine("\nEnter raw hex message to process (or type 'exit' to quit):");
            string input = Console.ReadLine();

            if (input.ToLower() == "exit")
                break;

            byte[] message = StringToByteArray(input);
            if (message == null || message.Length < 19)
            {
                Console.WriteLine("Invalid or too short hex string. Please try again.");
                continue;
            }

            var remoteEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraPort);
            await ProcessCameraMessageAsync(udpClient, message, remoteEndPoint);
        }
    }

    private static async Task ProcessCameraMessageAsync(UdpClient udpClient, byte[] message, IPEndPoint remoteEndPoint)
    {
        if (message.Length < 19)
        {
            Console.WriteLine($"Received message is too short (length: {message.Length})");
            return;
        }

        // Read message type and adjust for endianness
        ushort messageType = BitConverter.ToUInt16(message, 9);
        if (BitConverter.IsLittleEndian)
        {
            messageType = (ushort)((messageType << 8) | (messageType >> 8));
        }

        byte[] response = null;
        switch (messageType)
        {
            case 0x4400: // Status Request
                response = CreateStatusResponse(message);
                break;
            case 0x4300: // Trigger Request
                response = CreateTriggerResponse(message);
                break;
            case 0x4700: // LPN Image Request
                response = CreateLPNImageResponse(message);
                break;
            case 0x6000: // Ping
                response = CreatePingResponse(message);
                break;
            default:
                Console.WriteLine($"Unsupported message type: 0x{messageType:X4}");
                return;
        }

        if (response != null)
        {
            await udpClient.SendAsync(response, response.Length, remoteEndPoint);
            LogMessage("Camera", "Server", response);
        }
        if (messageType == 0x4300)
        {
            // Example input values for Unit ID, ID, Car ID, Trigger ID, and Detected Chars
            uint unitId = 1;
            uint id = 13;
            uint carId = 6;
            uint triggerId = 10005;
            string detectedChars = "395BTN";

            // Create the license plate info message with the provided parameters
            byte[] response2 = LPInfoMessage.CreateLicensePlateInfoMessage(unitId, id, carId, triggerId, detectedChars);
            await udpClient.SendAsync(response2, response2.Length, remoteEndPoint);

            // Display the raw message as a hexadecimal string
            Console.WriteLine("Raw License Plate Info Message (hex): " + BitConverter.ToString(message).Replace("-", ""));

        }
    }
    private static byte[] CreateStatusResponse(byte[] request)
    {
        // The response should be exactly 26 bytes (25 bytes + ETX)
        byte[] response = new byte[25];

        // STX (Start of Text)
        response[0] = 0x02;

        // Unit ID (4 bytes) - assuming it's the same as the request
        Buffer.BlockCopy(request, 1, response, 1, 4);

        // Size (4 bytes) - Total size of 25 bytes (0x19000000 in little-endian format)
        response[5] = 0x19; // Set message size to 25 bytes
        response[6] = 0x00;
        response[7] = 0x00;
        response[8] = 0x00;

        // Type (2 bytes) - Status Response (0x8400)
        response[9] = 0x84;
        response[10] = 0x00;

        // Version (2 bytes) - Version (0x0100)
        //response[11] = 0x01;
        //response[12] = 0x00;
        Buffer.BlockCopy(request, 11, response, 11, 2);

        // ID (4 bytes) - same as request
        Buffer.BlockCopy(request, 13, response, 13, 4);

        // Message Data (6 bytes) - Status data
        response[17] = 0x01; // Active
        response[18] = 0x01; // I/O Card Status
        response[19] = 0x01; // Camera Status
        response[20] = 0x01; // Additional status
        response[21] = 0x00; // Reserved
        response[22] = 0x00; // Reserved

        // BCC (Block Check Character) - XOR from STX to the last byte of Message Data
        response[23] = CalculateXOR(response, 0, 23);

        // ETX (End of Text)
        response[24] = 0x03;

        // Log the response message for verification
        Console.WriteLine("Raw Status Response (hex): " + BitConverter.ToString(response).Replace("-", ""));

        return response;
    }

    private static byte[] CreateTriggerResponse(byte[] request)
    {
        // The response should be exactly 19 bytes
        byte[] response = new byte[19];

        // STX (Start of Text)
        response[0] = 0x02;

        // Unit ID (4 bytes) - Copy from request
        Buffer.BlockCopy(request, 1, response, 1, 4);

        // Size (4 bytes) - Fixed size of 19 bytes (0x13000000 in little-endian format)
        response[5] = 0x13; // 19 bytes
        response[6] = 0x00;
        response[7] = 0x00;
        response[8] = 0x00;

        // Type (2 bytes) - ACK type (0xC000)
        response[9] = 0xC0;
        response[10] = 0x00;

        // Version (2 bytes) - Same as request
        Buffer.BlockCopy(request, 11, response, 11, 2);

        // ID (4 bytes) - Same as request
        Buffer.BlockCopy(request, 13, response, 13, 4);

        // BCC (Block Check Character) - XOR from STX to the last byte before BCC
        response[17] = CalculateXOR(response, 0, 17);

        // ETX (End of Text)
        response[18] = 0x03;

        // Log the response message for verification
        Console.WriteLine("Raw Trigger Response (hex): " + BitConverter.ToString(response).Replace("-", ""));

        return response;
    }


    private static byte[] CreateLPNImageResponse(byte[] request)
    {
        string imagePath = @"D:\Quercus\lp_image.jpg";
        byte[] imageData = File.ReadAllBytes(imagePath);
        int imageSize = imageData.Length;

        // Define ROI coordinates (example values)
        ushort roiTop = 100;
        ushort roiLeft = 200;
        ushort roiBottom = 150;
        ushort roiRight = 300;

        // Calculate total response size
        int totalSize = 1 + 4 + 4 + 2 + 2 + 4 + 8 + 4 + imageSize + 1 + 1;
        byte[] response = new byte[totalSize];

        // STX (Start of Text)
        response[0] = 0x02;

        // Unit ID (4 bytes) - Copy from request
        Buffer.BlockCopy(request, 1, response, 1, 4);

        // Size (4 bytes) - Total size of the message
        BitConverter.GetBytes((uint)totalSize).CopyTo(response, 5);

        // Type (2 bytes) - LPN Image Response (0x8700)
        response[9] = 0x87;
        response[10] = 0x00;

        // Version (2 bytes) - Copy from request
        Buffer.BlockCopy(request, 11, response, 11, 2);

        // ID (4 bytes) - Copy from request
        Buffer.BlockCopy(request, 13, response, 13, 4);

        // ROI coordinates (8 bytes)
        BitConverter.GetBytes(roiTop).CopyTo(response, 17);
        BitConverter.GetBytes(roiLeft).CopyTo(response, 19);
        BitConverter.GetBytes(roiBottom).CopyTo(response, 21);
        BitConverter.GetBytes(roiRight).CopyTo(response, 23);

        // Image Size (4 bytes)
        BitConverter.GetBytes((uint)imageSize).CopyTo(response, 25);

        // Image Data (variable)
        Buffer.BlockCopy(imageData, 0, response, 29, imageSize);

        // BCC (Block Check Character) - XOR from STX to the last byte before BCC
        response[totalSize - 2] = CalculateXOR(response, 0, totalSize - 2);

        // ETX (End of Text)
        response[totalSize - 1] = 0x03;

        // Log the response message for verification
        Console.WriteLine("Raw LPN Image Response (hex): " + BitConverter.ToString(response).Replace("-", ""));
        // Log the response message for verification
        Console.WriteLine("Response Message Details:");
        Console.WriteLine($"STX: {response[0]:X2}");
        Console.WriteLine($"Unit ID: {BitConverter.ToString(response, 1, 4).Replace("-", "")}");
        Console.WriteLine($"Size: {BitConverter.ToUInt32(response, 5)}");
        Console.WriteLine($"Type: {BitConverter.ToUInt16(response, 9):X4}");
        Console.WriteLine($"Version: {BitConverter.ToUInt16(response, 11)}");
        Console.WriteLine($"ID: {BitConverter.ToUInt32(response, 13)}");
        Console.WriteLine($"ROI Top: {BitConverter.ToUInt16(response, 17)}");
        Console.WriteLine($"ROI Left: {BitConverter.ToUInt16(response, 19)}");
        Console.WriteLine($"ROI Bottom: {BitConverter.ToUInt16(response, 21)}");
        Console.WriteLine($"ROI Right: {BitConverter.ToUInt16(response, 23)}");
        Console.WriteLine($"Image Size: {BitConverter.ToUInt32(response, 25)}");
        Console.WriteLine("Image Data: " + BitConverter.ToString(response, 29, imageSize).Replace("-", ""));
        Console.WriteLine($"BCC: {response[totalSize - 2]:X2}");
        Console.WriteLine($"ETX: {response[totalSize - 1]:X2}");

        return response;
    }

    private static byte[] CreatePingResponse(byte[] request)
    {
        // The response should be exactly 19 bytes (size for ACK response)
        byte[] response = new byte[19];

        // STX (Start of Text)
        response[0] = 0x02;

        // Unit ID (4 bytes) - Copy from the request
        Buffer.BlockCopy(request, 1, response, 1, 4);

        // Size (4 bytes) - Fixed size of 19 bytes
        response[5] = 0x13; // 19 bytes
        response[6] = 0x00;
        response[7] = 0x00;
        response[8] = 0x00;

        // Type (2 bytes) - ACK type (0xC000)
        response[9] = 0xC0;
        response[10] = 0x00;

        // Version (2 bytes) - Same as request
        Buffer.BlockCopy(request, 11, response, 11, 2);

        // ID (4 bytes) - Same as request
        Buffer.BlockCopy(request, 13, response, 13, 4);

        // BCC (Block Check Character) - XOR from STX to the last byte before BCC
        response[17] = CalculateXOR(response, 0, 17);

        // ETX (End of Text)
        response[18] = 0x03;

        // Log the response message for verification
        Console.WriteLine("Raw Ping Response (hex): " + BitConverter.ToString(response).Replace("-", ""));

        return response;
    }

    private static async Task SendTriggerRequestAsync(UdpClient udpClient, IPEndPoint remoteEndPoint, uint triggerId)
    {
        byte[] request = new byte[19];

        // STX (1 byte)
        request[0] = 0x02;

        // Unit ID (4 bytes) - Use a hardcoded or predefined Unit ID
        BitConverter.GetBytes(1).CopyTo(request, 1);

        // Size (4 bytes) - Fixed size of 19 bytes for trigger request
        BitConverter.GetBytes(19).CopyTo(request, 5);

        // Type (2 bytes) - Trigger Request (0x4300 in little-endian)
        request[9] = 0x43;
        request[10] = 0x00;

        // Version (2 bytes) - Use version 1.0 for example
        BitConverter.GetBytes(1).CopyTo(request, 11);

        // ID (4 bytes) - Set an ID (unique for each conversation)
        BitConverter.GetBytes(triggerId).CopyTo(request, 13);

        // BCC (Block Check Character) - XOR from STX to the last byte before BCC
        request[17] = CalculateXOR(request, 0, 17);

        // ETX (1 byte) - End of message
        request[18] = 0x03;

        // Send the request
        await udpClient.SendAsync(request, request.Length, remoteEndPoint);
        LogMessage("Trigger Request", "Camera", request);
    }

    private static async Task SendLPNImageRequestAsync(UdpClient udpClient, IPEndPoint remoteEndPoint, uint carId)
    {
        byte[] request = new byte[19];

        // STX (1 byte)
        request[0] = 0x02;

        // Unit ID (4 bytes) - Use a hardcoded or predefined Unit ID
        BitConverter.GetBytes(1).CopyTo(request, 1);

        // Size (4 bytes) - Fixed size of 19 bytes for LPN image request
        BitConverter.GetBytes(19).CopyTo(request, 5);

        // Type (2 bytes) - LPN Image Request (0x4700 in little-endian)
        request[9] = 0x47;
        request[10] = 0x00;

        // Version (2 bytes) - Use version 1.0 for example
        BitConverter.GetBytes(1).CopyTo(request, 11);

        // ID (4 bytes) - Set an ID (unique for each conversation)
        BitConverter.GetBytes(carId).CopyTo(request, 13);

        // BCC (Block Check Character) - XOR from STX to the last byte before BCC
        request[17] = CalculateXOR(request, 0, 17);

        // ETX (1 byte) - End of message
        request[18] = 0x03;

        // Send the request
        await udpClient.SendAsync(request, request.Length, remoteEndPoint);
        LogMessage("LPN Image Request", "Camera", request);
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

    private static void LogMessage(string source, string destination, byte[] message)
    {
        Console.WriteLine($"Source: {source}, Destination: {destination}");
        Console.WriteLine($"Message (Hex): {BitConverter.ToString(message).Replace("-", "")}");
    }

    private static byte[] StringToByteArray(string hex)
    {
        try
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        catch
        {
            return null;
        }
    }
}
