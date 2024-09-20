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

        ushort messageType = BitConverter.ToUInt16(message, 9);
        byte[] response = null;

        switch (messageType)
        {
            case 0x0044: // Status Request
                response = CreateStatusResponse(message);
                break;
            case 0x0043: // Trigger Request
                response = CreateTriggerResponse(message);
                break;
            case 0x0047: // LPN Image Request
                response = CreateLPNImageResponse(message);
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


    //private static byte[] CreateTriggerResponse(byte[] request)
    //{
    //    byte[] response = new byte[19];
    //    Buffer.BlockCopy(request, 0, response, 0, 19); // Copy STX, Unit ID, Size, Type, Version, and Id

    //    response[0] = 0x02; // STX
    //    BitConverter.GetBytes((uint)19).CopyTo(response, 4); // Size
    //    BitConverter.GetBytes((ushort)0xC000).CopyTo(response, 9); // Type (ACK)
    //    BitConverter.GetBytes((ushort)0x0000).CopyTo(response, 11); // Version

    //    response[17] = CalculateXOR(response, 0, 17); // BCC
    //    response[18] = 0x03; // ETX

    //    return response;
    //}
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
        byte[] response = new byte[200]; // Adjust size as needed
        Buffer.BlockCopy(request, 0, response, 0, 19); // Copy STX, Unit ID, Size, Type, Version, and Id

        response[0] = 0x02; // STX
        BitConverter.GetBytes((uint)response.Length).CopyTo(response, 4); // Size
        BitConverter.GetBytes((ushort)0x8700).CopyTo(response, 9); // Type (LPN Image Response)
        BitConverter.GetBytes((ushort)0x0000).CopyTo(response, 11); // Version

        // ROI coordinates (example values)
        BitConverter.GetBytes((ushort)100).CopyTo(response, 17); // RoiTop
        BitConverter.GetBytes((ushort)200).CopyTo(response, 19); // RoiLeft
        BitConverter.GetBytes((ushort)150).CopyTo(response, 21); // RoiBottom
        BitConverter.GetBytes((ushort)300).CopyTo(response, 23); // RoiRight

        // Image Size (example value)
        BitConverter.GetBytes((uint)150).CopyTo(response, 25);

        // Image Data (simplified, just fill with some dummy data)
        for (int i = 29; i < response.Length - 2; i++)
        {
            response[i] = (byte)(i % 256);
        }

        response[response.Length - 2] = CalculateXOR(response, 0, response.Length - 2); // BCC
        response[response.Length - 1] = 0x03; // ETX

        return response;
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
