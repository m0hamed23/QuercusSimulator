//using System;
//using System.Net;
//using System.Net.Sockets;
//using System.Threading.Tasks;

//class CameraActivatefocusSender
//{
//    private const string CameraIP = "10.0.0.110";
//    private const int CameraPort = 6051;

//    static async Task Main(string[] args)
//    {
//        Console.WriteLine("Camera Activatefocus Sender");
//        Console.WriteLine($"Target Camera: {CameraIP}:{CameraPort}");

//        uint unitId = 1;
//        uint id = 2; // Starting with 2 for messages sent by the central system

//        while (true)
//        {
//            Console.Write("Enter activation time in seconds (or 'exit' to quit): ");
//            string input = Console.ReadLine();

//            if (input.ToLower() == "exit")
//                break;

//            if (uint.TryParse(input, out uint activationTime))
//            {
//                try
//                {
//                    IPEndPoint cameraEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraPort);
//                    await SendActivatefocusRequestAsync(cameraEndPoint, unitId, id, activationTime);
//                    Console.WriteLine($"Activatefocus request sent with activation time: {activationTime} seconds");
//                    id += 2; // Increment by 2 for each new message
//                }
//                catch (Exception ex)
//                {
//                    Console.WriteLine($"Error sending Activatefocus request: {ex.Message}");
//                }
//            }
//            else
//            {
//                Console.WriteLine("Invalid input. Please enter a valid unsigned integer for activation time.");
//            }
//        }

//        Console.WriteLine("Exiting program.");
//    }

//    private static async Task SendActivatefocusRequestAsync(IPEndPoint remoteEndPoint, uint unitId, uint id, uint activationTime)
//    {
//        using (var udpClient = new UdpClient())
//        {
//            byte[] request = new byte[23];
//            request[0] = 0x02; // STX

//            // UnitId (4 bytes, little endian)
//            BitConverter.GetBytes(unitId).CopyTo(request, 1);

//            // Size (4 bytes, little endian, always 23)
//            BitConverter.GetBytes(23).CopyTo(request, 5);

//            // Type (2 bytes, little endian, 73 for Activatefocus)
//            BitConverter.GetBytes((ushort)73).CopyTo(request, 9);

//            // Version (2 bytes, little endian, make it 0)
//            BitConverter.GetBytes((ushort)0).CopyTo(request, 11);

//            // ID (4 bytes, little endian, parameter)
//            BitConverter.GetBytes(id).CopyTo(request, 13);

//            // Activation Time (4 bytes, little endian, parameter)
//            BitConverter.GetBytes(activationTime).CopyTo(request, 17);

//            // Calculate BCC (XOR from STX to the last data byte before ETX)
//            request[21] = CalculateXOR(request, 0, 21);

//            request[22] = 0x03; // ETX

//            await udpClient.SendAsync(request, request.Length, remoteEndPoint);
//            Console.WriteLine($"Raw request sent (hex): {BitConverter.ToString(request).Replace("-", "")}");
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
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class CameraActivatefocusSender
{
    private const string CameraIP = "10.0.0.121";
    //private const int CameraPort = 6051;
    //private const int LocalPort = 6050;
    private const int CameraPort = 7051;
    private const int LocalPort = 7050;

    static async Task Main(string[] args)
    {
        Console.WriteLine("Camera Activatefocus Sender with Response Capture");
        Console.WriteLine($"Target Camera: {CameraIP}:{CameraPort}");
        Console.WriteLine($"Listening for responses on local port: {LocalPort}");

        uint unitId = 2;
        uint id = 200; // Starting with 2 for messages sent by the central system

        using var udpClient = new UdpClient(LocalPort);

        while (true)
        {
            Console.Write("Enter activation time in seconds (or 'exit' to quit): ");
            string input = Console.ReadLine();

            if (input.ToLower() == "exit")
                break;

            if (uint.TryParse(input, out uint activationTime))
            {
                try
                {
                    IPEndPoint cameraEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraPort);
                    await SendActivatefocusRequestAsync(udpClient, cameraEndPoint, unitId, id, activationTime);
                    Console.WriteLine($"Activatefocus request sent with activation time: {activationTime} seconds");

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
            else
            {
                Console.WriteLine("Invalid input. Please enter a valid unsigned integer for activation time.");
            }
        }

        Console.WriteLine("Exiting program.");
    }

    private static async Task SendActivatefocusRequestAsync(UdpClient udpClient, IPEndPoint remoteEndPoint, uint unitId, uint id, uint activationTime)
    {
        byte[] request = new byte[23];
        request[0] = 0x02; // STX

        // UnitId (4 bytes, little endian)
        BitConverter.GetBytes(unitId).CopyTo(request, 1);

        // Size (4 bytes, little endian, always 23)
        BitConverter.GetBytes(23).CopyTo(request, 5);

        // Type (2 bytes, little endian, 73 for Activatefocus)
        BitConverter.GetBytes((ushort)73).CopyTo(request, 9);

        // Version (2 bytes, little endian, make it 0)
        BitConverter.GetBytes((ushort)0).CopyTo(request, 11);

        // ID (4 bytes, little endian, parameter)
        BitConverter.GetBytes(id).CopyTo(request, 13);

        // Activation Time (4 bytes, little endian, parameter)
        BitConverter.GetBytes(activationTime).CopyTo(request, 17);

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

    private static void ProcessResponse(byte[] response)
    {
        if (response.Length < 11)
        {
            Console.WriteLine("Response too short to contain a valid message.");
            return;
        }

        ushort messageType = BitConverter.ToUInt16(response, 9);
        Console.WriteLine($"Response Message Type: {messageType}");

        Console.WriteLine($"Raw response (hex): {BitConverter.ToString(response).Replace("-", "")}");

        // Add more processing here if needed, such as extracting other fields
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