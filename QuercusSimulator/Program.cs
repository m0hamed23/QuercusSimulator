//using System.Net.Sockets;
//using System.Net;
//using System;
//using System.Net;
//using System.Net.Sockets;
//using System.Text;
//using System.Threading.Tasks;

//class LPRCameraSimulator
//{
//    private const int ServerPort = 7051;
//    private const string ServerIP = "10.0.0.10";
//    private const int CameraPort = 7050;
//    private static UdpClient udpClient;

//    static async Task Main(string[] args)
//    {
//        Console.WriteLine("LPR Camera Simulator starting...");
//        udpClient = new UdpClient(CameraPort);

//        try
//        {
//            while (true)
//            {
//                var result = await udpClient.ReceiveAsync();
//                await ProcessMessageAsync(result.Buffer, result.RemoteEndPoint);
//            }
//        }
//        catch (Exception e)
//        {
//            Console.WriteLine($"An error occurred: {e.Message}");
//        }
//        finally
//        {
//            udpClient.Close();
//        }
//    }

//    private static async Task ProcessMessageAsync(byte[] message, IPEndPoint remoteEndPoint)
//    {
//        if (message.Length < 11)
//        {
//            Console.WriteLine($"Received message is too short (length: {message.Length})");
//            return;
//        }

//        ushort messageType = BitConverter.ToUInt16(message, 9);
//        Console.WriteLine($"Received message type: 0x{messageType:X4}");

//        byte[] response = null;

//        switch (messageType)
//        {
//            case 0x0040: // Status Request
//                response = CreateStatusResponse(message);
//                break;
//            case 0x0043: // Trigger Request
//                response = CreateTriggerResponse(message);
//                break;
//            case 0x0047: // LPN Image Request
//                response = CreateLPNImageResponse(message);
//                break;
//            default:
//                Console.WriteLine($"Unsupported message type: 0x{messageType:X4}");
//                return;
//        }

//        if (response != null)
//        {
//            await udpClient.SendAsync(response, response.Length, new IPEndPoint(IPAddress.Parse(ServerIP), ServerPort));
//            Console.WriteLine($"Sent response for message type: 0x{messageType:X4}");
//        }
//    }

//    private static byte[] CreateStatusResponse(byte[] request)
//    {
//        byte[] response = new byte[25];
//        Buffer.BlockCopy(request, 0, response, 0, 17); // Copy STX, Unit ID, Size, Type, Version, and Id

//        response[0] = 0x02; // STX
//        BitConverter.GetBytes((uint)25).CopyTo(response, 4); // Size
//        BitConverter.GetBytes((ushort)0x8400).CopyTo(response, 9); // Type (Status Response)

//        // Message Data: Active, I/O Card Status, Camera Status
//        response[17] = 0x01; // Active
//        response[18] = 0x01; // I/O Card Status
//        response[19] = 0x01; // Camera Status
//        response[20] = 0x01; // Additional status bytes
//        response[21] = 0x01;
//        response[22] = 0x00;

//        response[23] = CalculateXOR(response, 0, 23); // BCC
//        response[24] = 0x03; // ETX

//        return response;
//    }

//    private static byte[] CreateTriggerResponse(byte[] request)
//    {
//        byte[] response = new byte[19];
//        Buffer.BlockCopy(request, 0, response, 0, 17); // Copy STX, Unit ID, Size, Type, Version, and Id

//        response[0] = 0x02; // STX
//        BitConverter.GetBytes((uint)19).CopyTo(response, 4); // Size
//        BitConverter.GetBytes((ushort)0xC000).CopyTo(response, 9); // Type (ACK)

//        response[17] = CalculateXOR(response, 0, 17); // BCC
//        response[18] = 0x03; // ETX

//        return response;
//    }

//    private static byte[] CreateLPNImageResponse(byte[] request)
//    {
//        // This is a simplified response. In a real scenario, you'd include actual image data.
//        byte[] response = new byte[200]; // Adjust size as needed
//        Buffer.BlockCopy(request, 0, response, 0, 17); // Copy STX, Unit ID, Size, Type, Version, and Id

//        response[0] = 0x02; // STX
//        BitConverter.GetBytes((uint)response.Length).CopyTo(response, 4); // Size
//        BitConverter.GetBytes((ushort)0x8700).CopyTo(response, 9); // Type (LPN Image Response)

//        // ROI coordinates (example values)
//        BitConverter.GetBytes((ushort)100).CopyTo(response, 17); // RoiTop
//        BitConverter.GetBytes((ushort)200).CopyTo(response, 19); // RoiLeft
//        BitConverter.GetBytes((ushort)150).CopyTo(response, 21); // RoiBottom
//        BitConverter.GetBytes((ushort)300).CopyTo(response, 23); // RoiRight

//        // Image Size (example value)
//        BitConverter.GetBytes((uint)150).CopyTo(response, 25);

//        // Image Data (simplified, just fill with some dummy data)
//        for (int i = 29; i < response.Length - 2; i++)
//        {
//            response[i] = (byte)(i % 256);
//        }

//        response[response.Length - 2] = CalculateXOR(response, 0, response.Length - 2); // BCC
//        response[response.Length - 1] = 0x03; // ETX

//        return response;
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