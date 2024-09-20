//using System;
//using System.Net;
//using System.Net.Sockets;
//using System.Threading.Tasks;

//class LPRSimulator
//{
//    private const int ServerPort = 7051;
//    private const int CameraPort = 7050;
//    private const string LocalHost = "127.0.0.1";

//    static async Task Main(string[] args)
//    {
//        Console.WriteLine("LPR Simulator starting...");

//        // Start the camera simulator
//        var cameraTask = RunCameraSimulatorAsync();

//        // Start the server simulator
//        var serverTask = RunServerSimulatorAsync();

//        // Wait for both tasks to complete (they won't in this case, as they run indefinitely)
//        await Task.WhenAll(cameraTask, serverTask);
//    }

//    private static async Task RunCameraSimulatorAsync()
//    {
//        var udpClient = new UdpClient(CameraPort);
//        Console.WriteLine($"Camera simulator listening on port {CameraPort}");

//        while (true)
//        {
//            var result = await udpClient.ReceiveAsync();
//            await ProcessCameraMessageAsync(udpClient, result.Buffer, result.RemoteEndPoint);
//        }
//    }

//    private static async Task RunServerSimulatorAsync()
//    {
//        var udpClient = new UdpClient();
//        Console.WriteLine($"Server simulator running. Sending messages to port {CameraPort}");

//        while (true)
//        {
//            Console.WriteLine("\nSelect a message to send:");
//            Console.WriteLine("1. Status Request");
//            Console.WriteLine("2. Trigger Request");
//            Console.WriteLine("3. LPN Image Request");
//            Console.Write("Enter your choice (1-3): ");

//            var choice = Console.ReadLine();
//            byte[] message = null;

//            switch (choice)
//            {
//                case "1":
//                    message = CreateStatusRequest();
//                    break;
//                case "2":
//                    message = CreateTriggerRequest();
//                    break;
//                case "3":
//                    message = CreateLPNImageRequest();
//                    break;
//                default:
//                    Console.WriteLine("Invalid choice. Please try again.");
//                    continue;
//            }

//            await udpClient.SendAsync(message, message.Length, new IPEndPoint(IPAddress.Parse(LocalHost), CameraPort));
//            Console.WriteLine("Message sent. Waiting for response...");

//            var response = await udpClient.ReceiveAsync();
//            Console.WriteLine($"Received response: {BitConverter.ToString(response.Buffer)}");
//        }
//    }

//    private static async Task ProcessCameraMessageAsync(UdpClient udpClient, byte[] message, IPEndPoint remoteEndPoint)
//    {
//        if (message.Length < 11)
//        {
//            Console.WriteLine($"Received message is too short (length: {message.Length})");
//            return;
//        }

//        ushort messageType = BitConverter.ToUInt16(message, 9);
//        Console.WriteLine($"Camera received message type: 0x{messageType:X4}");

//        byte[] response = null;

//        switch (messageType)
//        {
//            case 0x0044: // Status Request
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
//            await udpClient.SendAsync(response, response.Length, remoteEndPoint);
//            Console.WriteLine($"Camera sent response for message type: 0x{messageType:X4}");
//        }
//    }

//    private static byte[] CreateStatusRequest()
//    {
//        byte[] request = new byte[19];
//        request[0] = 0x02; // STX
//        BitConverter.GetBytes((uint)1).CopyTo(request, 1); // Unit ID
//        BitConverter.GetBytes((uint)19).CopyTo(request, 5); // Size
//        BitConverter.GetBytes((ushort)0x0044).CopyTo(request, 9); // Type (Status Request)
//        BitConverter.GetBytes((ushort)0x0001).CopyTo(request, 11); // Version
//        BitConverter.GetBytes((uint)1).CopyTo(request, 13); // Id
//        request[17] = CalculateXOR(request, 0, 17); // BCC
//        request[18] = 0x03; // ETX
//        return request;
//    }

//    private static byte[] CreateTriggerRequest()
//    {
//        byte[] request = new byte[23];
//        request[0] = 0x02; // STX
//        BitConverter.GetBytes((uint)1).CopyTo(request, 1); // Unit ID
//        BitConverter.GetBytes((uint)23).CopyTo(request, 5); // Size
//        BitConverter.GetBytes((ushort)0x0043).CopyTo(request, 9); // Type (Trigger Request)
//        BitConverter.GetBytes((ushort)0x0000).CopyTo(request, 11); // Version
//        BitConverter.GetBytes((uint)2).CopyTo(request, 13); // Id
//        BitConverter.GetBytes((uint)1000).CopyTo(request, 17); // Trigger ID
//        request[21] = CalculateXOR(request, 0, 21); // BCC
//        request[22] = 0x03; // ETX
//        return request;
//    }

//    private static byte[] CreateLPNImageRequest()
//    {
//        byte[] request = new byte[23];
//        request[0] = 0x02; // STX
//        BitConverter.GetBytes((uint)1).CopyTo(request, 1); // Unit ID
//        BitConverter.GetBytes((uint)23).CopyTo(request, 5); // Size
//        BitConverter.GetBytes((ushort)0x0047).CopyTo(request, 9); // Type (LPN Image Request)
//        BitConverter.GetBytes((ushort)0x0000).CopyTo(request, 11); // Version
//        BitConverter.GetBytes((uint)3).CopyTo(request, 13); // Id
//        BitConverter.GetBytes((uint)1).CopyTo(request, 17); // Car ID
//        request[21] = CalculateXOR(request, 0, 21); // BCC
//        request[22] = 0x03; // ETX
//        return request;
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