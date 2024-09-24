using QuercusSimulator;
using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class LPRSimulator
{
    private const int CameraMainPort = 7051; // First port to listen on
    private const int CameraConfigPort = 7041; // Second port to listen on
    private const string ServerIP = "10.0.0.10";
    private const string RealCamIP = "10.0.0.110";
    private const int RealCamMainPort = 6051; // Second port to listen on

    private const int ServerMainPort = 7050;    // Default port for sending responses
    private const int ServerConfigPort = 7040; // Port for sending ping responses
    static uint lastid = 1;
    static uint lastcarId = 1;
    static uint id = 1;
    static uint carId = 1;


    static async Task Main(string[] args)
    {
        Console.WriteLine("LPR Simulator starting...");

        //await SendTriggerRequestAsync(udpClient, remoteEndPoint, triggerId: 1);
        //await SendLPNImageRequestAsync(udpClient, remoteEndPoint, carId: 100);

        // Start the camera simulator
        //await RunCameraSimulatorAsync();

        // Start the camera simulators for both ports
        Task listenOnPort1 = RunCameraSimulatorAsync(CameraMainPort);
        Task listenOnPort2 = RunCameraSimulatorAsync(CameraConfigPort);

        // Wait for both tasks to complete (they run indefinitely)
        await Task.WhenAll(listenOnPort1, listenOnPort2);

    }
    //private static async Task RunCameraSimulatorAsync(int port)
    //{
    //    using (var udpClient = new UdpClient(port))
    //    {
    //        Console.WriteLine($"Camera simulator listening on port {port}");

    //        while (true)
    //        {
    //            try
    //            {
    //                // Listen for incoming messages on the UDP port
    //                var result = await udpClient.ReceiveAsync();
    //                var message = result.Buffer;
    //                var remoteEndPoint = result.RemoteEndPoint;

    //                if (message == null || message.Length < 19)
    //                {
    //                    Console.WriteLine("Invalid or too short UDP message. Ignoring.");
    //                    continue;
    //                }

    //                // Process the message based on the type
    //                //await ProcessCameraMessageAsync(udpClient, message, remoteEndPoint);
    //                await ProcessCameraMessageAsync(udpClient, message);

    //            }
    //            catch (Exception ex)
    //            {
    //                Console.WriteLine($"Error receiving UDP message: {ex.Message}");
    //            }
    //        }
    //    }
    //}
    private static async Task RunCameraSimulatorAsync(int port)
    {
        using (var udpClient = new UdpClient(port))
        {
            Console.WriteLine($"Camera simulator listening on port {port}");

            while (true)
            {
                try
                {
                    var (message, remoteEndPoint) = await UdpLargeMessageHandler.ReceiveLargeMessageAsync(udpClient);

                    if (message == null || message.Length < 19)
                    {
                        Console.WriteLine("Invalid or too short UDP message. Ignoring.");
                        continue;
                    }

                    await ProcessCameraMessageAsync(udpClient, message);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error in camera simulator: {ex.Message}");
                }
            }
        }
    }
    private static async Task ProcessCameraMessageAsync(UdpClient udpClient, byte[] message)
    {
        if (message.Length < 19)
        {
            Console.WriteLine($"Received message is too short (length: {message.Length})");
            return;
        }
        IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(ServerIP), ServerMainPort);
        //IPEndPoint RealCameraEndPoint = new IPEndPoint(IPAddress.Parse(RealCamIP), RealCamMainPort);

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
                //await ResendTriggerRequest(message);
                response = CreateTriggerResponse(message);
                break;
            case 0x4700: // LPN Image Request
                response = CreateLPNImageResponse(message);
                break;
            case 0x6000: // Ping
                response = CreatePingResponse(message);
                // Ping response must be sent to 10.0.0.10:7040
                remoteEndPoint = new IPEndPoint(IPAddress.Parse(ServerIP), ServerConfigPort);
                break;
            default:
                Console.WriteLine($"Unsupported message type: 0x{messageType:X4}");
                return;
        }

        if (response != null)
        {

            await udpClient.SendAsync(response, response.Length, remoteEndPoint);
            //LogMessage("Camera", "Server", response);
        }

        if (messageType == 0x4300) // Trigger Request
        {
            IPEndPoint cameraEndPoint = new IPEndPoint(IPAddress.Parse(RealCamIP), RealCamMainPort);
            uint Id = 13;
            uint UnitId = 1;
            uint TriggerId = 11;

            await SendTriggerRequestAsync(cameraEndPoint, UnitId, Id, TriggerId);
            // Extract Trigger ID from the message data (4 bytes starting at index 17)

            //IPEndPoint RealCameraEndPoint = new IPEndPoint(IPAddress.Parse("10.0.0.110"), 6051);
            //await SendTriggerRequestAsync(RealCameraEndPoint, triggerId);
            // Resend the trigger request to 10.0.0.110:6051
            //await Task.Delay(500);

            LPNResult LastLPNResult = await QuercusSimulator.LPRService.CaptureLPNAsync("10.0.0.111");

            //LPNResult LastLPNResult = new LPNResult();

            //LastLPNResult.ArabicLPN = "395BTN";

            //string newDetectedChars = "123ASD";
            //string newPrintableString = "123 ASD";
            if (LastLPNResult != null)
            {
                uint triggerId = BitConverter.ToUInt32(message, 17);
                uint unitId = BitConverter.ToUInt32(message, 1);

                string newDetectedChars = LastLPNResult.ArabicLPN;
                string newPrintableString = newDetectedChars;
                Console.WriteLine($"newDetectedChars:{newDetectedChars}");
                // Separate digits and letters
                //string numbers = string.Concat(newDetectedChars.Where(char.IsDigit));
                //string letters = string.Concat(newDetectedChars.Where(char.IsLetter));

                //// Combine with a space in between
                //newPrintableString = numbers + " " + letters;

                id = lastid + 2;
                carId = lastcarId + 1;
                lastid = id;
                lastcarId = carId;

                //string detectedChars = "395BTN";

                // Create the license plate info message with the extracted Unit ID and Trigger ID
                byte[] licensePlateInfoMessage = LPInfoMessage.CreateLicensePlateInfoMessage(unitId, id, carId, triggerId, newDetectedChars);
                await udpClient.SendAsync(licensePlateInfoMessage, licensePlateInfoMessage.Length, remoteEndPoint);

                // Display the raw message as a hexadecimal string
                //Console.WriteLine("Raw License Plate Info Message (hex): " + BitConverter.ToString(licensePlateInfoMessage).Replace("-", ""));
            }
            else
            {
                Console.WriteLine($"LastLPNResult is null");

                
            }

        }
    }
    private static async Task ResendTriggerRequest(byte[] originalMessage)
    {
        IPEndPoint realCameraEndPoint = new IPEndPoint(IPAddress.Parse("10.0.0.110"), 6051);

        using (var newUdpClient = new UdpClient())
        {
            await newUdpClient.SendAsync(originalMessage, originalMessage.Length, realCameraEndPoint);
            Console.WriteLine($"Trigger request resent to {realCameraEndPoint}");
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
        //string imagePath = @"D:\lp.jpg";
        string imagePath = @"C:\EventImages\lastimage.jpg";

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
        //Console.WriteLine("Raw LPN Image Response (hex): " + BitConverter.ToString(response).Replace("-", ""));
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
        //Console.WriteLine("Image Data: " + BitConverter.ToString(response, 29, imageSize).Replace("-", ""));
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

    //private static async Task SendTriggerRequestAsync(UdpClient udpClient, IPEndPoint remoteEndPoint, uint triggerId)
    //{
    //    byte[] request = new byte[19];

    //    // STX (1 byte)
    //    request[0] = 0x02;

    //    // Unit ID (4 bytes) - Use a hardcoded or predefined Unit ID
    //    BitConverter.GetBytes(1).CopyTo(request, 1);

    //    // Size (4 bytes) - Fixed size of 19 bytes for trigger request
    //    BitConverter.GetBytes(19).CopyTo(request, 5);

    //    // Type (2 bytes) - Trigger Request (0x4300 in little-endian)
    //    request[9] = 0x43;
    //    request[10] = 0x00;

    //    // Version (2 bytes) - Use version 1.0 for example
    //    BitConverter.GetBytes(1).CopyTo(request, 11);

    //    // ID (4 bytes) - Set an ID (unique for each conversation)
    //    BitConverter.GetBytes(triggerId).CopyTo(request, 13);

    //    // BCC (Block Check Character) - XOR from STX to the last byte before BCC
    //    request[17] = CalculateXOR(request, 0, 17);

    //    // ETX (1 byte) - End of message
    //    request[18] = 0x03;

    //    // Send the request
    //    await udpClient.SendAsync(request, request.Length, remoteEndPoint);
    //    LogMessage("Trigger Request", "Camera", request);
    //}
    private static async Task SendTriggerRequestAsync(IPEndPoint remoteEndPoint, uint unitId, uint Id, uint triggerId)
    {
        using (var udpClient = new UdpClient())
        {
            byte[] request = new byte[23];
            request[0] = 0x02; // STX

            // UnitId (4 bytes, little endian)
            BitConverter.GetBytes(unitId).CopyTo(request, 1);

            // Size (4 bytes, little endian, always 23)
            BitConverter.GetBytes(23).CopyTo(request, 5);

            // Type (2 bytes, little endian, always 0x4300)
            request[9] = 0x43;
            request[10] = 0x00;

            // Version (2 bytes, little endian, make it 0)
            BitConverter.GetBytes((ushort)0).CopyTo(request, 11);

            // ID (4 bytes, little endian, parameter)
            BitConverter.GetBytes(Id).CopyTo(request, 13);

            // Trigger ID (4 bytes, little endian, parameter)
            BitConverter.GetBytes(triggerId).CopyTo(request, 17);

            // Calculate BCC (XOR from STX to the last data byte before ETX)
            request[21] = CalculateXOR(request, 0, 21);

            request[22] = 0x03; // ETX

            await udpClient.SendAsync(request, request.Length, remoteEndPoint);
            Console.WriteLine($"Raw request sent (hex): {BitConverter.ToString(request).Replace("-", "")}");
        }
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
}
