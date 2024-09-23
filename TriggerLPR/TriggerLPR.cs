
//namespace TriggerLPR
//{
//    class Program
//    {
//        static async Task Main(string[] args)
//        {
//            try
//            {
//                // Simulate capturing the LPN from a device with IP address 10.0.0.111
//                LPNResult lastLPNResult = await TriggerLPR.LPRService.CaptureLPNAsync("10.0.0.111");

//                // Store the detected characters from the LPN result
//                string newDetectedChars = lastLPNResult.ArabicLPN;
//                string newPrintableString = string.Empty;

//                // Display the detected characters
//                Console.WriteLine($"newDetectedChars: {newDetectedChars}");

//                // You can format `newPrintableString` as needed, for now, it's empty
//                // Example: Format the newPrintableString if required

//                Console.WriteLine($"newPrintableString: {newDetectedChars}");
//            }
//            catch (Exception ex)
//            {
//                Console.WriteLine($"An error occurred: {ex.Message}");
//            }
//        }
//    }
//}

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

class CameraTriggerTester
{
    private const string CameraIP = "10.0.0.110";
    private const int CameraPort = 6051;

    static async Task Main(string[] args)
    {
        Console.WriteLine("Camera Trigger Tester");
        Console.WriteLine($"Target Camera: {CameraIP}:{CameraPort}");

        while (true)
        {
            Console.Write("Enter trigger ID (or 'exit' to quit): ");
            string input = Console.ReadLine();

            if (input.ToLower() == "exit")
                break;

            if (uint.TryParse(input, out uint triggerId))
            {
                try
                {
                    IPEndPoint cameraEndPoint = new IPEndPoint(IPAddress.Parse(CameraIP), CameraPort);
                    await SendTriggerRequestAsync(cameraEndPoint, triggerId);
                    Console.WriteLine($"Trigger request sent with ID: {triggerId}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error sending trigger: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Invalid input. Please enter a valid unsigned integer.");
            }
        }

        Console.WriteLine("Exiting program.");
    }

    private static async Task SendTriggerRequestAsync(IPEndPoint remoteEndPoint, uint triggerId)
    {
        using (var udpClient = new UdpClient())
        {
            byte[] request = new byte[19];
            request[0] = 0x02; // STX
            BitConverter.GetBytes(1).CopyTo(request, 1); // Unit ID
            BitConverter.GetBytes(19).CopyTo(request, 5); // Size
            request[9] = 0x43; request[10] = 0x00; // Type (0x4300)
            BitConverter.GetBytes((short)1).CopyTo(request, 11); // Version
            BitConverter.GetBytes(triggerId).CopyTo(request, 13); // Trigger ID
            request[17] = CalculateXOR(request, 0, 17); // BCC
            request[18] = 0x03; // ETX

            await udpClient.SendAsync(request, request.Length, remoteEndPoint);
            Console.WriteLine($"Raw request sent (hex): {BitConverter.ToString(request).Replace("-", "")}");
        }
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