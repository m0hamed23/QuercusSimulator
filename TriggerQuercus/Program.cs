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
                    uint Id = 1;
                    uint UnitId = 1;

                    await SendTriggerRequestAsync(cameraEndPoint, UnitId, Id, triggerId); // Using UnitId = 1 as per the requirement
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