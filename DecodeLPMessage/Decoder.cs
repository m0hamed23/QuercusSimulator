using System;
using System.Text;

class LicensePlateMessageDecoder
{
    static void Main()
    {
        // The raw message to decode
        string rawMessageHex = "0201000000BC000000020002000D00000006000000152700007BF6ED66A015C30933393542544E0000000000000000000000000000000000000000000000000000000000000000000064646464646464646464646464646464646464646464646464646464646464646464646464646464013339352042544E00000000000000000000000000000000000000000000000000000000000000000045542842290000000000000000000000000000000000000000000000000000008C03";

        byte[] message = HexStringToByteArray(rawMessageHex);
        DecodeLicensePlateInfoMessage(message);
    }

    // Convert hex string to byte array
    private static byte[] HexStringToByteArray(string hex)
    {
        int length = hex.Length;
        byte[] data = new byte[length / 2];

        for (int i = 0; i < length; i += 2)
        {
            data[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return data;
    }

    private static void DecodeLicensePlateInfoMessage(byte[] message)
    {
        Console.WriteLine("Decoded License Plate Info Message:");

        // STX (Start of Text)
        Console.WriteLine($"STX: {message[0]:X2} ({message[0]})");

        // Unit ID (4 bytes)
        Console.WriteLine($"Unit ID: {BitConverter.ToString(message, 1, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 1)})");

        // Size (4 bytes)
        Console.WriteLine($"Size: {BitConverter.ToString(message, 5, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 5)})");

        // Type (2 bytes)
        Console.WriteLine($"Type: {BitConverter.ToString(message, 9, 2).Replace("-", "")} ({BitConverter.ToUInt16(message, 9)})");

        // Version (2 bytes)
        Console.WriteLine($"Version: {BitConverter.ToString(message, 11, 2).Replace("-", "")} ({BitConverter.ToUInt16(message, 11)})");

        // ID (4 bytes)
        Console.WriteLine($"ID: {BitConverter.ToString(message, 13, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 13)})");

        // Car ID (4 bytes)
        Console.WriteLine($"Car ID: {BitConverter.ToString(message, 17, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 17)})");

        // Trigger ID (4 bytes)
        Console.WriteLine($"Trigger ID: {BitConverter.ToString(message, 21, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 21)})");

        // Timestamp (4 bytes) - Unix timestamp
        Console.WriteLine($"Timestamp: {BitConverter.ToString(message, 25, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 25)})");

        // TimestampUSec (4 bytes)
        Console.WriteLine($"TimestampUSec: {BitConverter.ToString(message, 29, 4).Replace("-", "")} ({BitConverter.ToUInt32(message, 29)})");

        // Detected Chars (40 bytes) - Null-terminated ASCII
        string detectedChars = Encoding.ASCII.GetString(message, 33, 40).TrimEnd('\0');
        Console.WriteLine($"Detected Chars: {BitConverter.ToString(message, 33, 40).Replace("-", "")} (\"{detectedChars}\")");

        // Qualities (40 bytes) - Decimal representation of each byte
        Console.WriteLine("Qualities: ");
        for (int i = 73; i < 113; i++)
        {
            Console.Write($"{message[i]:X2} ({message[i]}) ");
        }
        Console.WriteLine();

        // Grammar OK (1 byte)
        Console.WriteLine($"Grammar OK: {message[113]:X2} ({message[113]})");

        // Printable String (40 bytes) - Null-terminated ASCII
        string printableString = Encoding.ASCII.GetString(message, 114, 40).TrimEnd('\0');
        Console.WriteLine($"Printable String: {BitConverter.ToString(message, 114, 40).Replace("-", "")} (\"{printableString}\")");

        // Country (32 bytes) - Null-terminated ASCII
        string country = Encoding.ASCII.GetString(message, 154, 32).TrimEnd('\0');
        Console.WriteLine($"Country: {BitConverter.ToString(message, 154, 32).Replace("-", "")} (\"{country}\")");

        // BCC (Block Check Character)
        Console.WriteLine($"BCC: {message[186]:X2} ({message[186]})");

        // ETX (End of Text)
        Console.WriteLine($"ETX: {message[187]:X2} ({message[187]})");
    }
}
