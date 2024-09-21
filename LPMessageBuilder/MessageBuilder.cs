//using System;
//using System.Text;

//class LicensePlateMessageBuilder
//{
//    static void Main()
//    {
//        byte[] message = CreateLicensePlateInfoMessage();
//        Console.WriteLine("Raw License Plate Info Message (hex): " + BitConverter.ToString(message).Replace("-", ""));
//    }

//    private static byte[] CreateLicensePlateInfoMessage()
//    {
//        // Total size of the message should be 188 bytes
//        byte[] message = new byte[188];

//        // STX (Start of Text)
//        message[0] = 0x02;

//        // Unit ID (4 bytes) - fixed 01000000 (1)
//        message[1] = 0x01;
//        message[2] = 0x00;
//        message[3] = 0x00;
//        message[4] = 0x00;

//        // Size (4 bytes) - BC000000 (188 bytes, little-endian)
//        message[5] = 0xBC;
//        message[6] = 0x00;
//        message[7] = 0x00;
//        message[8] = 0x00;

//        // Type (2 bytes) - License Info (0200)
//        message[9] = 0x02;
//        message[10] = 0x00;

//        // Version (2 bytes) - Version (0200)
//        message[11] = 0x02;
//        message[12] = 0x00;

//        // ID (4 bytes) - Fixed value 0D000000 (13)
//        message[13] = 0x0D;
//        message[14] = 0x00;
//        message[15] = 0x00;
//        message[16] = 0x00;

//        // Message Data (112 bytes) 
//        // Car Id (4 bytes) - Example value (e.g., 6)
//        message[17] = 0x06;
//        message[18] = 0x00;
//        message[19] = 0x00;
//        message[20] = 0x00;

//        // Trigger Id (4 bytes) - Example value (e.g., 0x00152700)
//        message[21] = 0x15;
//        message[22] = 0x27;
//        message[23] = 0x00;
//        message[24] = 0x00;

//        // Timestamp (4 bytes) - Example value (UNIX timestamp)
//        message[25] = 0x7E;
//        message[26] = 0x0B;
//        message[27] = 0xEC;
//        message[28] = 0x66;

//        // TimestampUSec (4 bytes) - Example value
//        message[29] = 0x81;
//        message[30] = 0xD2;
//        message[31] = 0x0D;
//        message[32] = 0x00;

//        // Detected Chars (40 bytes) - Example value (e.g., "395BTN")
//        string detectedChars = "395BTN";
//        byte[] detectedCharsBytes = Encoding.ASCII.GetBytes(detectedChars);
//        Buffer.BlockCopy(detectedCharsBytes, 0, message, 33, detectedCharsBytes.Length);

//        // Qualities (40 bytes) - Example values (e.g., all 100)
//        for (int i = 73; i < 113; i++)
//        {
//            message[i] = 0x64; // Quality = 100
//        }

//        // Grammar Ok (1 byte) - Example value (1 for grammar OK)
//        message[113] = 0x01;

//        // Printable String (40 bytes) - Example value (e.g., "395 BTN")
//        string printableString = "395 BTN";
//        byte[] printableStringBytes = Encoding.ASCII.GetBytes(printableString);
//        Buffer.BlockCopy(printableStringBytes, 0, message, 114, printableStringBytes.Length);

//        // Country (32 bytes) - Example value (e.g., "ESP")
//        string country = "ET";
//        byte[] countryBytes = Encoding.ASCII.GetBytes(country);
//        Buffer.BlockCopy(countryBytes, 0, message, 154, countryBytes.Length);

//        // BCC (Block Check Character) - XOR from STX to the last byte of Message Data
//        message[186] = CalculateXOR(message, 0, 186);

//        // ETX (End of Text)
//        message[187] = 0x03;

//        return message;
//    }

//    // Helper method to calculate the XOR for BCC
//    private static byte CalculateXOR(byte[] data, int start, int length)
//    {
//        byte xor = 0x00;
//        for (int i = start; i < length; i++)
//        {
//            xor ^= data[i];
//        }
//        return xor;
//    }
//}
using System;
using System.Text;

class LicensePlateMessageBuilder
{
    static void Main()
    {
        // Example input values for Unit ID, ID, Car ID, Trigger ID, and Detected Chars
        uint unitId = 1;
        uint id = 13;
        uint carId = 6;
        uint triggerId = 10005;
        string detectedChars = "395BTN";

        // Create the license plate info message with the provided parameters
        byte[] message = CreateLicensePlateInfoMessage(unitId, id, carId, triggerId, detectedChars);

        // Display the raw message as a hexadecimal string
        Console.WriteLine("Raw License Plate Info Message (hex): " + BitConverter.ToString(message).Replace("-", ""));
    }

    private static byte[] CreateLicensePlateInfoMessage(uint unitId, uint id, uint carId, uint triggerId, string detectedChars)
    {
        // Total size of the message should be 188 bytes
        byte[] message = new byte[188];

        // STX (Start of Text)
        message[0] = 0x02;

        // Unit ID (4 bytes) - Convert from decimal to little-endian
        Buffer.BlockCopy(BitConverter.GetBytes(unitId), 0, message, 1, 4);

        // Size (4 bytes) - BC000000 (188 bytes, little-endian)
        message[5] = 0xBC;
        message[6] = 0x00;
        message[7] = 0x00;
        message[8] = 0x00;

        // Type (2 bytes) - License Info (0200)
        message[9] = 0x02;
        message[10] = 0x00;

        // Version (2 bytes) - Version (0200)
        message[11] = 0x02;
        message[12] = 0x00;

        // ID (4 bytes) - Convert from decimal to little-endian
        Buffer.BlockCopy(BitConverter.GetBytes(id), 0, message, 13, 4);

        // Car Id (4 bytes) - Convert from decimal to little-endian
        Buffer.BlockCopy(BitConverter.GetBytes(carId), 0, message, 17, 4);

        // Trigger Id (4 bytes) - Convert from decimal to little-endian
        Buffer.BlockCopy(BitConverter.GetBytes(triggerId), 0, message, 21, 4);

        // Timestamp (4 bytes) - Get the current UNIX timestamp (seconds since 1st Jan 1970)
        uint timestamp = (uint)(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Buffer.BlockCopy(BitConverter.GetBytes(timestamp), 0, message, 25, 4);

        // TimestampUSec (4 bytes) - Microseconds part of the current time
        uint timestampUsec = (uint)(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() % 1000000) * 1000;
        Buffer.BlockCopy(BitConverter.GetBytes(timestampUsec), 0, message, 29, 4);

        // Detected Chars (40 bytes) - Convert detected characters to bytes
        byte[] detectedCharsBytes = Encoding.ASCII.GetBytes(detectedChars);
        Buffer.BlockCopy(detectedCharsBytes, 0, message, 33, detectedCharsBytes.Length);

        // Qualities (40 bytes) - Set all qualities to 100 (0x64)
        for (int i = 73; i < 113; i++)
        {
            message[i] = 0x64; // Quality = 100
        }

        // Grammar Ok (1 byte) - Set to 1 (grammar is OK)
        message[113] = 0x01;

        // Printable String (40 bytes) - Detected Chars with spaces between letters and numbers
        string printableString = AddSpaceBetweenCharsAndNumbers(detectedChars);
        byte[] printableStringBytes = Encoding.ASCII.GetBytes(printableString);
        Buffer.BlockCopy(printableStringBytes, 0, message, 114, printableStringBytes.Length);

        // Country (32 bytes) - Example value (e.g., "ET")
        string country = "ET(B)";
        byte[] countryBytes = Encoding.ASCII.GetBytes(country);
        Buffer.BlockCopy(countryBytes, 0, message, 154, countryBytes.Length);

        // BCC (Block Check Character) - XOR from STX to the last byte of Message Data
        message[186] = CalculateXOR(message, 0, 186);

        // ETX (End of Text)
        message[187] = 0x03;

        return message;
    }

    // Helper method to add a space between letters and numbers in a string
    private static string AddSpaceBetweenCharsAndNumbers(string input)
    {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < input.Length; i++)
        {
            result.Append(input[i]);
            if (i < input.Length - 1 && char.IsDigit(input[i]) && char.IsLetter(input[i + 1]))
            {
                result.Append(' ');
            }
        }
        return result.ToString();
    }

    // Helper method to calculate the XOR for BCC
    private static byte CalculateXOR(byte[] data, int start, int length)
    {
        byte xor = 0x00;
        for (int i = start; i < length; i++)
        {
            xor ^= data[i];
        }
        return xor;
    }
}
