using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
namespace TriggerLPR
{

        public static class LPRService
        {
            private static string serverIpAddress = "127.0.0.1"; // Server IP address
                                                                 //private static string serverIpAddress = "10.0.0.21"; // Server IP address
            private static string ServerIP = "10.0.0.100"; // Server IP address


            private static int serverPort = 65432; // Server port number
            private static byte[] buffer = new byte[1024];
            private static string lastImagePath = null;
            private static string lastCroppedLPImagePath = null;

            private static readonly Dictionary<char, char> charMapping = new Dictionary<char, char>()
        {
            {'A', 'أ'}, {'B', 'ب'}, {'G', 'ج'}, {'D', 'د'}, {'R', 'ر'},
            {'S', 'س'}, {'C', 'ص'}, {'T', 'ط'}, {'E', 'ع'}, {'F', 'ف'},
            {'K', 'ق'}, {'L', 'ل'}, {'M', 'م'}, {'N', 'ن'}, {'H', 'ﻫ'},
            {'W', 'و'}, {'Y', 'ی'}, {'0', '٠'}, {'1', '1'}, {'2', '2'},
            {'3', '3'}, {'4', '4'}, {'5', '5'}, {'6', '6'}, {'7', '7'},
            {'8', '8'}, {'9', '9'}
        };
            private static readonly Dictionary<char, char> charMappingArNumbers = new Dictionary<char, char>()
        {
                {'0', '٠'}, {'1', '١'}, {'2', '٢'},
                {'3', '٣'}, {'4', '٤'}, {'5', '٥'}, {'6', '٦'}, {'7', '٧'},
                {'8', '٨'}, {'9', '٩'}
        };
            public static async Task<LPNResult> CaptureLPNAsync(string transactionID)
            {
                try
                {
                    serverIpAddress = "127.0.0.1";
                    using (TcpClient client = new TcpClient())
                    {
                        await client.ConnectAsync(serverIpAddress, serverPort);
                        using (NetworkStream stream = client.GetStream())
                        {
                            string requestMessage = $"Trigger {transactionID}";
                            byte[] requestData = Encoding.ASCII.GetBytes(requestMessage);
                            await stream.WriteAsync(requestData, 0, requestData.Length);

                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                            string responseData = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            Console.WriteLine($"responseData: {responseData}");

                        if (string.IsNullOrEmpty(responseData))
                            {

                            //MessageBox.Show("Received empty response from server.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                            return null;
                            }

                            var responseJson = JsonSerializer.Deserialize<Dictionary<string, string>>(responseData);

                            if (responseJson != null && responseJson.ContainsKey("LPN"))
                            {
                                string lpn = responseJson["LPN"];
                                string imageFilePathBase = responseJson["ImageFilePath"];
                                string newImagePath = imageFilePathBase + ".png";
                                string croppedLPImagePath = imageFilePathBase + "_LP.png";
                                //string arabicLPN = ConvertToArabic(lpn);
                                string arabicLPN = lpn;
                            Console.WriteLine($"License Plate: {arabicLPN}");

                            return new LPNResult
                                {
                                    ArabicLPN = arabicLPN,
                                    BaseLPRImagePath = imageFilePathBase,
                                    NewImagePath = newImagePath,
                                    CroppedLPImagePath = croppedLPImagePath
                                };
                            }
                            else
                            {
                                Console.WriteLine($"License Plate: Null");

                                return null;

                            }
                    }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"LPR Error: {ex.Message}");
                    return null;
                }
            }
        }
        public class LPNResult
        {
            public string ArabicLPN { get; set; }
            public string BaseLPRImagePath { get; set; }
            public string NewImagePath { get; set; }
            public string CroppedLPImagePath { get; set; } // New property for cropped license plate image path
        }


}
