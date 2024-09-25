﻿using System;
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
            private static string ServerIP = "127.0.0.1"; // Server IP address


            private static int serverPort = 65432; // Server port number
            private static byte[] buffer = new byte[1024];

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
                            Console.WriteLine($"Trigger: {transactionID}");
                            byte[] requestData = Encoding.ASCII.GetBytes(requestMessage);
                            await stream.WriteAsync(requestData, 0, requestData.Length);
                            int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                            string responseData = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                            Console.WriteLine($"Raw response from server: {responseData}");

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
