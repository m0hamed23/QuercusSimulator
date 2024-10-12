using System;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog;

namespace QuercusSimulator
{
    public static class LPRService2
    {
        public static string LPRServerIP = JsonConfigManager.GetValueForKey("LPRServerIP");
        public static int LPRServerPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("LPRServerPort"));

        public static async Task<LPNResult> CaptureLPNAsync(string transactionID, byte[] imageData)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    await client.ConnectAsync(LPRServerIP, LPRServerPort);
                    using (NetworkStream stream = client.GetStream())
                    {
                        // Prepare the request message
                        var requestData = new
                        {
                            TransactionID = transactionID,
                            ImageData = Convert.ToBase64String(imageData)
                        };
                        string requestJson = JsonSerializer.Serialize(requestData);

                        // Send the request
                        byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);
                        await stream.WriteAsync(requestBytes, 0, requestBytes.Length);

                        // Read the response
                        byte[] buffer = new byte[4096];
                        using (MemoryStream ms = new MemoryStream())
                        {
                            int bytesRead;
                            while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                            {
                                ms.Write(buffer, 0, bytesRead);
                            }
                            string responseData = Encoding.UTF8.GetString(ms.ToArray());
                            Log.Information($"Raw response from server: {responseData}");

                            if (string.IsNullOrEmpty(responseData))
                            {
                                return null;
                            }

                            var responseJson = JsonSerializer.Deserialize<Dictionary<string, string>>(responseData);

                            if (responseJson != null && responseJson.ContainsKey("LPN"))
                            {
                                string lpn = responseJson["LPN"];
                                string imageFilePathBase = responseJson["ImageFilePath"];
                                string newImagePath = imageFilePathBase + ".png";
                                string croppedLPImagePath = imageFilePathBase + "_LP.png";
                                string arabicLPN = lpn;
                                Log.Information($"License Plate: {arabicLPN}");

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
                                Log.Information($"License Plate: Null");
                                return null;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Log.Error($"LPR Error: {ex.Message}");
                return null;
            }
        }
    }

    public class LPNResult2
    {
        public string ArabicLPN { get; set; }
        public string BaseLPRImagePath { get; set; }
        public string NewImagePath { get; set; }
        public string CroppedLPImagePath { get; set; }
    }
}