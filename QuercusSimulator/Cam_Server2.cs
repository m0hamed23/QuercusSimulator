using QuercusSimulator;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using System.Text.Json;
using Serilog;
using static QuercusSimulator.MessageBuilder;
namespace QuercusSimulator
{
    class LPRSimulator
    {

        public static int SimulatorMainPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("CameraMainPort"));
        public static int SimulatorConfigPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("CameraConfigPort"));
        public static string ZRIP = JsonConfigManager.GetValueForKey("ServerIP");
        //public static string RealCamIP = JsonConfigManager.GetValueForKey("RealCamIP");
        //public static int RealCamMainPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("RealCamMainPort"));
        public static int ZRMainPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("ServerMainPort"));
        public static int ZRConfigPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("ServerConfigPort"));
        //public static string LogFilePath = JsonConfigManager.GetValueForKey("LogFilePath");
        private static readonly string LogFilePath = "C:\\LPR\\EventImages\\Logs\\"; // Hardcoded JSON file path

        //public static uint UnitId = Convert.ToUInt32(JsonConfigManager.GetValueForKey("UnitId"));
        //public static string TriggerText = JsonConfigManager.GetValueForKey("TriggerText");


        static uint lastid = 1;
        static uint lastcarId = 1;
        static uint id = 1;
        static uint carId = 1;
        //private const int CameraMainPort = 7051; // First port to listen on
        //private const int CameraConfigPort = 7041; // Second port to listen on
        //private const string ServerIP = "10.0.0.10";
        //private const string RealCamIP = "10.0.0.110";
        //private const int RealCamMainPort = 6051; // Second port to listen on
        //private const int ServerMainPort = 7050;    // Default port for sending responses
        //private const int ServerConfigPort = 7040; // Port for sending ping responses
        //static uint lastid = 1;
        //static uint lastcarId = 1;
        //static uint id = 1;
        //static uint carId = 1;
        static async Task Main(string[] args)
        {
            ConfigureLogging(); // Call the method to set up Serilog

            Log.Information("LPR Simulator starting...");
            Log.Error("An error occurred.");
            //Log.CloseAndFlush(); // Ensure logs are flushed before application exit

            // Start the camera simulators for both ports
            Task listenOnPort1 = RunCameraSimulatorAsync(SimulatorMainPort);
            Task listenOnPort2 = RunCameraSimulatorAsync(SimulatorConfigPort);

            // Wait for both tasks to complete (they run indefinitely)
            await Task.WhenAll(listenOnPort1, listenOnPort2);

        }
        private static async Task RunCameraSimulatorAsync(int port)
        {
            using (var udpClient = new UdpClient(port))
            {
                Log.Information($"Camera simulator listening on port {port}");

                while (true)
                {
                    try
                    {
                        var (message, remoteEndPoint) = await UdpLargeMessageHandler.ReceiveLargeMessageAsync(udpClient);

                        if (message == null || message.Length < 19)
                        {
                            Log.Information("Invalid or too short UDP message. Ignoring.");
                            continue;
                        }

                        // Process each message in a separate task to handle concurrency
                        _ = Task.Run(async () =>
                        {
                            await ProcessCameraMessageAsync(udpClient, message);
                        });
                    }
                    catch (Exception ex)
                    {
                        Log.Error($"Error in camera simulator: {ex.Message}");
                    }
                }
            }
        }

        // Method to configure Serilog
        private static void ConfigureLogging()
        {
            // Set up Serilog to log to the file specified in LogFilePath
            Log.Logger = new LoggerConfiguration()
                .WriteTo.File($"{LogFilePath}simulatorlog.txt", // Save logs to logfile.txt in the specified folder
                              rollingInterval: RollingInterval.Day, // Creates a new log file daily
                              retainedFileCountLimit: 7, // Retain last 7 log files
                              rollOnFileSizeLimit: true)
                .CreateLogger();
        }

        private static async Task ProcessCameraMessageAsync(UdpClient udpClient, byte[] message)
        {
            if (message.Length < 19)
            {
                Log.Information($"Received message is too short (length: {message.Length})");
                return;
            }
            IPEndPoint remoteEndPoint = new IPEndPoint(IPAddress.Parse(ZRIP), ZRMainPort);
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
                    remoteEndPoint = new IPEndPoint(IPAddress.Parse(ZRIP), ZRConfigPort);
                    break;
                default:
                    Log.Information($"Unsupported message type: 0x{messageType:X4}");
                    return;
            }

            if (response != null)
            {

                await udpClient.SendAsync(response, response.Length, remoteEndPoint);
                //LogMessage("Camera", "Server", response);
            }

            if (messageType == 0x4300) // Trigger Request
            {
                Log.Information($"############# after trigger ack time: {DateTime.Now.ToString("HH:mm:ss.fff")}");

                //uint Id = 13;
                //uint TriggerId = 11;
                uint unitId = BitConverter.ToUInt32(message, 1);
                uint Id = BitConverter.ToUInt32(message, 13);
                uint TriggerId = BitConverter.ToUInt32(message, 17);

                // Initialize cameraEndPoint with default values
                IPEndPoint cameraEndPoint = null;

                // Get RealCam IP and Port based on UnitId
                (string realCamIP, int realCamMainPort) = JsonConfigManager.GetCameraInfoByUnitId(unitId);

                //if (realCamIP != null && realCamMainPort != 0)
                //{
                //    cameraEndPoint = new IPEndPoint(IPAddress.Parse(realCamIP), realCamMainPort);
                //    Log.Information($"Camera IP: {realCamIP}, Port: {realCamMainPort}");
                //    await SendTriggerRequestAsync(cameraEndPoint, unitId, Id, TriggerId);
                //}
                //else
                //{
                //    Log.Error($"Invalid camera configuration for UnitId {unitId}");
                //}

                //IPEndPoint cameraEndPoint = new IPEndPoint(IPAddress.Parse(RealCamIP), RealCamMainPort);

                //LPNResult LastLPNResult = await QuercusSimulator.LPRService.CaptureLPNAsync("10.0.0.111");
                int cameraSendPort = 6051;
                int cameraReceivePort = 6050;
                string OutputDirectory = @"D:\LPR\EventImages";
                int[] exposureTimes = { 75000, 200000, 500000 };
                int[] ids = { 120, 122, 124 };

                await CurrentFrame.GetAndSaveImages(unitId, realCamIP, exposureTimes, ids, OutputDirectory, cameraSendPort, cameraReceivePort);
                {
                    LPNResult LastLPNResult = await QuercusSimulator.LPRService.CaptureLPNAsync(realCamIP);


                    //LPNResult LastLPNResult = new LPNResult();

                    //LastLPNResult.ArabicLPN = "395BTN";

                    //string newDetectedChars = "123ASD";
                    //string newPrintableString = "123 ASD";
                    if (LastLPNResult != null)
                    //if (true)

                    {
                        //uint triggerId = BitConverter.ToUInt32(message, 17);
                        //uint unitId = BitConverter.ToUInt32(message, 1);

                        string newDetectedChars = LastLPNResult.ArabicLPN;
                        //string newDetectedChars = "395BTN";

                        string newPrintableString = newDetectedChars;
                        Log.Information($"newDetectedChars:{newDetectedChars}");
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
                        byte[] licensePlateInfoMessage = LPInfoMessage.CreateLicensePlateInfoMessage(unitId, id, carId, TriggerId, newDetectedChars);
                        await udpClient.SendAsync(licensePlateInfoMessage, licensePlateInfoMessage.Length, remoteEndPoint);


                        // Display the raw message as a hexadecimal string
                        //Log.Information("Raw License Plate Info Message (hex): " + BitConverter.ToString(licensePlateInfoMessage).Replace("-", ""));
                    }
                    else
                    {
                        Log.Information($"LastLPNResult is null");


                    }
                    Log.Information($"############# sent LPN time: {DateTime.Now.ToString("HH:mm:ss.fff")}");


                }
            }


        }

    }
}
