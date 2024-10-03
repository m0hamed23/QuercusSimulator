using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace QuercusSimulator
{
    public static class GlobalVariables
    {

        public static int CameraMainPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("CameraMainPort"));
        public static int CameraConfigPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("CameraConfigPort"));
        public static string ServerIP = JsonConfigManager.GetValueForKey("ServerIP");
        public static string RealCamIP = JsonConfigManager.GetValueForKey("RealCamIP");
        public static int RealCamMainPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("RealCamMainPort"));
        public static int ServerMainPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("ServerMainPort"));
        public static int ServerConfigPort = Convert.ToInt32(JsonConfigManager.GetValueForKey("ServerConfigPort"));
        public static string ImagePath = JsonConfigManager.GetValueForKey("ImagePath");
        public static string LogFilePath = JsonConfigManager.GetValueForKey("LogFilePath");


    }
}
