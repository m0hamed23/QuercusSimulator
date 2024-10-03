using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Newtonsoft.Json;
using Serilog;

namespace QuercusSimulator
{
    public static class JsonConfigManager
    {
        private static readonly string _filePath = "D:\\LPR\\SimulatorConfig.json"; // Hardcoded JSON file path

        public static string GetValueForKey(string key)
        {
            try
            {
                if (File.Exists(_filePath))
                {
                    string json = File.ReadAllText(_filePath);
                    var configValues = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);

                    if (configValues.TryGetValue(key, out string value))
                    {
                        return value;
                    }
                    else
                    {
                        Log.Information($"Key '{key}' not found in the JSON file.");
                        return null;
                    }
                }
                else
                {
                    Log.Information("JSON file does not exist. Returning null.");
                    return null;
                }
            }
            catch (Exception ex)
            {
                Log.Error($"Error loading JSON file: {ex.Message}");
                // Handle the error as needed
                return null;
            }
        }

        public static void UpdateValueForKey(string key, string newValue)
        {
            try
            {
                // Load existing configuration from JSON file
                string json = File.Exists(_filePath) ? File.ReadAllText(_filePath) : "{}";
                var configValues = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);

                // Update the value associated with the key
                configValues[key] = newValue;

                // Save the updated configuration back to the JSON file
                File.WriteAllText(_filePath, JsonConvert.SerializeObject(configValues, Newtonsoft.Json.Formatting.Indented));
            }
            catch (Exception ex)
            {
                Log.Error($"Error updating JSON file: {ex.Message}");
                // Handle the error as needed
            }
        }
    }

}
