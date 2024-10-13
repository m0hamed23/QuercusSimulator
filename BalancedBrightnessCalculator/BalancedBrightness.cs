using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

class BalancedBrightness
{
    static void Main(string[] args)
    {
        string directoryPath = @"D:\Quercus\brightness\LPR\test";
        List<(string fileName, double score)> imageScores = new List<(string, double)>();

        foreach (string filePath in Directory.GetFiles(directoryPath, "*.jpg"))
        {
            double score = CalculateImageScore(filePath);
            imageScores.Add((Path.GetFileName(filePath), score));
        }

        // Sort images by score (lower is better)
        var sortedScores = imageScores.OrderBy(x => x.score).ToList();

        // Print results
        Console.WriteLine("Image Scores (lower is better):");
        foreach (var (fileName, score) in sortedScores)
        {
            Console.WriteLine($"{fileName}: {score:F4}");
        }
    }

    static double CalculateImageScore(string filePath)
    {
        using (var image = SixLabors.ImageSharp.Image.Load<Rgb24>(filePath))
        {
            const int gridSize = 16; // Divide image into 16x16 grid
            int cellWidth = image.Width / gridSize;
            int cellHeight = image.Height / gridSize;

            double overallBrightness = 0;
            List<double> cellBrightnesses = new List<double>();

            for (int y = 0; y < gridSize; y++)
            {
                for (int x = 0; x < gridSize; x++)
                {
                    double cellBrightness = CalculateCellBrightness(image, x * cellWidth, y * cellHeight, cellWidth, cellHeight);
                    cellBrightnesses.Add(cellBrightness);
                    overallBrightness += cellBrightness;
                }
            }

            overallBrightness /= (gridSize * gridSize);

            // Calculate brightness variance
            double brightnessVariance = cellBrightnesses.Select(b => Math.Pow(b - overallBrightness, 2)).Average();

            // Calculate score (lower is better)
            const double targetBrightness = 0.35;
            double brightnessScore = Math.Abs(overallBrightness - targetBrightness);
            double varianceScore = brightnessVariance * 10; // Adjust weight as needed

            //return brightnessScore + varianceScore;
            return varianceScore;

        }
    }

    static double CalculateCellBrightness(Image<Rgb24> image, int startX, int startY, int width, int height)
    {
        double totalBrightness = 0;
        int pixelCount = 0;

        for (int y = startY; y < startY + height && y < image.Height; y++)
        {
            for (int x = startX; x < startX + width && x < image.Width; x++)
            {
                Rgb24 pixel = image[x, y];
                double brightness = (0.299 * pixel.R + 0.587 * pixel.G + 0.114 * pixel.B) / 255.0;
                totalBrightness += brightness;
                pixelCount++;
            }
        }

        return totalBrightness / pixelCount;
    }
}
//using System;
//using System.Collections.Generic;
//using System.IO;
//using System.Linq;
//using SixLabors.ImageSharp;
//using SixLabors.ImageSharp.PixelFormats;

//class Program
//{
//    static void Main(string[] args)
//    {
//        string directoryPath = @"D:\Quercus\brightness\LPR\test";
//        List<(string fileName, double brightness, double variance)> imageScores = new List<(string, double, double)>();

//        foreach (string filePath in Directory.GetFiles(directoryPath, "*.jpg"))
//        {
//            (double brightness, double variance) = AnalyzeImage(filePath);
//            imageScores.Add((Path.GetFileName(filePath), brightness, variance));
//        }

//        // Filter images with brightness between 0.1 and 0.6
//        var filteredImages = imageScores.Where(x => x.brightness >= 0.2 && x.brightness <= 0.6).ToList();

//        if (filteredImages.Count == 0)
//        {
//            Console.WriteLine("No images found with brightness between 0.1 and 0.6");
//            return;
//        }

//        // Select the image with the least variance
//        var bestImage = filteredImages.OrderBy(x => x.variance).First();

//        Console.WriteLine("Best Image:");
//        Console.WriteLine($"Filename: {bestImage.fileName}");
//        Console.WriteLine($"Brightness: {bestImage.brightness:F4}");
//        Console.WriteLine($"Variance: {bestImage.variance:F4}");

//        Console.WriteLine("\nAll Filtered Images:");
//        foreach (var (fileName, brightness, variance) in filteredImages.OrderBy(x => x.variance))
//        {
//            Console.WriteLine($"{fileName}: Brightness = {brightness:F4}, Variance = {variance:F4}");
//        }
//    }

//    static (double brightness, double variance) AnalyzeImage(string filePath)
//    {
//        using (var image = Image.Load<Rgb24>(filePath))
//        {
//            const int gridSize = 16; // Divide image into 16x16 grid
//            int cellWidth = image.Width / gridSize;
//            int cellHeight = image.Height / gridSize;

//            List<double> cellBrightnesses = new List<double>();

//            for (int y = 0; y < gridSize; y++)
//            {
//                for (int x = 0; x < gridSize; x++)
//                {
//                    double cellBrightness = CalculateCellBrightness(image, x * cellWidth, y * cellHeight, cellWidth, cellHeight);
//                    cellBrightnesses.Add(cellBrightness);
//                }
//            }

//            double overallBrightness = cellBrightnesses.Average();
//            double variance = CalculateVariance(cellBrightnesses, overallBrightness);

//            return (overallBrightness, variance);
//        }
//    }

//    static double CalculateCellBrightness(Image<Rgb24> image, int startX, int startY, int width, int height)
//    {
//        double totalBrightness = 0;
//        int pixelCount = 0;

//        for (int y = startY; y < startY + height && y < image.Height; y++)
//        {
//            for (int x = startX; x < startX + width && x < image.Width; x++)
//            {
//                Rgb24 pixel = image[x, y];
//                double brightness = (0.299 * pixel.R + 0.587 * pixel.G + 0.114 * pixel.B) / 255.0;
//                totalBrightness += brightness;
//                pixelCount++;
//            }
//        }

//        return totalBrightness / pixelCount;
//    }

//    static double CalculateVariance(List<double> values, double mean)
//    {
//        return values.Sum(v => Math.Pow(v - mean, 2)) / values.Count;
//    }
//}