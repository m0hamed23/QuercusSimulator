using System;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.PixelFormats;
using SixLabors.ImageSharp.Processing;

public class ImageBrightnessCalculator
{
    public static void Main(string[] args)
    {
        string imagePath = @"D:\currentimage4.jpg";

        try
        {
            using (Image<Rgba32> image = SixLabors.ImageSharp.Image.Load<Rgba32>(imagePath))
            {
                double brightness = CalculateBrightness(image);
                Console.WriteLine($"Average brightness of {imagePath}: {brightness:F4}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }

    private static double CalculateBrightness(Image<Rgba32> image)
    {
        double totalBrightness = 0;
        int pixelCount = image.Width * image.Height;

        image.ProcessPixelRows(accessor =>
        {
            for (int y = 0; y < accessor.Height; y++)
            {
                Span<Rgba32> pixelRow = accessor.GetRowSpan(y);

                for (int x = 0; x < pixelRow.Length; x++)
                {
                    ref Rgba32 pixel = ref pixelRow[x];
                    double pixelBrightness = (0.299 * pixel.R + 0.587 * pixel.G + 0.114 * pixel.B) / 255.0;
                    totalBrightness += pixelBrightness;
                }
            }
        });

        return totalBrightness / pixelCount;
    }
}