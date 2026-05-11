using Microsoft.Playwright; // ESSENCIAL: Resolve todos os erros de tipos do Playwright
using GhostScan.Domain.Entities;

namespace GhostScan.Infrastructure.ScanModules.Web.Engines;

public class ScreenshotEngine : IScreenshotEngine
{
    public async Task<string?> CaptureAsync(string url, CancellationToken ct)
    {
        try
        {
             using var playwright = await Microsoft.Playwright.Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = true
            });

            var page = await browser.NewPageAsync();

            await page.GotoAsync(url, new PageGotoOptions
            {
                WaitUntil = WaitUntilState.NetworkIdle
            });

            var bytes = await page.ScreenshotAsync();
            return Convert.ToBase64String(bytes);
        }
        catch (Exception)
        {
            return null;
        }
    }
}