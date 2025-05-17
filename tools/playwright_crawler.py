import asyncio
from playwright.async_api import async_playwright

TARGET_URLS = [
    "http://example.com",
    "http://example.com/login",
    "http://example.com/dashboard"
]

BURP_PROXY = "http://127.0.0.1:8080"

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(proxy={"server": BURP_PROXY})
        page = await context.new_page()

        for url in TARGET_URLS:
            print(f"[+] Visiting {url}")
            try:
                await page.goto(url, timeout=30000)
                await page.wait_for_timeout(3000)  # allow JS to load
            except Exception as e:
                print(f"[!] Failed to load {url}: {e}")

        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
