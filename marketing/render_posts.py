"""
Render all Instagram posts as PNG images using Playwright.
This converts the HTML posts into actual 1080x1080 PNG files.
"""
import asyncio
import os
from playwright.async_api import async_playwright

INSTAGRAM_DIR = r"C:\Users\neela\OneDrive\Documents\Python\Cereberus\cereberus\marketing\instagram"
RENDERS_DIR = os.path.join(INSTAGRAM_DIR, "renders")

POSTS = [
    "post-1-intro.html",
    "post-2-commander-bond.html",
    "post-3-pipeline.html",
    "post-4-before-after.html",
    "post-5-architecture.html",
    "ad-1-awareness.html",
    "ad-2-conversion.html",
]


async def main():
    os.makedirs(RENDERS_DIR, exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1080, "height": 1080},
            device_scale_factor=2,
        )
        page = await context.new_page()

        for post_file in POSTS:
            filepath = os.path.join(INSTAGRAM_DIR, post_file)
            out_name = post_file.replace(".html", ".png")
            out_path = os.path.join(RENDERS_DIR, out_name)

            print(f"[*] Rendering: {post_file}")
            try:
                file_url = f"file:///{filepath.replace(os.sep, '/')}"
                await page.goto(file_url, wait_until="domcontentloaded")
                await page.wait_for_timeout(3000)  # Let animations start, fonts load

                await page.screenshot(
                    path=out_path,
                    full_page=False,
                    clip={"x": 0, "y": 0, "width": 1080, "height": 1080},
                )
                print(f"  [+] {out_name}")
            except Exception as e:
                err_str = str(e).encode('ascii', 'replace').decode()
                print(f"  [!] Error: {err_str[:100]}")

        await browser.close()
        print(f"\n[*] All renders saved to {RENDERS_DIR}")


if __name__ == "__main__":
    asyncio.run(main())
