"""
Playwright script to capture high-resolution screenshots of Cereberus modules.
Uses domcontentloaded (not networkidle) because the dashboard has active WebSocket connections.
"""
import asyncio
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = r"C:\Users\neela\OneDrive\Documents\Python\Cereberus\cereberus\marketing\instagram\screenshots"
BASE_URL = "http://127.0.0.1:8000"

PANELS = [
    ("CMD CENTER", "cmd-center", 4000),
    ("SIGINT", "sigint", 3000),
    ("THREAT BOARD", "threat-board", 3000),
    ("CMDR BOND", "commander-bond", 4000),
    ("AI OPS", "ai-ops", 3000),
    ("INCIDENT CMD", "incident-cmd", 2500),
    ("FUSION CTR", "fusion-center", 3000),
    ("THREAT ASMT", "threat-assessment", 2500),
    ("INTEL BRIEF", "intel-briefing", 2500),
    ("DETECT RULES", "detection-rules", 2500),
    ("SYS DIAG", "sys-diagnostics", 2500),
    ("WATCHLIST", "watchlist", 2500),
    ("DEF PROTOCOL", "defense-protocols", 2500),
    ("OPS BOARD", "ops-board", 2500),
    ("MEM RECON", "memory-recon", 2500),
    ("SEC PROTOCOL", "security-protocol", 3000),
    ("ASSET TRKR", "asset-tracker", 2500),
    ("OPS LOG", "ops-log", 2500),
]


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=2,
        )
        page = await context.new_page()

        # Step 1: Navigate to login page first
        print("[*] Loading login page...")
        await page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")
        await page.wait_for_timeout(3000)

        # Step 2: Login via API to set httpOnly cookie
        print("[*] Logging in via API...")
        login_response = await page.evaluate("""
            async () => {
                const resp = await fetch('/api/v1/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: 'admin', password: 'admin' }),
                    credentials: 'include',
                });
                return { status: resp.status, data: await resp.json() };
            }
        """)
        print(f"[*] Login status: {login_response['status']}")

        token = login_response.get("data", {}).get("access_token", "")
        csrf = login_response.get("data", {}).get("csrf_token", "")
        if token:
            await page.evaluate(f"""() => {{
                localStorage.setItem('token', '{token}');
                localStorage.setItem('csrf_token', '{csrf}');
            }}""")
            print("[*] Token stored in localStorage")

        # Step 3: Navigate to dashboard (use domcontentloaded - WS keeps it from networkidle)
        print("[*] Navigating to dashboard...")
        await page.goto(f"{BASE_URL}/dashboard", wait_until="domcontentloaded")
        await page.wait_for_timeout(6000)

        print(f"[*] Current URL: {page.url}")

        # If still on login, fill form manually
        if "/login" in page.url:
            print("[*] Still on login, filling form...")
            await page.fill('input[placeholder*="callsign" i]', "admin")
            await page.fill('input[type="password"]', "admin")
            await page.click('button[type="submit"]')
            await page.wait_for_timeout(6000)
            print(f"[*] URL after manual login: {page.url}")

        # If on change-password, handle it
        if "change-password" in page.url.lower():
            print("[*] Password change required...")
            inputs = await page.query_selector_all('input[type="password"]')
            if len(inputs) >= 3:
                await inputs[0].fill("admin")
                await inputs[1].fill("Admin123!@#new")
                await inputs[2].fill("Admin123!@#new")
                await page.click('button[type="submit"]')
                await page.wait_for_timeout(3000)

        # Debug screenshot
        await page.screenshot(path=f"{SCREENSHOTS_DIR}/_debug.png", full_page=False)
        page_text_len = await page.evaluate("() => document.body.innerText.length")
        print(f"[*] Dashboard loaded, body text length: {page_text_len}")

        # Expand all sidebar groups
        print("[*] Expanding sidebar groups...")
        for group_name in ["COMMAND", "INTELLIGENCE", "DEFENSE", "OPERATIONS", "ADMIN"]:
            try:
                btn = page.locator(f'button:has-text("{group_name}")').first
                if await btn.is_visible(timeout=1000):
                    await btn.click()
                    await page.wait_for_timeout(300)
            except:
                pass

        await page.wait_for_timeout(500)

        # Capture each panel
        success_count = 0
        for nav_label, filename, wait_ms in PANELS:
            print(f"[*] Capturing: {nav_label}")
            try:
                btn = page.locator(f'button:has-text("{nav_label}")').first
                if await btn.is_visible(timeout=2000):
                    await btn.click()
                    await page.wait_for_timeout(wait_ms)
                    await page.screenshot(
                        path=f"{SCREENSHOTS_DIR}/{filename}.png",
                        full_page=False,
                    )
                    success_count += 1
                    print(f"  [+] {filename}.png")
                else:
                    print(f"  [!] Not visible: {nav_label}")
            except Exception as e:
                err_str = str(e).encode('ascii', 'replace').decode()
                print(f"  [!] Error: {err_str[:80]}")

        # Full dashboard with CMD CENTER
        print("[*] Final captures...")
        try:
            btn = page.locator('button:has-text("CMD CENTER")').first
            if await btn.is_visible(timeout=2000):
                await btn.click()
                await page.wait_for_timeout(4000)
        except:
            pass
        await page.screenshot(path=f"{SCREENSHOTS_DIR}/full-dashboard.png", full_page=False)
        print("  [+] full-dashboard.png")

        # Sidebar
        try:
            sidebar = page.locator('nav').first
            if await sidebar.is_visible(timeout=2000):
                await sidebar.screenshot(path=f"{SCREENSHOTS_DIR}/sidebar.png")
                print("  [+] sidebar.png")
        except:
            pass

        # Login page
        print("[*] Capturing login page...")
        await context.clear_cookies()
        await page.evaluate("() => localStorage.clear()")
        await page.goto(f"{BASE_URL}/login", wait_until="domcontentloaded")
        await page.wait_for_timeout(3000)
        await page.screenshot(path=f"{SCREENSHOTS_DIR}/login-page.png", full_page=False)
        print("  [+] login-page.png")

        await browser.close()
        print(f"\n[*] Done! {success_count} panels + extras captured.")


if __name__ == "__main__":
    asyncio.run(main())
