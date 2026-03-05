from playwright.sync_api import sync_playwright

print("Starting Playwright test...")

with sync_playwright() as p:
    print("Launching browser...")
    browser = p.chromium.launch()

    page = browser.new_page()

    print("Navigating...")
    page.goto("https://example.com")

    title = page.title()
    print("Page title:", title)

    browser.close()

print("Finished.")