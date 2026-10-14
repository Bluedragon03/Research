import asyncio
from playwright.async_api import async_playwright
import re
import csv
import os
import dateparser

async def fetch_latest_scams():
    async with async_playwright() as p:
        # Launch browser with chromium args to minimize bot detection
        browser = await p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 800}
        )
        page = await context.new_page()

        print("Navigating to latest page...")
        # Load DOM content
        await page.goto("https://www.scamner.com/latest", wait_until="domcontentloaded", timeout=30000)

        # Pause briefly and scroll to trigger lazy loading
        await asyncio.sleep(2)
        await page.evaluate("window.scrollTo(0, 500)")
        await asyncio.sleep(1)

        # Extract all links and filter in JavaScript
        scams = await page.evaluate("""
            () => {
                const links = Array.from(document.querySelectorAll('a'));
                const results = [];

                links.forEach(a => {
                    const href = a.href || '';
                    const text = a.innerText.trim();

                    // Filter for domain checks or site inspection routes
                    if (href.includes('/check/') || href.includes('/site/')) {
                        const container = a.closest('tr') || a.closest('li') || a.parentElement;
                        results.push({
                            domain: text,
                            url: href,
                            container_text: container ? container.innerText.replace(/\\s+/g, ' ').trim() : ''
                        });
                    }
                });

                return results;
            }
        """)

        await browser.close()
        return scams

def extract_time(text):
    """
    Extracts relative timestamps ('2 hours ago', '1 day ago') from text
    and converts them to MM/DD/YYYY format. Safely handles NoneType matches.
    """
    print(text)
    # Match patterns like '2 hours ago', '15 mins ago', '1 day ago'
    match = re.search(
        r"(\d+\s+(?:sec|second|min|minute|hour|day|week|month|year)s?\s+ago)",
        text,
        re.IGNORECASE,
    )

    if match:
        relative_str = match.group(1)
        dt = dateparser.parse(relative_str)
        if dt:
            return dt.strftime("%m/%d/%Y")

def save_to_csv(scraped_items, filename="Website_List.csv"):
    """Appends unique entries to CSV, initializing headers if file doesn't exist."""
    headers = ["url", "source", "type", "report_date"]
    existing_urls = set()

    # Load existing URLs to prevent duplicate entries
    if os.path.exists(filename):
        with open(filename, mode="r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if "url" in row:
                    existing_urls.add(row["url"])

    new_entries = []
    for item in scraped_items:
        url = item["domain"]
        # Skip duplicates
        if "https://" + url in existing_urls:
            continue

        report_date = extract_time(item["container_text"])
        new_entries.append(
            {
                "url": "https://" + url,
                "source": "https://www.scamner.com/latest",
                "type": "scam",
                "report_date": report_date,
            }
        )
        existing_urls.add(url)

    # Append new records to the CSV file
    file_exists = os.path.exists(filename)
    if new_entries:
        with open(filename, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)

            # Write header row only if file is newly created
            if not file_exists or os.path.getsize(filename) == 0:
                writer.writeheader()

            writer.writerows(new_entries)

        print(f"Added {len(new_entries)} new records to '{filename}'.")
    else:
        print("No new records found. CSV is up to date.")

if __name__ == "__main__":
    results = asyncio.run(fetch_latest_scams())
    print(f"\nSuccessfully parsed {len(results)} items:\n")
    save_to_csv(results)