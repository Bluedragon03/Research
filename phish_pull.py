import requests
from datetime import datetime
import os
import csv

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def format_iso_to_mm_dd_yyyy(iso_str):
    """Converts PhishTank's ISO 8601 submission string to MM/DD/YYYY."""
    if not iso_str:
        return datetime.now().strftime("%m/%d/%Y")
    try:
        # Handles ISO strings like "2026-09-23T14:32:10+00:00"
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%m/%d/%Y")
    except ValueError:
        return datetime.now().strftime("%m/%d/%Y")

def get_phish(limit=500):
    """Downloads online valid phishing reports from PhishTank and slices to limit."""
    pt_url = "https://data.phishtank.com/data/online-valid.json"
    headers = {"User-Agent": USER_AGENT}

    try:
        print("Fetching PhishTank feed...")
        resp = requests.get(pt_url, headers=headers, allow_redirects=True, timeout=60)
        
        if resp.status_code == 200:
            data = resp.json()
            # Limit payload to first 500 records
            target_data = data[:limit]
            
            results = []
            for item in target_data:
                raw_url = item.get("url")
                raw_time = item.get("submission_time")

                if raw_url:
                    results.append(
                        {
                            "url": raw_url,
                            "report_date": format_iso_to_mm_dd_yyyy(raw_time),
                        }
                    )

            print(f"PhishTank: Processing top {len(results)} records.")
            return results
        else:
            print(f"PhishTank HTTP Error: {resp.status_code}")
            return []

    except Exception as e:
        print(f"PhishTank Error: {e}")
        return []

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
        url = item["url"]
        # Skip duplicates
        if "https://" + url in existing_urls or url in existing_urls:
            continue

        if url.lower().startswith("https://") or url.lower().startswith("http://"):
            saved_url = url
        else:
            saved_url = "https://" + url

        new_entries.append(
            {
                "url": saved_url,
                "source": "https://data.phishtank.com/data/online-valid.json",
                "type": "phishing",
                "report_date": item["report_date"],
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
    new_phish = get_phish()
    save_to_csv(new_phish)
