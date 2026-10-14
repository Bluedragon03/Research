import asyncio
import argparse
import os
import hashlib
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from playwright.async_api import async_playwright
import json
import aiohttp
import re
import random
import dns.resolver
import pandas as pd
import requests
import ipinfo
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from publicsuffixlist import PublicSuffixList
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
import csv
from time import sleep
import whodap
import urllib.request
import zipfile
import io
from datetime import datetime, timezone
import functools
import time

FREE_CA_ISSUERS = [
    "Let's Encrypt", "ZeroSSL", "Cloudflare", "Google Trust Services", "Amazon", 
    "Buypass", "Sectigo", "SSL.com", "GoGetSSL", "TrustCor", "Comodo"
]

COMMERCIAL_CA_ISSUERS = [
    "DigiCert", "GlobalSign", "Entrust", "Thawte", 
    "GeoTrust", "RapidSSL", "Starfield", "USERTrust"
]

# Combined list for flagging ANY recognized CA
ALL_COMMON_CA_ISSUERS = FREE_CA_ISSUERS + COMMERCIAL_CA_ISSUERS

CHEAP_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".work", ".info", ".buzz", ".tk", ".ml"}
ECOM_PLATFORMS = ("myshopify.com", "bigcartel.com", "etsy.com", "wixsite.com", "squarespace.com", "weebly.com")

FALLBACK_WHOIS = {
    "de": "whois.denic.de",
    "lt": "whois.domreg.lt",
    "ie": "whois.iedr.ie",
    "se": "whois.iis.se",
    "ro": "whois.rotld.ro",
}

# Config
OUTPUT_DIR = "Results"
VIEWPORT = {"width": 1280, "height": 960}
HEADLESS = True
TIMEOUT = 45000  # Set a more aggressive timeout (45 seconds)
DOWNLOAD_TIMEOUT = 15 # Shorter timeout for individual files
MAX_JS_FILES = 10
MAX_SUSPICIOUS_FILES = 10
MAX_IMAGES_TO_DOWNLOAD = 10 # Variable for number of images

SUSPICIOUS_EXTENSIONS = {".exe", ".bin", ".dll", ".scr", ".apk", ".vbs", ".rb", ".pl", ".py", ".run", ".sh", ".pkg", ".dmg", ".app", ".pif", ".cpl", ".jse", ".ps1", ".cmd", ".bat", ".msi"}

# List of user agents to choose from
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/114.0.1823.51 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/114.0.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.196 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
]

URL_TIMESTAMPS = {}
save_paths = {}
failed_attempts = {}

def get_random_user_agent():
    """Selects a random user agent from the list."""
    return random.choice(USER_AGENTS)

# --- HASH FUNCTIONS ---

def get_full_sha256_hash(value: str) -> str:
    """Generates a full 64-character SHA256 hash."""
    return hashlib.sha256(value.encode()).hexdigest()

def get_truncated_sha256_hash(value: str, length: int = 15) -> str:
    """Generates a truncated SHA256 hash of a specified length."""
    return hashlib.sha256(value.encode()).hexdigest()[:length]

def get_fqdn_and_hash(url: str):
    """Extracts FQDN from a URL and returns its full hash."""
    fqdn = urlparse(url).netloc
    return fqdn, get_full_sha256_hash(fqdn)

def get_url_hash(url: str):
    """Generates a truncated hash for the full URL."""
    return get_truncated_sha256_hash(url, length=15)

def get_formatted_timestamp():
    """Returns a formatted timestamp string."""
    now = datetime.now()
    return f"{now.year}_{now.month:02d}_{now.day:02d}_{now.hour:02d}_{now.minute:02d}"

def get_filename_from_url(url, default_name):
    """
    Extracts a filename from a URL. If no clear filename, uses default_name.
    Ensures filename is safe for file systems.
    """
    path = urlparse(url).path
    filename = os.path.basename(path)
    if not filename or filename.endswith("/"):
        filename = default_name

    # Sanitize filename (remove/replace invalid characters)
    filename = re.sub(r'[\\/:*?"<>|]', '_', filename) # Replace forbidden chars with underscore
    filename = filename.strip() # Remove leading/trailing whitespace
    return filename

class WebsiteCrawler:
    """
    A class to crawl websites, capture screenshots, HTML, text, and download
    various associated files (JS, images, suspicious files).
    Manages a single Playwright browser instance for efficiency across multiple crawls.
    """
    def __init__(self, output_dir=OUTPUT_DIR, viewport=VIEWPORT, headless=HEADLESS,
                 timeout=TIMEOUT, download_timeout=DOWNLOAD_TIMEOUT,
                 max_js_files=MAX_JS_FILES, max_suspicious_files=MAX_SUSPICIOUS_FILES,
                 max_images_to_download=MAX_IMAGES_TO_DOWNLOAD):

        self.output_dir = output_dir
        self.viewport = viewport
        self.headless = headless
        self.timeout = timeout
        self.download_timeout = download_timeout
        self.max_js_files = max_js_files
        self.max_suspicious_files = max_suspicious_files
        self.max_images_to_download = max_images_to_download

        self.suspicious_extensions = SUSPICIOUS_EXTENSIONS # Use the global config

        self.browser = None  # Playwright browser instance
        self.context = None  # Playwright browser context
        self.playwright_instance = None # To store the playwright context manager

        self.session = None

    async def initialize(self):
        """Initializes the Playwright browser, context, and aiohttp session."""
        if self.browser is None:
            print("Initializing Playwright browser...")
            self.playwright_instance = await async_playwright().start()
            self.browser = await self.playwright_instance.chromium.launch(headless=self.headless)

            # --- MODIFIED: Use a random user agent here ---
            user_agent_to_use = get_random_user_agent()

            self.context = await self.browser.new_context(
                viewport=self.viewport,
                user_agent=user_agent_to_use
            )
            print("Playwright browser initialized.")

        if self.session is None:
            print("Initializing aiohttp client session...")
            self.session = aiohttp.ClientSession()
            print("aiohttp client session initialized.")

    async def close(self):
        """Closes the Playwright browser and aiohttp session."""
        if self.browser:
            print("Closing Playwright browser...")
            await self.browser.close()
            if self.playwright_instance:
                await self.playwright_instance.stop()
            self.browser = None
            self.context = None
            self.playwright_instance = None
            print("Playwright browser closed.")

        if self.session:
            print("Closing aiohttp client session...")
            await self.session.close()
            self.session = None
            print("aiohttp client session closed.")

    async def _download_file(self, url, save_path):
        """Internal helper to download a single file using the shared aiohttp session."""
        try:
            async with self.session.get(url, timeout=self.download_timeout) as resp:
                if resp.status == 200:
                    os.makedirs(os.path.dirname(save_path), exist_ok=True)
                    with open(save_path, "wb") as f:
                        f.write(await resp.read())
                else:
                    print(f"⚠️ Failed to download {url}: HTTP Status {resp.status}")
        except aiohttp.ClientError as e:
            print(f"❌ Client error downloading file {url}: {e}")
        except asyncio.TimeoutError:
            print(f"❌ Timeout downloading file {url}")
        except Exception as e:
            print(f"❌ General error downloading file {url}: {e}")

    async def crawl_url(self, url: str):
        """
        Crawls a single URL, collects data, and saves it to a structured directory.
        Captures all HTTP requests and responses as network_transactions.json.
        """
        fqdn, fqdn_hash = get_fqdn_and_hash(url)
        url_hash = get_url_hash(url)
        timestamp = get_formatted_timestamp()

        if url not in URL_TIMESTAMPS:
                URL_TIMESTAMPS[url] = {}

        URL_TIMESTAMPS[url] = timestamp

        save_path = os.path.join(self.output_dir, url, timestamp)
        os.makedirs(save_path, exist_ok=True)

        # Create sub-directories
        js_folder = os.path.join(save_path, "js_scripts")
        suspicious_folder = os.path.join(save_path, "suspicious_files")
        images_folder = os.path.join(save_path, "images")

        os.makedirs(js_folder, exist_ok=True)
        os.makedirs(suspicious_folder, exist_ok=True)
        os.makedirs(images_folder, exist_ok=True)

        if self.browser is None or self.context is None or self.session is None:
            print("Crawler not initialized. Calling initialize()...")
            await self.initialize()

        page = await self.context.new_page()
        logs = []
        network_transactions = [] # <<< NEW: List to store all network data

        page.on("console", lambda msg: logs.append(f"[{msg.type}] {msg.text}"))

        # --- NEW: Network Event Handlers to capture all traffic ---
        def handle_request(request):
            """Captures request details."""
            network_transactions.append({
                "type": "request",
                "url": request.url,
                "method": request.method,
                "resourceType": request.resource_type,
                "headers": request.headers,
                "timestamp": datetime.now().isoformat()
            })

        def handle_response(response):
            """Captures response details."""
            network_transactions.append({
                "type": "response",
                "url": response.url,
                "status": response.status,
                "statusText": response.status_text,
                "headers": response.headers,
                # --- FIX APPLIED HERE ---
                # Simplified to use the supported 'from_service_worker' property
                # and relying on Playwright's overall behavior for disk cache.
                "fromCache": response.from_service_worker, 
                # --- END FIX ---
                "requestUrl": response.request.url,
                "timestamp": datetime.now().isoformat()
            })

        page.on("request", handle_request)
        page.on("response", handle_response)
        # --- END NEW HANDLERS ---

        try:
            print(f" Navigating to: {url}")
            
            # Navigate to the URL
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout)
            if not response:
                print(f"⚠️ No primary response received for {url}.")
                return

            status_code = response.status
            is_non_200 = (status_code != 200)

            if is_non_200:
                if not failed_attempts[url]:
                    failed_attempts[url] = 1
                else:
                    failed_attempts[url] = failed_attempts[url] + 1

            # Wait for the main content to load fully
            await page.wait_for_selector("body", state="visible", timeout=10000)
            await asyncio.sleep(2) # Give a short delay for any final lazy-loaded resources

            # --- SAVE NETWORK TRANSACTIONS ---
            print(f" Saving {len(network_transactions)} network events.")
            with open(os.path.join(save_path, "network_transactions.json"), "w") as f:
                json.dump(network_transactions, f, indent=2)
            # --- END SAVE ---

            # --- Core Artifacts Capture ---
            print(" Capturing screenshot and source code.")
            await page.screenshot(path=os.path.join(save_path, "screenshot.png"), full_page=True)

            rendered_html = await page.content()
            with open(os.path.join(save_path, "rendered_html.html"), "w", encoding="utf-8") as f:
                f.write(rendered_html)

            text = await page.inner_text("body")
            with open(os.path.join(save_path, "text.txt"), "w", encoding="utf-8") as f:
                f.write(text)

            # --- Primary Response Details ---
            print(" Saving request/response metadata.")
            with open(os.path.join(save_path, "response_headers.json"), "w") as f:
                json.dump(response.headers, f, indent=2)
            with open(os.path.join(save_path, "request_headers.json"), "w") as f:
                json.dump(response.request.headers, f, indent=2)

            csp = response.headers.get("content-security-policy", "")
            with open(os.path.join(save_path, "csp_headers.txt"), "w", encoding="utf-8") as f:
                f.write(csp)

            cookies = await self.context.cookies()
            with open(os.path.join(save_path, "cookies.json"), "w") as f:
                json.dump(cookies, f, indent=2)

            with open(os.path.join(save_path, "console_logs.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(logs))

            # --- Link Extraction ---
            print(" Extracting links.")
            links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            internal = [l for l in links if urlparse(l).netloc == fqdn]
            external = [l for l in links if urlparse(l).netloc != fqdn]

            with open(os.path.join(save_path, "internal_links.txt"), "w") as f:
                f.write("\n".join(internal))
            with open(os.path.join(save_path, "external_links.txt"), "w") as f:
                f.write("\n".join(external))

            # --- Social Media Signals Extraction ---
            print(" Processing social media signals.")

            def filter_platform_links(domain: str) -> list[str]:
                return [l for l in links if domain in l.lower()]

            fb_links = filter_platform_links("facebook.com")
            tw_links = filter_platform_links("twitter.com") + filter_platform_links("x.com")
            ig_links = filter_platform_links("instagram.com")
            yt_links = filter_platform_links("youtube.com")
            li_links = filter_platform_links("linkedin.com")

            has_fb_photo = False
            try:
                og_image = await page.get_attribute('meta[property="og:image"]', "content", timeout=2000)
                has_fb_photo = og_image is not None and len(og_image) > 0
            except Exception:
                has_fb_photo = False

            has_fb_address = False
            try:
                og_street = await page.get_attribute('meta[property="og:street-address"]', "content", timeout=1000)
                has_fb_address = og_street is not None
            except Exception:
                has_fb_address = False

            social_signals = {
                # Boolean Flags (B)
                "facebook_profile_found": len(fb_links) > 0,
                "facebook_profile_mismatch": None,
                "has_facebook_profile_photo": has_fb_photo,
                "has_facebook_profile_address": has_fb_address,
                "twitter_profile_found": len(tw_links) > 0,
                "instagram_profile_found": len(ig_links) > 0,
                "youtube_profile_found": len(yt_links) > 0,
                "linkedin_profile_found": len(li_links) > 0,

                # Numeric Counts (N)
                "facebook_profile_age": None,       
                "facebook_profile_followers": None, 
                "facebook_profile_likes": None,
                "facebook_integration_links": len(fb_links),
                "twitter_integration_links": len(tw_links),
                "instagram_integration_links": len(ig_links),
                "youtube_integration_links": len(yt_links),
                "linkedin_integration_links": len(li_links),

                # Raw extracted URLs for audit/further lookup
                "extracted_urls": {
                    "facebook": fb_links,
                    "twitter": tw_links,
                    "instagram": ig_links,
                    "youtube": yt_links,
                    "linkedin": li_links
                }
            }

            with open(os.path.join(save_path, "social_signals.json"), "w", encoding="utf-8") as f:
                json.dump(social_signals, f, indent=2)
            

            # --- JS File Download ---
            print(" Downloading JS files.")
            script_urls = await page.eval_on_selector_all(
                "script[src]",
                "els => els.map(e => e.src).filter(src => src)"
            )
            script_urls = [url for url in script_urls if urlparse(url).netloc == fqdn]
            script_urls = script_urls[:self.max_js_files]

            for idx, js_url in enumerate(script_urls):
                filename = get_filename_from_url(js_url, f"script_{idx + 1}.js")
                save_js_path = os.path.join(js_folder, filename)
                await self._download_file(js_url, save_js_path)

            # --- Image Download ---
            print(" Downloading images.")
            image_urls = await page.eval_on_selector_all(
                "img[src]",
                    "els => els.map(e => e.src).filter(src => src)"
            )
            base_url_for_images = response.url
            absolute_image_urls = []
            for img_url in image_urls:
                absolute_img_url = urljoin(base_url_for_images, img_url)
                if urlparse(absolute_img_url).netloc == fqdn:
                    absolute_image_urls.append(absolute_img_url)
            
            images_to_download = absolute_image_urls[:self.max_images_to_download]
            
            base_output_dir = save_path
            
            for img_url in images_to_download:
                parsed_url = urlparse(img_url)
                rel_path = parsed_url.path.lstrip('/')
                if not rel_path:
                    continue
                save_img_path = os.path.join(base_output_dir, rel_path)
                os.makedirs(os.path.dirname(save_img_path), exist_ok=True)
                await self._download_file(img_url, save_img_path)

            # --- Suspicious File Check ---
            print(" Checking for suspicious files.")
            suspicious_urls = []
            for ext in self.suspicious_extensions:
                selector = f'[src$="{ext}" i], [href$="{ext}" i]'
                # Playwright's page.eval_on_selector_all can return None for elements, so filter
                found_urls = await page.eval_on_selector_all(selector, "els => els.map(e => e.src || e.href).filter(Boolean)")
                suspicious_urls.extend(found_urls)

            suspicious_urls = [url for url in suspicious_urls if urlparse(url).netloc == fqdn][:self.max_suspicious_files]

            for idx, sus_url in enumerate(suspicious_urls):
                filename = get_filename_from_url(sus_url, f"suspicious_{idx + 1}{os.path.splitext(sus_url)[1]}")
                save_sus_path = os.path.join(suspicious_folder, filename)
                await self._download_file(sus_url, save_sus_path)

            # --- Final Metadata ---
            metadata = {
                "original_url": url,
                "fqdn": fqdn,
                "fqdn_hash": fqdn_hash,
                "url_hash": url_hash,
                "timestamp": timestamp,
                "js_files_count": len(script_urls),
                "suspicious_files_count": len(suspicious_urls),
                "images_downloaded_count": len(images_to_download),
                "total_network_transactions": len(network_transactions),
                "social_facebook_links_count": len(fb_links),
                "social_twitter_links_count": len(tw_links),
                "social_instagram_links_count": len(ig_links),
                "social_youtube_links_count": len(yt_links),
                "social_linkedin_links_count": len(li_links)
            }
            with open(os.path.join(save_path, "metadata.txt"), "w", encoding="utf-8") as f:
                for k, v in metadata.items():
                    f.write(f"{k}: {v}\n")

            print(f" Successfully crawled: {url}")
            print(f" Data saved to: {save_path}")

            save_paths[url] = save_path

        except Exception as e:
            print(f" Error crawling {url}: {e}")

        finally:
            await page.close()

async def main(urls, concurrency=5):
    """
    Main function to orchestrate crawling of multiple URLs with concurrency.
    Manages a single WebsiteCrawler instance.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    crawler = WebsiteCrawler(output_dir=OUTPUT_DIR, headless=HEADLESS,
                             max_images_to_download=MAX_IMAGES_TO_DOWNLOAD)
    await crawler.initialize()
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_crawl(url):
        async with semaphore:
            await crawler.crawl_url(url)

    tasks = [sem_crawl(url) for url in urls]
    await asyncio.gather(*tasks)

    await crawler.close()
    print("\nAll crawling tasks completed and resources released.")

def formalize_domain(url):
    """
    Cleans up a URL to get the base domain name.
    """
    if not url.startswith('http'):
        url = 'https://' + url
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    if domain.startswith('www.'):
        domain = domain[4:]
        
    return domain

def get_tls_info(hostname, port=443):
    """
    Connects to a server to get detailed TLS and certificate information.
    Returns both the raw cert data and the processed features.
    """
    print(f"Getting tls data for {hostname} at {datetime.now().strftime("%H:%M:%S")}")
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((hostname, port)) as sock:
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # --- Original Certificate Query Result ---
                # This is the original data from getpeercert()
                original_cert_data = ssock.getpeercert()
                
                # --- Processed Features ---
                cert_der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                # TLS validation
                supports_tls_v3 = ssock.version() == 'TLSv1.3'
                
                # Public key length
                pub_key_length = cert.public_key().key_size
                
                # SANs and distinct E2LDS
                num_sans, distinct_e2lds_count = 0, 0
                try:
                    san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = san_ext.value.get_values_for_type(x509.DNSName)
                    num_sans = len(sans)
                    psl = PublicSuffixList()
                    e2lds = {psl.publicsuffix(san) for san in sans}
                    distinct_e2lds_count = len(e2lds)
                except x509.ExtensionNotFound:
                    pass

                # Certificate issuer checks
                issuer_org_name_list = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                issuer_org_name = issuer_org_name_list[0].value if issuer_org_name_list else ""
                
                # Original Feature: Checks against the list of known FREE CAs
                is_free_cert = any(ca in issuer_org_name for ca in FREE_CA_ISSUERS)

                # NEW Feature: Checks against the combined list of ALL common CAs
                is_common_ca = any(ca in issuer_org_name for ca in ALL_COMMON_CA_ISSUERS)

                # Validity period
                # Use timezone-aware datetime objects for correct calculation
                validity_period = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days

                # Certificate validation level
                validation_level = "N/A"
                try:
                    cp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
                    policy_oids = [p.policy_identifier.dotted_string for p in cp_ext.value]
                    if "2.23.140.1.2.1" in policy_oids:
                        validation_level = "Domain Validation (DV)"
                    elif "2.23.140.1.1" in policy_oids:
                        validation_level = "Extended Validation (EV)"
                    elif "2.23.140.1.2.2" in policy_oids:
                        validation_level = "Organization Validation (OV)"
                except x509.ExtensionNotFound:
                    pass

                processed_data = {
                    "TLS_enabled": True,
                    "Supports_TLSv3": supports_tls_v3,
                    "TLS_validation_OK": True,
                    "Leaf_cert_public_key_length": pub_key_length,
                    "number_of_SANs": num_sans,
                    "number_of_distinct_SAN_E2LDS": distinct_e2lds_count,
                    "Free_certificate_issuer": is_free_cert,        # Original Feature
                    "Common_CA_issuer": is_common_ca,              # NEW Feature (covers all common CAs)
                    "Leaf_cert_validity_period_days": validity_period,
                    "Leaf_cert_validation_level": validation_level,
                    "number_of_leaf_cert_extensions": len(cert.extensions),
                }

                return {
                    "certificate_query_result": original_cert_data,
                    "features": processed_data
                }

    except Exception as e:
        # Handle the case where the hostname is not found or connection fails
        return {
            "TLS_enabled": False,
            "error": str(e)
        }

def get_host_info(ip_address):
    """
    Retrieves host information (country, provider, ASN) for an IP address.
    Using a free IP lookup API for this.
    """
    try:
        access_token = '3685a4761020e4'
        handler = ipinfo.getHandler(access_token)
        details = handler.getDetails(ip_address)
        return {
            "country": details.country_name,
            "provider": details.org,
            "asn_name": details.asn['name'] if hasattr(details, 'asn') and 'name' in details.asn else "N/A"
        }
    except Exception as e:
        return {
            "country": "N/A",
            "provider": "N/A",
            "asn_name": "N/A",
            "error": str(e)
        }

def get_dns_info(domain):
    """
    Queries for multiple types of DNS records and extracts key features.
    """
    print(f"Getting dns data for {domain} at {datetime.now().strftime("%H:%M:%S")}")
    record_types = ['A', 'AAAA', 'CNAME', 'DNAME', 'NS', 'MX', 'RP', 'HINFO', 'TXT', 'SOA']
    all_records = {}
    features = {
        "Presence of MX record": False,
        "Presence of CNAME record": False,
        "Presence of DNAME record": False,
        "Presence of HINFO record": False,
        "Presence of AAAA record": False,
        "Presence of NS record": False,
        "Presence of RP record": False,
        "Presence of SOA record": False,
        "Presence of TXT record": False,
        "# of TXT records": 0,
        "# of domain verification records": 0,
        "Email spoof protection enabled": False,
        "# of A record IPs": 0,
        "# of AAAA record IPs": 0,
        "Server Host country": "N/A",
        "Server Host provider": "N/A",
        "Server Host ASN name": "N/A"
    }

    # Iterate through each record type and query
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = [rdata.to_text() for rdata in answers]
            all_records[rtype] = records
            
            # Update presence flags based on record type
            if rtype == 'MX':
                features["Presence of MX record"] = True
            elif rtype == 'CNAME':
                features["Presence of CNAME record"] = True
            elif rtype == 'DNAME':
                features["Presence of DNAME record"] = True
            elif rtype == 'HINFO':
                features["Presence of HINFO record"] = True
            elif rtype == 'AAAA':
                features["Presence of AAAA record"] = True
                features["# of AAAA record IPs"] = len(records)
            elif rtype == 'NS':
                features["Presence of NS record"] = True
            elif rtype == 'RP':
                features["Presence of RP record"] = True
            elif rtype == 'SOA':
                features["Presence of SOA record"] = True
            elif rtype == 'TXT':
                features["Presence of TXT record"] = True
                features["# of TXT records"] = len(records)
                
                # Check for email spoof protection and verification records
                for record in records:
                    if "v=spf1" in record or "DKIM" in record or "DMARC" in record:
                        features["Email spoof protection enabled"] = True
                    if "google-site-verification" in record or "adobe-sign-verification" in record:
                        features["# of domain verification records"] += 1
        
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
            all_records[rtype] = "No record found"
            
    # Get A record count and host info
    if 'A' in all_records and all_records['A'] != "No record found":
        features["# of A record IPs"] = len(all_records['A'])
        
        # Use the first A record to get host info
        first_ip = all_records['A'][0]
        host_info = get_host_info(first_ip)
        features["Server Host country"] = host_info["country"]
        features["Server Host provider"] = host_info["provider"]
        features["Server Host ASN name"] = host_info["asn_name"]

    return {
        "original_query_result": all_records,
        "features": features
    }

def get_rdap_info(domain, max_retries=4, base_delay=5):
    print(f"[+] Starting lookup for: {domain}")
    
    domain = domain.strip().lower()
    
    result_data = {
        "domain": domain,
        "rdap_json": None,
        "whois_raw": None,
        "whois_parsed": None,
        "errors": {}
    }
    
    for attempt in range(max_retries):
        # 1. RDAP lookup
        try:
            domain_name, tld = domain.rsplit(".", 1)
        
            rdap_response = whodap.lookup_domain(
                domain=domain_name,
                tld=tld
            )
        
            result_data["rdap_json"] = rdap_response.to_dict()

            return result_data
        
        except Exception as e:
            err_msg = str(e)
            # Check if error is due to Rate Limiting (429)
            if "429" in err_msg or "RATE_LIMIT" in err_msg or "Too many requests" in err_msg:
                # Exponential delay with randomized jitter: 5s, 10s, 20s (+ random 1-3s)
                sleep_time = (base_delay * (2 ** attempt)) + random.uniform(1, 3)
                print(f"[!] Rate limit hit for {domain} (Attempt {attempt + 1}/{max_retries}). Sleeping for {sleep_time:.1f}s...")
                time.sleep(sleep_time)
            else:
                # Non-rate-limit error (e.g. domain non-existent); don't retry endlessly
                result_data["errors"]["rdap"] = err_msg
                print(f"[-] RDAP error for {domain}: {e}")
                return result_data

    result_data["errors"]["rdap"] = "Failed after maximum rate-limit retries."
    return result_data

def parse_rdap_creation_date(rdap_dict: dict) -> datetime | None:
    """
    Parses the registration/creation date from standard RDAP event arrays.
    """
    if not rdap_dict or "events" not in rdap_dict:
        return None

    for event in rdap_dict.get("events", []):
        if event.get("eventAction") in ("registration", "reregistration"):
            date_str = event.get("eventDate")
            if date_str:
                return datetime.fromisoformat(date_str.replace("Z", "+00:00"))

@functools.lru_cache(maxsize=1)
def _get_tranco_map() -> dict:
    """
    Downloads and caches the Tranco Top 1M list in memory once across thread executions.
    Returns a dict mapping domain -> rank.
    """
    tranco_map = {}
    try:
        url = "https://tranco-list.eu/top-1m.csv.zip"
        req = urllib.request.urlopen(url, timeout=10)
        with zipfile.ZipFile(io.BytesIO(req.read())) as z:
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                for line in f:
                    rank_str, domain_b = line.decode('utf-8').strip().split(',')
                    tranco_map[domain_b.lower()] = int(rank_str)
    except Exception as e:
        print(f"[-] Tranco list download failed: {e}")
    return tranco_map

def analyze_domain_metrics(site: str) -> dict:
    """
    Synchronous analysis of domain characteristics, Tranco rankings, and RDAP telemetry.
    Designed for ThreadPoolExecutor execution.
    """
    # 1. URL Parsing
    parsed = urlparse(site if "://" in site else f"http://{site}")
    hostname = parsed.netloc.lower().split(":")[0] if parsed.netloc else parsed.path.lower().split(":")[0]

    parts = hostname.split(".")
    tld = f".{parts[-1]}" if len(parts) > 1 else ""
    registered_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

    # 2. Structural Domain Checks
    is_ecom_subdomain = hostname.endswith(ECOM_PLATFORMS) and hostname not in ECOM_PLATFORMS
    num_non_chars = len(re.findall(r"[^a-zA-Z0-9]", registered_domain))
    is_cheap_tld = tld in CHEAP_TLDS
    domain_length = len(registered_domain)

    # 3. Cached Tranco Lookup
    tranco_map = _get_tranco_map()
    rank = tranco_map.get(registered_domain)
    tranco_top_1m = rank is not None and rank <= 1_000_000
    tranco_top_100k = rank is not None and rank <= 100_000

    # 4. Synchronous Whodap RDAP Lookup
    domain_age_days = None
    try:
        domain_name, ld = registered_domain.rsplit(".", 1)
        # Using synchronous whodap lookup for standard threads
        rdap_response = whodap.lookup_domain(domain=domain_name, tld=ld)
        rdap_dict = rdap_response.to_dict() if hasattr(rdap_response, "to_dict") else rdap_response
        
        creation_date = parse_rdap_creation_date(rdap_dict)
        if creation_date:
            now = datetime.now(timezone.utc)
            domain_age_days = (now - creation_date).days
    except Exception as e:
        print(f"[-] RDAP calculation failed for {registered_domain}: {e}")

    return {
        "tranco_top_1m": tranco_top_1m,
        "tranco_top_100k": tranco_top_100k,
        "subdomain_of_ecommerce_platform": is_ecom_subdomain,
        "cheap_tld": is_cheap_tld,
        "num_non_characters": num_non_chars,
        "domain_length": domain_length,
        "telemetry_domain_age_days": domain_age_days,
        "telemetry_domain_minimum_rank": rank,
        "telemetry_domain_maximum_rank": rank,
        "telemetry_domain_avg_daily_visits": None
    }

def get_metadata_from_scrapper (file_path):
    metadata_dict = {}
    full_path = os.path.abspath(os.path.normpath(file_path))
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    key, value = line.split(":", 1)
                    metadata_dict[key.strip()] = value.strip()
        return metadata_dict
    except FileNotFoundError:
        print(f"❌ Metadata file not found at: {full_path}")
        return {}

def flatten_dict(d, prefix=''):
    """
    Recursively flattens a nested dictionary and prefixes keys.
    Example: {'a': {'b': 1}} -> {'a_b': 1}
    """
    items = []
    for k, v in d.items():
        new_key = f"{prefix}_{k}" if prefix else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key).items())
        else:
            if isinstance(v, (list, tuple)):
                v = "|".join(map(str, v))
            elif isinstance(v, datetime):
                v = v.isoformat()
            items.append((new_key, v))
    return dict(items)

def extract_urls(csv_file_path):
    urls = []
    with open(csv_file_path, mode="r", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue

            cell = row[0].strip()

            # Checking for these keys. Other keys can be added if needed
            if cell and not cell.lower() in ("url", "urls", "site", "domain"):
                urls.append(cell)
    return urls

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process URLs from a CSV file.")
    parser.add_argument("csv_path", nargs="?", default=None, help="Path to the input CSV file containing URLs")
    args = parser.parse_args()
    
    while 1 == 1:
        if args.csv_path and os.path.exists(args.csv_path):
                URLS_TO_TEST = extract_urls(args.csv_path)
        else:
            if args.csv_path:
                print(
                    f"Warning: File '{args.csv_path}' not found. Using default URL list."
                )
            URLS_TO_TEST = ["https://example.com/"]
        
        if not URLS_TO_TEST:
            print("No URLs found to process.")
            exit()

        max_urls_for_parallel_process = 5

        asyncio.run(main(URLS_TO_TEST, concurrency=max_urls_for_parallel_process))

        for url in URLS_TO_TEST:
            site = formalize_domain(url)
            #fqdn, fqdn_hash = get_fqdn_and_hash(site)
            #url_hash = get_url_hash(site)
            if not save_paths.get(url) or not os.path.exists(os.path.join(save_paths.get(url), "metadata.txt")):
                print(f"⚠️ Skipping metrics for {url}: Crawl path or metadata.txt not found.")
                continue
            metadata_path = save_paths.get(url) + "/metadata.txt"

            with ThreadPoolExecutor() as executor:
                A1 = executor.submit(get_tls_info, site)
                A2 = executor.submit(get_dns_info, site)
                A3 = executor.submit(get_rdap_info, site)
                A4 = executor.submit(analyze_domain_metrics, site)
                A5 = executor.submit(get_metadata_from_scrapper, metadata_path)

                cert_info = A1.result()
                dns_info = A2.result()
                rdap_info = A3.result()
                domain_metrics = A4.result()
                metadata = A5.result()

            total_data = {"search_url": url}

            total_data.update(flatten_dict(cert_info or {}, "tls"))
            total_data.update(flatten_dict(dns_info or {}, "dns"))
            total_data.update(flatten_dict(rdap_info or {}, "whois"))
            total_data.update(flatten_dict(domain_metrics or {}, "domain_metrics"))
            total_data.update(flatten_dict(metadata or {}, "metadata"))

            if total_data:
                all_keys = set()
                
                all_keys.update(total_data.keys())

                with open(f"{save_paths[url]}/results.csv", "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(f, fieldnames=sorted(list(all_keys)))
                        writer.writeheader()
                        writer.writerow(total_data)

                print(f"Results saved to {save_paths[url]}/results.csv")

            if failed_attempts.get(url)== 3:
                URLS_TO_TEST.remove(url)

            sleep(3)

        print("finished daily scrape")
        sleep(86400)
