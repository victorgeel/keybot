#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# FILE: test_and_upload.py
# Description: Fetches and processes mixed Hysteria/Hysteria2 subscription links (plain & base64),
#              saves them to separate files.
# Version: 3.7 (Handles mixed plain and base64 encoded links)

import requests
import os
import re
import sys
import base64
from urllib.parse import urlparse

# --- Configuration ---
print("--- Script Configuration ---")
SOURCE_URLS = [
    "https://hysteria2.github.io/uploads/2025/04/0-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/1-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/2-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/3-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/4-20250425.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/hysteria",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/hysteriabase64"
]
print(f"Loaded {len(SOURCE_URLS)} URLs.")

OUTPUT_DIR = "subscription"
HYSTERIA_OUTPUT_FILENAME = "hysteria.txt"
HYSTERIA2_OUTPUT_FILENAME = "hysteria2.txt"
HYSTERIA_OUTPUT_PATH = os.path.join(OUTPUT_DIR, HYSTERIA_OUTPUT_FILENAME)
HYSTERIA2_OUTPUT_PATH = os.path.join(OUTPUT_DIR, HYSTERIA2_OUTPUT_FILENAME)
print(f"Hysteria output file path: {HYSTERIA_OUTPUT_PATH}")
print(f"Hysteria2 output file path: {HYSTERIA2_OUTPUT_PATH}")

REQUEST_TIMEOUT = 25
print(f"Subscription fetch timeout: {REQUEST_TIMEOUT}s")

REQUEST_HEADERS = {
    'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 KeyTester/3.7'
}
print(f"Subscription Fetch Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

def find_hysteria_links(text):
    """Finds Hysteria links in a given text."""
    return re.findall(r"hysteria:\/\/[\w\d\.:\/?=&%#]+", text)

def find_hysteria2_links(text):
    """Finds Hysteria2 links in a given text."""
    return re.findall(r"hy2:\/\/[\w\d\.\-@:\/?=&%#]+", text)

def decode_base64_text(encoded_text):
    """Tries to decode a base64 encoded text."""
    try:
        padding = '=' * (-len(encoded_text) % 4)
        return base64.b64decode(encoded_text + padding).decode('utf-8', errors='ignore')
    except Exception:
        return None

def main():
    """Main function."""
    script_start_time = time.time()
    print(f"\n=== Starting Mixed-Format Hysteria/Hysteria2 Link Fetcher (v3.7) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

    # Step 1: Output Dir
    print(f"\n--- Step 1: Output Dir ({OUTPUT_DIR}) ---")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"Output dir ok.")
    except OSError as e:
        print(f"FATAL: Cannot create dir {OUTPUT_DIR}: {e}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Fetch and Process URLs
    print("\n--- Step 2: Fetching and Processing URLs ---")
    hysteria_links = set()
    hysteria2_links = set()
    fetch_errors = 0
    total_lines_fetched = 0

    for index, url in enumerate(SOURCE_URLS):
        print(f"\nFetching {index+1}/{len(SOURCE_URLS)}: {url[:100]}...")
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
            response.raise_for_status()
            raw_data = response.content.decode('utf-8', errors='ignore')
            lines = raw_data.splitlines()

            for line in lines:
                line = line.strip()

                # Check for plain text links
                hysteria_links.update(find_hysteria_links(line))
                hysteria2_links.update(find_hysteria2_links(line))

                # Try to decode as base64
                decoded_text = decode_base64_text(line)
                if decoded_text:
                    hysteria_links.update(find_hysteria_links(decoded_text))
                    hysteria2_links.update(find_hysteria2_links(decoded_text))

            fetched_count = len(hysteria_links) + len(hysteria2_links) - total_lines_fetched
            total_lines_fetched = len(hysteria_links) + len(hysteria2_links)
            print(f" -> Fetched and processed {fetched_count} new links from this source.")

        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout {url[:100]}", file=sys.stderr)
            fetch_errors += 1
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Fetching {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
        except Exception as e:
            print(f"ERROR: Processing {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
            import traceback
            traceback.print_exc()

    print(f"\nFetch done. Processed links: {total_lines_fetched}. Errors: {fetch_errors}.")
    print(f"Found {len(hysteria_links)} hysteria links.")
    print(f"Found {len(hysteria2_links)} hysteria2 links.")

    # Step 3: Write Results to Files
    print("\n--- Step 3: Writing Results to Files ---")

    # Write Hysteria Links
    try:
        with open(HYSTERIA_OUTPUT_PATH, 'w', encoding='utf-8', newline='\n') as f:
            for link in sorted(list(hysteria_links)):
                f.write(link + '\n')
        print(f"Wrote {len(hysteria_links)} hysteria links to: {HYSTERIA_OUTPUT_PATH}")
        print(f"Abs path: {os.path.abspath(HYSTERIA_OUTPUT_PATH)}")
    except IOError as e_w:
        print(f"ERROR writing file {HYSTERIA_OUTPUT_PATH}: {e_w}", file=sys.stderr)
        sys.exit(1)

    # Write Hysteria2 Links
    try:
        with open(HYSTERIA2_OUTPUT_PATH, 'w', encoding='utf-8', newline='\n') as f:
            for link in sorted(list(hysteria2_links)):
                f.write(link + '\n')
        print(f"Wrote {len(hysteria2_links)} hysteria2 links to: {HYSTERIA2_OUTPUT_PATH}")
        print(f"Abs path: {os.path.abspath(HYSTERIA2_OUTPUT_PATH)}")
    except IOError as e_w:
        print(f"ERROR writing file {HYSTERIA2_OUTPUT_PATH}: {e_w}", file=sys.stderr)
