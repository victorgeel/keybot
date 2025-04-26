#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# FILE: test_and_upload.py
# Description: Fetches and processes Hysteria/Hysteria2 subscription links,
#              saves them to separate files.
# Version: 3.2 (Removed xray test, split output files)

import requests
import os
import base64
import re
import sys
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
    'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 KeyTester/3.2'
}
print(f"Subscription Fetch Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

def decode_base64_url(encoded_url):
    """Decodes a base64 encoded URL."""
    try:
        padding = '=' * (-len(encoded_url) % 4)
        decoded_bytes = base64.urlsafe_b64decode(encoded_url + padding)
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error decoding base64 URL: {e}", file=sys.stderr)
        return None

def main():
    """Main function."""
    script_start_time = time.time()
    print(f"\n=== Starting Hysteria/Hysteria2 Link Fetcher (v3.2) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

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
            raw_data = None
            try:
                raw_data = response.content.decode('utf-8')
                print(f"  Decoded UTF-8.")
            except UnicodeDecodeError:
                try:
                    encoding = response.encoding if response.encoding else response.apparent_encoding
                    encoding = encoding if encoding else 'iso-8859-1'
                    raw_data = response.content.decode(encoding, errors='replace')
                    print(f"  Decoded {encoding}.")
                except Exception as decode_err:
                    raw_data = response.content.decode('iso-8859-1', errors='replace')
                    print(f"  ERROR: Decode failed: {decode_err}.", file=sys.stderr)
                    fetch_errors += 1

            lines = raw_data.splitlines()
            count_for_source = 0
            for line in lines:
                line = line.strip()
                if line:
                    if line.startswith("hysteria://"):
                        hysteria_links.add(line)
                        count_for_source += 1
                    elif line.startswith("hy2://"):
                        hysteria2_links.add(line)
                        count_for_source += 1
                    elif base64.b64encode(base64.b64decode(line)).decode('utf-8') == line:
                        decoded_url = base64.b64decode(line).decode('utf-8', errors='ignore').strip()
                        if decoded_url.startswith("hysteria://"):
                            hysteria_links.add(decoded_url)
                            count_for_source += 1
                        elif decoded_url.startswith("hy2://"):
                            hysteria2_links.add(decoded_url)
                            count_for_source += 1
                    elif base64.urlsafe_b64encode(base64.urlsafe_b64decode(line + '=' * (-len(line) % 4))).decode('utf-8').rstrip('=') == line:
                        decoded_url = decode_base64_url(line)
                        if decoded_url:
                            if decoded_url.startswith("hysteria://"):
                                hysteria_links.add(decoded_url)
                                count_for_source += 1
                            elif decoded_url.startswith("hy2://"):
                                hysteria2_links.add(decoded_url)
                                count_for_source += 1
            total_lines_fetched += count_for_source
            print(f" -> Fetched and processed {count_for_source} lines from this source.")

        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout {url[:100]}", file=sys.stderr)
            fetch_errors += 1
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Fetching {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
        except Exception as e:
            print(f"ERROR: Processing {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
            traceback.print_exc(file=sys.stderr)

    print(f"\nFetch done. Processed lines: {total_lines_fetched}. Errors: {fetch_errors}.")
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
        sys.exit(1)

    # Step 4: Final Summary
    print("\n--- Script Summary ---")
    script_end_time = time.time()
    total_time = script_end_time - script_start_time
    print(f"Hysteria Links Collected: {len(hysteria_links)}")
    print(f"Hysteria2 Links Collected: {len(hysteria2_links)}")
    print(f"Finished in {total_time:.2f} seconds.")
    print("======================================================")

# --- Entry Point ---
if __name__ == "__main__":
    import time
    import traceback
    main()
