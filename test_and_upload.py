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
import time  # <--- ဒီလိုင်းကို ထည့်သွင်းလိုက်ပါ

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
        # Add padding if necessary
        padding = '=' * (-len(encoded_text) % 4)
        # Decode Base64 and then decode UTF-8, ignoring errors
        return base64.b64decode(encoded_text + padding).decode('utf-8', errors='ignore')
    except Exception:
        # Return None if any error occurs during decoding
        return None

def main():
    """Main function."""
    script_start_time = time.time() # Now 'time' is defined
    print(f"\n=== Starting Mixed-Format Hysteria/Hysteria2 Link Fetcher (v3.7) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===") # Now 'time' is defined

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
    initial_hysteria_count = 0 # Track initial count before loop
    initial_hysteria2_count = 0 # Track initial count before loop

    # Optional: Load existing links to compare later (if needed for debugging)
    # try:
    #     with open(HYSTERIA_OUTPUT_PATH, 'r', encoding='utf-8') as f:
    #         initial_hysteria_count = len(set(line.strip() for line in f))
    # except FileNotFoundError:
    #     pass
    # try:
    #     with open(HYSTERIA2_OUTPUT_PATH, 'r', encoding='utf-8') as f:
    #         initial_hysteria2_count = len(set(line.strip() for line in f))
    # except FileNotFoundError:
    #     pass

    for index, url in enumerate(SOURCE_URLS):
        print(f"\nFetching {index+1}/{len(SOURCE_URLS)}: {url[:100]}...")
        current_hysteria_before = len(hysteria_links)
        current_hysteria2_before = len(hysteria2_links)
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
            response.raise_for_status() # Check for HTTP errors (4xx or 5xx)
            raw_data = response.content # Get raw bytes first
            
            # Try decoding as UTF-8, fall back to latin-1 if errors occur
            try:
                content = raw_data.decode('utf-8')
            except UnicodeDecodeError:
                print(f"Warning: UTF-8 decoding failed for {url[:100]}, trying latin-1.")
                content = raw_data.decode('latin-1', errors='ignore')

            lines = content.splitlines()
            processed_lines_from_source = 0

            for line in lines:
                line = line.strip()
                if not line: # Skip empty lines
                    continue

                # Check for plain text links
                found_hy1 = find_hysteria_links(line)
                found_hy2 = find_hysteria2_links(line)
                hysteria_links.update(found_hy1)
                hysteria2_links.update(found_hy2)
                if found_hy1 or found_hy2:
                    processed_lines_from_source += 1


                # Try to decode as base64 only if it looks like base64
                # (basic check: length > 10, no spaces, mostly alphanumeric + '+/=')
                # This avoids trying to decode every single line unnecessarily.
                if len(line) > 10 and ' ' not in line and re.match(r'^[A-Za-z0-9+/=]+$', line):
                    decoded_text = decode_base64_text(line)
                    if decoded_text:
                        # Check for links within the decoded text
                        found_decoded_hy1 = find_hysteria_links(decoded_text)
                        found_decoded_hy2 = find_hysteria2_links(decoded_text)
                        hysteria_links.update(found_decoded_hy1)
                        hysteria2_links.update(found_decoded_hy2)
                        if found_decoded_hy1 or found_decoded_hy2:
                             processed_lines_from_source +=1 # Count if links found after decoding

            new_hy1_count = len(hysteria_links) - current_hysteria_before
            new_hy2_count = len(hysteria2_links) - current_hysteria2_before
            print(f" -> Processed lines/decoded blocks: {processed_lines_from_source}. Found {new_hy1_count} new unique hysteria links, {new_hy2_count} new unique hysteria2 links.")

        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout fetching {url[:100]}", file=sys.stderr)
            fetch_errors += 1
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Fetching {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
        except Exception as e:
            print(f"ERROR: Processing data from {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
            import traceback
            traceback.print_exc(file=sys.stderr) # Print full traceback for debugging

    total_hysteria = len(hysteria_links)
    total_hysteria2 = len(hysteria2_links)
    print(f"\nFetch done. Total unique links found: Hysteria={total_hysteria}, Hysteria2={total_hysteria2}. Fetch Errors: {fetch_errors}.")

    # Step 3: Write Results to Files
    print("\n--- Step 3: Writing Results to Files ---")

    # Write Hysteria Links
    try:
        # Write only if there are links to write
        if hysteria_links:
             # Using 'w' ensures the file is overwritten each time
            with open(HYSTERIA_OUTPUT_PATH, 'w', encoding='utf-8', newline='\n') as f:
                # Sort the links before writing for consistency
                for link in sorted(list(hysteria_links)):
                    f.write(link + '\n')
            print(f"Wrote {total_hysteria} unique hysteria links to: {HYSTERIA_OUTPUT_PATH}")
            print(f"Absolute path: {os.path.abspath(HYSTERIA_OUTPUT_PATH)}")
        else:
             print(f"No hysteria links found to write to {HYSTERIA_OUTPUT_PATH}.")
             # Optional: Create an empty file if none found, or delete existing one
             # open(HYSTERIA_OUTPUT_PATH, 'w').close() # Create empty file
             # if os.path.exists(HYSTERIA_OUTPUT_PATH): os.remove(HYSTERIA_OUTPUT_PATH) # Remove if exists

    except IOError as e_w:
        print(f"ERROR writing file {HYSTERIA_OUTPUT_PATH}: {e_w}", file=sys.stderr)
        # Don't exit immediately, try writing the other file too

    # Write Hysteria2 Links
    try:
         # Write only if there are links to write
        if hysteria2_links:
             # Using 'w' ensures the file is overwritten each time
            with open(HYSTERIA2_OUTPUT_PATH, 'w', encoding='utf-8', newline='\n') as f:
                 # Sort the links before writing for consistency
                for link in sorted(list(hysteria2_links)):
                    f.write(link + '\n')
            print(f"Wrote {total_hysteria2} unique hysteria2 links to: {HYSTERIA2_OUTPUT_PATH}")
            print(f"Absolute path: {os.path.abspath(HYSTERIA2_OUTPUT_PATH)}")
        else:
            print(f"No hysteria2 links found to write to {HYSTERIA2_OUTPUT_PATH}.")
            # Optional: Create empty file or remove existing
            # open(HYSTERIA2_OUTPUT_PATH, 'w').close()
            # if os.path.exists(HYSTERIA2_OUTPUT_PATH): os.remove(HYSTERIA2_OUTPUT_PATH)

    except IOError as e_w:
        print(f"ERROR writing file {HYSTERIA2_OUTPUT_PATH}: {e_w}", file=sys.stderr)
        # Consider exiting if writing fails, as the main purpose is compromised
        # sys.exit(1) # Uncomment if writing failure should stop the script

    script_end_time = time.time()
    print(f"\n=== Script finished at {time.strftime('%Y-%m-%d %H:%M:%S %Z')}. Total execution time: {script_end_time - script_start_time:.2f} seconds ===")

# Make sure the script calls the main function when executed
if __name__ == "__main__":
    main()
