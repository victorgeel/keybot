#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# FILE: test_and_upload_final.py
# Description: Fetches and processes mixed Hysteria/Hysteria2 subscription links.
#              Handles plain text, line-by-line Base64, and fully Base64 encoded sources.
# Version: 4.0 (Combined plain, line-based, and full Base64 handling)

import requests
import os
import re
import sys
import base64
import time # <-- အချိန် function များအတွက် ထည့်သွင်းထားသည်

# --- Configuration ---
print("--- Script Configuration ---")
# (သင့်ရဲ့ URL list အမှန်ကို ဒီနေရာမှာ ထည့်ပါ)
SOURCE_URLS = [
    "https://hysteria2.github.io/uploads/2025/04/0-20250425.txt",
    "https://sub.nothing1.workers.dev/",
    "https://hysteria2.github.io/uploads/2025/04/1-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/2-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/3-20250425.txt",
    "https://hysteria2.github.io/uploads/2025/04/4-20250425.txt",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/channels/protocols/hysteria",
    "https://raw.githubusercontent.com/soroushmirzaei/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/hysteriabase64" # <-- Example of a potentially fully Base64 source
]
print(f"Loaded {len(SOURCE_URLS)} URLs.")

OUTPUT_DIR = "subscription"
HYSTERIA_OUTPUT_FILENAME = "hysteria.txt"
HYSTERIA2_OUTPUT_FILENAME = "hysteria2.txt"
HYSTERIA_OUTPUT_PATH = os.path.join(OUTPUT_DIR, HYSTERIA_OUTPUT_FILENAME)
HYSTERIA2_OUTPUT_PATH = os.path.join(OUTPUT_DIR, HYSTERIA2_OUTPUT_FILENAME)
print(f"Hysteria output file path: {HYSTERIA_OUTPUT_PATH}")
print(f"Hysteria2 output file path: {HYSTERIA2_OUTPUT_PATH}")

REQUEST_TIMEOUT = 25 # စက္ကန့်
print(f"Subscription fetch timeout: {REQUEST_TIMEOUT}s")

REQUEST_HEADERS = {
    'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 KeyTester/4.0' # Version updated
}
print(f"Subscription Fetch Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

# --- Helper Functions ---

def find_hysteria_links(text):
    """Finds Hysteria v1 links (hysteria://...) in a given text."""
    # This regex finds hysteria:// followed by allowed characters for the link body.
    return re.findall(r"hysteria:\/\/[\w\d\.:\/?=&%#\-]+", text) # Added hyphen to character set just in case

def find_hysteria2_links(text):
    """Finds Hysteria v2 links (hy2://...) in a given text."""
    # This regex finds hy2:// followed by allowed characters including '-', '@', etc.
    return re.findall(r"hy2:\/\/[\w\d\.\-@:\/?=&%#]+", text)

def decode_base64_text(encoded_text):
    """
    Tries to decode a single string assumed to be Base64 encoded.
    Handles potential padding errors. Returns decoded string or None on failure.
    """
    try:
        # Calculate required padding
        padding = '=' * (-len(encoded_text) % 4)
        # Decode Base64 (assuming input is string, encode to bytes first if needed, but usually it's already bytes from split)
        if isinstance(encoded_text, str):
            encoded_text_bytes = encoded_text.encode('utf-8') # Encode to bytes for b64decode
        else:
            encoded_text_bytes = encoded_text # Assume it's already bytes

        decoded_bytes = base64.b64decode(encoded_text_bytes + padding.encode('utf-8'))
        # Decode the result back to a UTF-8 string, ignoring errors
        return decoded_bytes.decode('utf-8', errors='ignore')
    except (base64.binascii.Error, ValueError, UnicodeDecodeError):
        # Return None if any error occurs during decoding
        return None

# --- Main Execution Logic ---

def main():
    """Main function to fetch, process, and save links."""
    script_start_time = time.time()
    print(f"\n=== Starting Hysteria/Hysteria2 Link Fetcher (v4.0) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

    # Step 1: Ensure Output Directory Exists
    print(f"\n--- Step 1: Ensuring Output Directory ({OUTPUT_DIR}) ---")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"Output directory '{OUTPUT_DIR}' is ready.")
    except OSError as e:
        print(f"FATAL: Cannot create directory {OUTPUT_DIR}: {e}", file=sys.stderr)
        sys.exit(1) # Exit if cannot create output directory

    # Step 2: Fetch and Process URLs
    print("\n--- Step 2: Fetching and Processing URLs ---")
    hysteria_links = set() # Use a set to store unique links
    hysteria2_links = set() # Use a set for unique Hysteria 2 links
    fetch_errors = 0 # Counter for URLs that failed to fetch/process

    for index, url in enumerate(SOURCE_URLS):
        print(f"\n[{index+1}/{len(SOURCE_URLS)}] Fetching: {url[:100]}...") # Show progress
        try:
            # Fetch the raw content (bytes)
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
            response.raise_for_status() # Check for HTTP errors like 404, 500
            raw_data = response.content # Get content as raw bytes

            processed_content = None # Will hold the string content after decoding
            is_fully_base64 = False # Flag to indicate if the whole source was Base64

            # --- Attempt 1: Decode the ENTIRE response as Base64 (V2Ray style) ---
            try:
                padding = b'=' * (-len(raw_data) % 4) # Padding for Base64
                decoded_as_whole = base64.b64decode(raw_data + padding)
                # Try decoding the result as UTF-8 text
                processed_content = decoded_as_whole.decode('utf-8')
                print(f"   -> Source decoded successfully as full Base64 content.")
                is_fully_base64 = True
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                # --- Attempt 2: If full Base64 fails, treat as plain text (UTF-8 or Latin-1) ---
                print(f"   -> Source is not full Base64. Treating as plain/mixed text.")
                try:
                    processed_content = raw_data.decode('utf-8')
                except UnicodeDecodeError:
                    # Fallback to latin-1 if UTF-8 fails
                    print(f"     Warning: UTF-8 decoding failed, trying latin-1 for {url[:100]}.")
                    processed_content = raw_data.decode('latin-1', errors='ignore') # Ignore errors on fallback

            # Check if content processing failed entirely
            if processed_content is None:
                 print(f"   ERROR: Could not decode content from {url[:100]} using any method.")
                 fetch_errors += 1
                 continue # Skip to the next URL if content is unusable

            # --- Process the lines from the (decoded) content ---
            lines = processed_content.splitlines()
            print(f"   -> Processing {len(lines)} lines from source.")
            current_hysteria_before = len(hysteria_links) # Count before adding from this source
            current_hysteria2_before = len(hysteria2_links)

            for line in lines:
                line = line.strip() # Remove leading/trailing whitespace
                if not line:
                    continue # Skip empty lines

                # A. Find plain links directly in the line (works for both full B64 decoded content and plain text)
                hysteria_links.update(find_hysteria_links(line))
                hysteria2_links.update(find_hysteria2_links(line))

                # B. If the source was NOT fully Base64, TRY decoding this specific line as Base64
                if not is_fully_base64:
                     # Basic check to see if line might be Base64 (avoids unnecessary attempts)
                     if len(line) > 10 and ' ' not in line and re.match(r'^[A-Za-z0-9+/=]+$', line):
                        decoded_line_text = decode_base64_text(line) # Use our helper function
                        if decoded_line_text:
                            # Find links within the text decoded from this single line
                            # print(f"      Decoded line: {decoded_line_text[:60]}...") # Uncomment for debugging
                            hysteria_links.update(find_hysteria_links(decoded_line_text))
                            hysteria2_links.update(find_hysteria2_links(decoded_line_text))

            # Report links found from this specific source
            new_hy1 = len(hysteria_links) - current_hysteria_before
            new_hy2 = len(hysteria2_links) - current_hysteria2_before
            if new_hy1 > 0 or new_hy2 > 0:
                print(f"   -> Found {new_hy1} new unique hysteria, {new_hy2} new unique hysteria2 links from this source.")
            else:
                print(f"   -> No new unique links found in this source.")

        # --- Handle Exceptions during Fetching/Processing for this URL ---
        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout occurred while fetching {url[:100]}", file=sys.stderr)
            fetch_errors += 1
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Network/HTTP error fetching {url[:100]}: {e}", file=sys.stderr)
            fetch_errors += 1
        except Exception as e:
            # Catch any other unexpected errors during processing
            print(f"ERROR: Unexpected error processing data from {url[:100]}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr) # Print full traceback for debugging
            fetch_errors += 1

    # --- Step 3: Summarize and Write Results to Files ---
    print("\n--- Step 3: Writing Results ---")
    total_hysteria = len(hysteria_links)
    total_hysteria2 = len(hysteria2_links)
    print(f"Fetch process completed.")
    print(f"Total unique Hysteria links found: {total_hysteria}")
    print(f"Total unique Hysteria2 links found: {total_hysteria2}")
    if fetch_errors > 0:
        print(f"WARNING: Encountered errors with {fetch_errors} URLs.")

    # Write Hysteria Links
    try:
        if hysteria_links:
            # Convert set to list, sort it for consistent order, then write
            sorted_hysteria = sorted(list(hysteria_links))
            with open(HYSTERIA_OUTPUT_PATH, 'w', encoding='utf-8', newline='\n') as f:
                for link in sorted_hysteria:
                    f.write(link + '\n')
            print(f"Successfully wrote {total_hysteria} unique hysteria links to: {HYSTERIA_OUTPUT_PATH}")
            # print(f"Absolute path: {os.path.abspath(HYSTERIA_OUTPUT_PATH)}") # Uncomment if needed
        else:
             print(f"No hysteria links found to write to {HYSTERIA_OUTPUT_PATH}.")
             # Optional: Create empty file if needed, or remove existing one
             # open(HYSTERIA_OUTPUT_PATH, 'w').close() # Create empty file

    except IOError as e_w:
        print(f"ERROR writing file {HYSTERIA_OUTPUT_PATH}: {e_w}", file=sys.stderr)
        # Consider exiting if writing fails critically
        # sys.exit(1)

    # Write Hysteria2 Links
    try:
        if hysteria2_links:
            # Convert set to list, sort it, then write
            sorted_hysteria2 = sorted(list(hysteria2_links))
            with open(HYSTERIA2_OUTPUT_PATH, 'w', encoding='utf-8', newline='\n') as f:
                for link in sorted_hysteria2:
                    f.write(link + '\n')
            print(f"Successfully wrote {total_hysteria2} unique hysteria2 links to: {HYSTERIA2_OUTPUT_PATH}")
            # print(f"Absolute path: {os.path.abspath(HYSTERIA2_OUTPUT_PATH)}") # Uncomment if needed
        else:
            print(f"No hysteria2 links found to write to {HYSTERIA2_OUTPUT_PATH}.")
            # Optional: Create empty file or remove existing
            # open(HYSTERIA2_OUTPUT_PATH, 'w').close()

    except IOError as e_w:
        print(f"ERROR writing file {HYSTERIA2_OUTPUT_PATH}: {e_w}", file=sys.stderr)
        # sys.exit(1) # Optional exit on critical write failure

    # --- Final Summary ---
    script_end_time = time.time()
    print(f"\n=== Script finished at {time.strftime('%Y-%m-%d %H:%M:%S %Z')}. ===")
    print(f"Total execution time: {script_end_time - script_start_time:.2f} seconds.")

# --- Script Entry Point ---
if __name__ == "__main__":
    # This ensures the main function runs only when the script is executed directly
    main()
