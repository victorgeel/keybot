import requests
import subprocess
import os
import time
import random
import base64

# --- Configuration ---
OUTPUT_FILE = "working_keys.txt"
XRAY_PATH = "./xray"
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 20

def download_and_extract_xray():
    # ... (အရင် script မှ download_and_extract_xray function ကို ဒီအတိုင်း ထားပါ) ...
    print("Xray download and extraction complete.")
    return True

def generate_config(key_url):
    # ... (အရင် script မှ generate_config function ကို ဒီအတိုင်း ထားပါ) ...
    return None

def test_v2ray_key(key_url):
    # ... (အရင် script မှ test_v2ray_key function ကို DEBUG log အပြည့်အစုံနဲ့ ဒီအတိုင်း ထားပါ) ...
    return key_url, False

def main():
    start_time = time.time(); print("Starting V2Ray Key Testing Script...")
    if not download_and_extract_xray(): print("FATAL: Failed to get/verify Xray binary. Aborting."); return
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK): print(f"FATAL: Xray executable not found or not executable at {XRAY_PATH}. Aborting."); return
    print(f"Using Xray executable at: {os.path.abspath(XRAY_PATH)}")

    source_urls_secret = os.environ.get("SOURCE_URLS_SECRET")
    if not source_urls_secret:
        print("ERROR: SOURCE_URLS_SECRET environment variable not found.")
        return

    SOURCE_URLS = source_urls_secret.strip().split('\n')
    print(f"\n--- Fetching Keys from {len(SOURCE_URLS)} URLs ---")

    all_keys_to_test = []
    for url in SOURCE_URLS:
        url = url.strip()
        if not url:
            continue
        try:
            print(f"Fetching keys from {url}...")
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0 V2RayKeyTester/1.0'})
            response.raise_for_status()
            raw_data = response.content.decode(response.encoding or 'utf-8', errors='replace')
            processed_data = raw_data

            # Base64 detection and decoding (simplified for all URLs)
            if "base64" in url.lower() or "b64" in url.lower():
                try:
                    decoded_bytes = base64.b64decode(processed_data)
                    processed_data = decoded_bytes.decode('utf-8', errors='replace')
                    print(f"  Detected and decoded Base64 content from {url}.")
                except Exception:
                    print(f"  Could not decode Base64 content from {url}, treating as plain text.")

            keys_from_source = [line.strip() for line in processed_data.splitlines() if line.strip() and any(line.strip().startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"])]
            print(f"  Found {len(keys_from_source)} potential keys from {url}.")
            all_keys_to_test.extend(keys_from_source)
        except requests.exceptions.RequestException as e: print(f"ERROR: Failed to fetch keys from {url}: {e}")
        except Exception as e: print(f"ERROR: Failed to process source from {url}: {e}")

    unique_keys_to_test = list(dict.fromkeys(all_keys_to_test))
    print(f"\nTotal unique potential keys to test: {len(unique_keys_to_test)}")

    working_keys = []
    tested_count = 0; start_test_time = time.time()
    print(f"\n--- Starting Tests (Timeout: {TEST_TIMEOUT}s) ---")
    for key in unique_keys_to_test:
        _key_url_ignored, is_working = test_v2ray_key(key)
        if is_working:
            working_keys.append(key)
        tested_count += 1
        if tested_count % 100 == 0 or tested_count == len(unique_keys_to_test):
            elapsed = time.time() - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
            print(f"Progress: Tested {tested_count}/{len(unique_keys_to_test)} keys... ({elapsed:.1f}s, {rate:.1f} keys/s)")

    print("\n--- Test Results Summary ---")
    print(f"  Found {len(working_keys)} working keys.")

    # Save working keys to a single file
    with open(OUTPUT_FILE, 'w', encoding='utf-8', newline='\n') as f:
        for key in working_keys:
            f.write(key + '\n')
    print(f"  Working keys saved to {OUTPUT_FILE}")

    end_time = time.time()
    print(f"Script finished in {end_time - start_time:.2f} seconds.")
    print("----------------------------------------")

if __name__ == "__main__":
    main()
