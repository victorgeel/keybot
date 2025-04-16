#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# FILE: test_and_upload.py
# Description: Fetches V2Ray/Xray keys from multiple sources,
#              tests their connectivity using the xray-knife ping command,
#              stops testing early when a target number of working keys are found,
#              deduplicates and saves the working keys to a file.
# Version: 2.5 (Using xray-knife, Fixed SyntaxErrors, Improved success pattern, Added missing import)

import requests
import subprocess
import os
import json # Kept for potential future use
import tempfile # Kept for potential future use
import time
import platform
import zipfile
import io
import stat
import base64
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
import sys
import socket
import re
import random
import traceback # For printing detailed tracebacks on errors
import signal # *** ADDED MISSING IMPORT ***

# --- Configuration ---
print("--- Script Configuration ---")
# Read subscription URLs from GitHub Actions secret
SOURCE_URLS_RAW = os.environ.get('SOURCE_URLS_SECRET', '')
SOURCE_URLS_LIST = [url.strip() for url in SOURCE_URLS_RAW.splitlines() if url.strip()]

if not SOURCE_URLS_LIST:
    print("ERROR: SOURCE_URLS_SECRET environment variable is empty or not set. Please configure the secret.", file=sys.stderr)
    sys.exit(1) # Exit if no sources are provided
else:
    print(f"Loaded {len(SOURCE_URLS_LIST)} URLs from SOURCE_URLS_SECRET.")

# Output directory and filename
OUTPUT_DIR = "subscription"
OUTPUT_FILENAME = "working_keys.txt"
OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)
print(f"Output file path: {OUTPUT_FILE_PATH}")

# Path for the xray-knife executable
XRAY_KNIFE_PATH = "./xray-knife"
print(f"Expected xray-knife path: {XRAY_KNIFE_PATH}")

# Concurrency settings
MAX_WORKERS = 15 # Adjust based on runner resources and network stability
print(f"Max worker threads for testing: {MAX_WORKERS}")

# Timeout settings
REQUEST_TIMEOUT = 25 # Timeout for fetching subscription URLs (increased slightly)
print(f"Subscription fetch timeout: {REQUEST_TIMEOUT}s")
TEST_PING_TIMEOUT = 10 # Timeout value passed to the 'xray-knife ping --timeout' flag
print(f"xray-knife ping --timeout flag: {TEST_PING_TIMEOUT}s")
SUBPROCESS_TIMEOUT = TEST_PING_TIMEOUT + 5 # Max time for the entire xray-knife subprocess call
print(f"Subprocess execution timeout: {SUBPROCESS_TIMEOUT}s")

# Early exit configuration
TARGET_EARLY_EXIT_KEYS = 700 # Stop testing when this many working keys are found
print(f"Target working keys to stop testing early: {TARGET_EARLY_EXIT_KEYS}")

# Supported key URL protocols (ensure xray-knife ping supports these)
SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"]
print(f"Supported protocols for testing: {SUPPORTED_PROTOCOLS}")

# User-Agent for fetching subscription URLs
REQUEST_HEADERS = {
    'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 KeyTester/2.5' # Version bump
}
print(f"Subscription Fetch Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

# --- xray-knife Installation/Verification ---
def download_and_extract_xray_knife():
    """
    Downloads the latest release of xray-knife for the current OS/architecture
    from GitHub, extracts it, makes it executable, and verifies it.
    Returns True on success, False on failure.
    """
    print("\n--- Checking/Downloading xray-knife ---")
    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)

    # Check if already exists and is executable
    if os.path.exists(abs_xray_knife_path) and os.access(abs_xray_knife_path, os.X_OK):
         print(f"xray-knife executable already exists at {abs_xray_knife_path} and is executable. Skipping download.")
         return True

    try:
        # Fetch latest release information from GitHub API
        api_url = "https://api.github.com/repos/lilendian0x00/xray-knife/releases/latest"
        github_token = os.environ.get('GH_TOKEN') # Use GITHUB_TOKEN passed from workflow
        headers = {'Accept': 'application/vnd.github.v3+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if github_token:
            headers['Authorization'] = f'Bearer {github_token}'
            print("Using GH_TOKEN/GITHUB_TOKEN for GitHub API request.")
        else:
            print("Warning: GH_TOKEN/GITHUB_TOKEN not found. Making unauthenticated API request (rate limits may apply).")

        print(f"Fetching latest release info from {api_url}")
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        release_info = response.json()
        tag_name = release_info.get('tag_name', 'N/A')
        print(f"Latest xray-knife version tag: {tag_name}")

        # Determine asset name based on OS and architecture
        system = platform.system().lower()
        machine = platform.machine().lower()
        print(f"Detected System: {system}, Machine: {machine}")

        # Asset name logic corrected based on previous error log
        asset_name = None
        if system == 'linux':
            if machine in ['x86_64', 'amd64']:
                asset_name = "Xray-knife-linux-64.zip"
            elif machine in ['aarch64', 'arm64']:
                asset_name = "Xray-knife-linux-arm64-v8a.zip"
            else:
                raise ValueError(f"Unsupported Linux architecture for xray-knife download: {machine}")
        # Add elif conditions for other OS if needed (ensure names match release page)
        else:
            raise ValueError(f"Unsupported operating system for automatic xray-knife download: {system}")

        if not asset_name:
             raise ValueError("Could not determine the correct asset name.")

        # Find the download URL for the determined asset name
        asset_url = None
        print(f"Searching for asset: {asset_name}")
        available_assets = [a.get('name') for a in release_info.get('assets', [])]
        for asset in release_info.get('assets', []):
            if asset.get('name') == asset_name:
                asset_url = asset.get('browser_download_url')
                print(f"Found asset URL: {asset_url}")
                break
        if not asset_url:
            raise ValueError(f"Could not find asset '{asset_name}' in release '{tag_name}'. Available assets: {available_assets}")

        # Download the asset
        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=180)
        download_response.raise_for_status()

        # Extract the executable
        print(f"Extracting {asset_name}...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray-knife.exe' if system == 'windows' else 'xray-knife'
                extracted = False
                for member in zf.namelist():
                    if member.endswith('/'): continue
                    member_base_name = os.path.basename(member)
                    if member_base_name == exe_name and not member.startswith('__MACOSX'):
                        print(f"  Found executable member: {member}")
                        zf.extract(member, path=".")
                        extracted_path = os.path.normpath(os.path.join(".", member))
                        print(f"  Extracted to: {extracted_path}")
                        if os.path.abspath(extracted_path) != abs_xray_knife_path:
                            print(f"  Moving/Renaming from {extracted_path} to {abs_xray_knife_path}...")
                            os.makedirs(os.path.dirname(abs_xray_knife_path) or '.', exist_ok=True)
                            if os.path.exists(abs_xray_knife_path) or os.path.islink(abs_xray_knife_path):
                                print(f"  Removing existing file/link at {abs_xray_knife_path}")
                                os.remove(abs_xray_knife_path)
                            os.rename(extracted_path, abs_xray_knife_path)
                        else:
                            print(f"  Extracted directly to target path: {abs_xray_knife_path}")
                        member_dir = os.path.dirname(member)
                        if member_dir and os.path.exists(os.path.join(".", member_dir)) and not os.listdir(os.path.join(".", member_dir)):
                            try: os.rmdir(os.path.join(".", member_dir)); print(f"  Removed empty source directory: {os.path.join('.', member_dir)}")
                            except OSError as rmdir_e: print(f"  Warning: Could not remove source directory {os.path.join('.', member_dir)}: {rmdir_e}")
                        print(f"  xray-knife executable placed at '{abs_xray_knife_path}'")
                        extracted = True; break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' executable not found within the downloaded zip file '{asset_name}'. Contents: {zf.namelist()}")
        else: raise NotImplementedError(f"Extraction logic not implemented for asset type: {asset_name}")
        if not os.path.exists(abs_xray_knife_path): raise FileNotFoundError(f"xray-knife executable not found at '{abs_xray_knife_path}' after extraction attempt.")

        # Set execute permissions
        if system != 'windows':
            try:
                print(f"Setting execute permissions for '{abs_xray_knife_path}'...")
                current_mode = os.stat(abs_xray_knife_path).st_mode
                new_mode = current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                if current_mode != new_mode: os.chmod(abs_xray_knife_path, new_mode); print(f"Permissions set to {oct(new_mode)}.")
                else: print("Execute permissions already set.")
                if not os.access(abs_xray_knife_path, os.X_OK): raise OSError("Execute permission check failed after chmod.")
            except Exception as chmod_e:
                print(f"ERROR: Failed to make '{abs_xray_knife_path}' executable: {chmod_e}. Trying fallback...", file=sys.stderr)
                try: subprocess.run(['chmod', '+x', abs_xray_knife_path], check=True); print("Fallback chmod +x command succeeded.")
                except Exception as fallback_e: print(f"ERROR: Fallback chmod failed: {fallback_e}.", file=sys.stderr); return False

        # Verify installation
        print(f"Verifying xray-knife installation by running: {abs_xray_knife_path} -v")
        try:
            version_process = subprocess.run( [abs_xray_knife_path, "-v"], capture_output=True, text=True, timeout=15, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY-KNIFE VERSION OUTPUT ---"); print(f"Command: {' '.join(version_process.args)}"); print(f"Exit Code: {version_process.returncode}"); stdout_strip = version_process.stdout.strip() if version_process.stdout else ""; stderr_strip = version_process.stderr.strip() if version_process.stderr else ""; print(f"Stdout: {stdout_strip}");
            if stderr_strip: print(f"Stderr: {stderr_strip}"); print(f"--- END XRAY-KNIFE VERSION OUTPUT ---")
            if version_process.returncode != 0 or "xray-knife" not in stdout_strip.lower(): print("Warning: xray-knife version command failed or output did not contain 'xray-knife'. Check output above.", file=sys.stderr)
            else: print("xray-knife version verified successfully.")
        except subprocess.TimeoutExpired: print(f"ERROR: Timeout expired while running '{abs_xray_knife_path} -v'.", file=sys.stderr); return False
        except FileNotFoundError: print(f"ERROR: Cannot execute '{abs_xray_knife_path}' (File not found during verification).", file=sys.stderr); return False
        except Exception as verify_e: print(f"ERROR: Unexpected error during xray-knife verification: {verify_e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return False

        print("xray-knife download and setup appears complete.")
        return True

    except requests.exceptions.RequestException as req_e: print(f"ERROR: Network error during xray-knife download: {req_e}", file=sys.stderr); return False
    except zipfile.BadZipFile as zip_e: print(f"ERROR: Downloaded file is not a valid ZIP file: {zip_e}", file=sys.stderr); return False
    except (ValueError, NotImplementedError, FileNotFoundError, OSError) as setup_e: print(f"ERROR: Failed during xray-knife setup: {setup_e}", file=sys.stderr); return False
    except Exception as e: print(f"ERROR: An unexpected error occurred in download_and_extract_xray_knife: {e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return False


# --- Key Testing Function (using xray-knife ping) ---
def test_v2ray_key(key_url):
    """
    Tests a single V2Ray/Xray key URL using the 'xray-knife ping' command.
    Returns a tuple: (key_url, is_working)
    """
    key_url = key_url.strip()

    if not key_url or not any(key_url.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
        return key_url, False

    is_working = False
    final_fail_reason = "Test not run"
    stdout_data = ""
    stderr_data = ""

    # Optional: Quick Socket Pre-check
    host = None; port = None
    try:
        parsed = urlparse(key_url); host = parsed.hostname
        port = parsed.port if parsed.port else {'vmess': 443, 'vless': 443, 'trojan': 443, 'ss': 8388}.get(parsed.scheme, 443)
        if not host: final_fail_reason = "Invalid URL (no hostname)"; return key_url, False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0); s.connect((host, port))
    except socket.gaierror: final_fail_reason = "Pre-check DNS failed"; return key_url, False
    except (socket.timeout, ConnectionRefusedError, OSError) as e_sock: final_fail_reason = f"Pre-check connection failed ({type(e_sock).__name__})"; pass
    except Exception as e_pre_other: print(f"Warning: Unexpected pre-check error for {key_url[:30]}...: {e_pre_other}", file=sys.stderr); pass

    # Main Test using xray-knife ping
    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)
    cmd = [ abs_xray_knife_path, "ping", "link", key_url, "--timeout", str(TEST_PING_TIMEOUT) + "s" ]

    try:
        process = subprocess.run( cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT, check=False, encoding='utf-8', errors='replace')
        stdout_data = process.stdout.strip() if process.stdout else ""
        stderr_data = process.stderr.strip() if process.stderr else ""

        # Determine Success/Failure
        success_pattern = r'Success,.*(RTT|Delay):\s*\d+ms'

        if process.returncode == 0 and re.search(success_pattern, stdout_data, re.IGNORECASE):
            is_working = True; final_fail_reason = ""
        else:
            is_working = False
            if process.returncode != 0: final_fail_reason = f"xray-knife exited with code {process.returncode}" ;
            elif "timeout" in stdout_data.lower() or "timeout" in stderr_data.lower(): final_fail_reason = f"Ping Timeout detected in output"
            elif stderr_data: final_fail_reason = f"Error in Stderr: {stderr_data.splitlines()[0]}"[:150]
            elif stdout_data: final_fail_reason = f"Output (No Success Pattern): {stdout_data.splitlines()[0]}"[:150]
            else: final_fail_reason = f"Exit Code {process.returncode} and No Output"
            if is_working == False and process.returncode!=0 and stderr_data: final_fail_reason += f" ({stderr_data.splitlines()[0] if stderr_data else ''})".rstrip()[:150] # Append stderr snippet if exit code non-zero

        return key_url, is_working

    except subprocess.TimeoutExpired: final_fail_reason = f"Subprocess Timeout ({SUBPROCESS_TIMEOUT}s)"; print(f"ERROR: {final_fail_reason} for Key: {key_url[:50]}...", file=sys.stderr); return key_url, False
    except FileNotFoundError: final_fail_reason = f"xray-knife not found at {abs_xray_knife_path}"; print(f"ERROR: {final_fail_reason}. Ensure setup step succeeded.", file=sys.stderr); return key_url, False
    except Exception as e_test: final_fail_reason = f"Unexpected error during ping: {e_test}"; print(f"ERROR: {final_fail_reason} for Key: {key_url[:50]}...", file=sys.stderr); traceback.print_exc(file=sys.stderr); return key_url, False
    finally:
        if not is_working:
             log_message = f"DEBUG: Test FAIL Key: {key_url[:60]}... Reason: {final_fail_reason}"
             # Avoid printing redundant stderr if already included in reason
             if stderr_data and "Stderr" not in final_fail_reason and "exited with code" not in final_fail_reason: log_message += f" | Stderr: {stderr_data.splitlines()[0]}"[:150]
             print(log_message, file=sys.stderr)

# --- Main Execution Logic ---
def main():
    """Main function to orchestrate the key fetching, testing, and saving."""
    script_start_time = time.time()
    print(f"\n=== Starting Key Tester Script (v2.5 - using xray-knife) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

    # Step 1: Setup xray-knife
    if not download_and_extract_xray_knife(): print("FATAL: Failed to setup xray-knife. Exiting.", file=sys.stderr); sys.exit(1)
    abs_xray_knife_path_main = os.path.abspath(XRAY_KNIFE_PATH)
    if not os.path.exists(abs_xray_knife_path_main) or not os.access(abs_xray_knife_path_main, os.X_OK): print(f"FATAL: xray-knife executable is not ready at {abs_xray_knife_path_main} after setup attempt. Exiting.", file=sys.stderr); sys.exit(1)
    print(f"Confirmed xray-knife executable is ready: {abs_xray_knife_path_main}")

    # Step 2: Prepare Output Directory
    print(f"\n--- Step 2: Preparing Output Directory ({OUTPUT_DIR}) ---")
    try: os.makedirs(OUTPUT_DIR, exist_ok=True); print(f"Output directory '{OUTPUT_DIR}' ensured/created.")
    except OSError as e: print(f"FATAL: Could not create output directory {OUTPUT_DIR}: {e}", file=sys.stderr); sys.exit(1)

    # Step 3: Fetch Keys from Source URLs
    print("\n--- Step 3: Fetching Keys from Source URLs ---")
    all_fetched_keys_raw = []; fetch_errors = 0; total_lines_fetched = 0
    for index, url in enumerate(SOURCE_URLS_LIST):
        print(f"\nFetching from URL {index+1}/{len(SOURCE_URLS_LIST)}: {url[:100]}...")
        try:
            response = requests.get( url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True); response.raise_for_status(); raw_data = None
            try: raw_data = response.content.decode('utf-8'); print(f"  Successfully decoded as UTF-8.")
            except UnicodeDecodeError:
                 try:
                     encoding = response.encoding if response.encoding else response.apparent_encoding; encoding = encoding if encoding else 'iso-8859-1'
                     raw_data = response.content.decode(encoding, errors='replace'); print(f"  Warning: UTF-8 decode failed. Decoded as {encoding} (best guess/fallback).")
                 except Exception as decode_err:
                     raw_data = response.content.decode('iso-8859-1', errors='replace'); print(f"  ERROR: Failed to decode content properly: {decode_err}. Using forced iso-8859-1.", file=sys.stderr); fetch_errors += 1
            lines = raw_data.splitlines(); count_for_source = 0
            for line in lines:
                line = line.strip();
                if line: all_fetched_keys_raw.append(line); count_for_source += 1
            total_lines_fetched += count_for_source; print(f" -> Fetched {count_for_source} non-empty lines from this source.")
        except requests.exceptions.Timeout: print(f"ERROR: Timeout occurred while fetching {url[:100]}", file=sys.stderr); fetch_errors += 1
        except requests.exceptions.RequestException as e: print(f"ERROR: Failed fetching {url[:100]}: {e}", file=sys.stderr); fetch_errors += 1
        except Exception as e: print(f"ERROR: An unexpected error occurred while processing {url[:100]}: {e}", file=sys.stderr); fetch_errors += 1; traceback.print_exc(file=sys.stderr)

    # Check if any keys were fetched
    print(f"\nFinished fetching. Total non-empty lines fetched: {total_lines_fetched}. Source URL fetch errors: {fetch_errors}.")
    # Corrected block for handling no fetched keys
    if not all_fetched_keys_raw:
        print("Error: No key lines were fetched from any source URL. Writing empty output file.", file=sys.stderr)
        try:
            with open(OUTPUT_FILE_PATH, 'w') as f: pass
            print(f"Created empty output file: {OUTPUT_FILE_PATH}")
        except IOError as e_f:
            print(f"Warning: Could not create empty output file {OUTPUT_FILE_PATH}: {e_f}", file=sys.stderr)
        print(f"Exiting script. Fetch errors: {fetch_errors}, Total sources: {len(SOURCE_URLS_LIST)}")
        sys.exit(0 if fetch_errors < len(SOURCE_URLS_LIST) else 1)

    # Step 4: Process Fetched Lines (Decode Base64, Deduplicate)
    print("\n--- Step 4: Processing Fetched Lines & Deduplicating Keys ---")
    unique_keys_to_test = set(); processed_line_count = 0; decode_attempts = 0; keys_found_in_base64 = 0; skipped_invalid_lines = 0
    for line in all_fetched_keys_raw:
        processed_line_count += 1
        if any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS): unique_keys_to_test.add(line)
        else:
            decode_attempts += 1
            try:
                line_padded = line + '=' * (-len(line) % 4); decoded_content = base64.b64decode(line_padded).decode('utf-8', errors='replace')
                found_keys = re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>\`\\]+', decoded_content)
                if found_keys:
                    for key in found_keys:
                        key = key.strip()
                        if any(key.startswith(proto) for proto in SUPPORTED_PROTOCOLS): unique_keys_to_test.add(key); keys_found_in_base64 += 1
            except (base64.binascii.Error, UnicodeDecodeError): skipped_invalid_lines += 1
            except Exception as e_dec: print(f"Warning: Error processing potential Base64 line: {e_dec}", file=sys.stderr); skipped_invalid_lines += 1
    unique_keys_list = list(unique_keys_to_test)
    print(f"Processed {processed_line_count} fetched lines.")
    print(f"Found {len(unique_keys_list)} unique potential keys matching supported protocols {SUPPORTED_PROTOCOLS}.")
    print(f"(Base64 decode attempts: {decode_attempts}, Keys successfully extracted from Base64: {keys_found_in_base64}, Skipped/invalid lines: {skipped_invalid_lines})")

    # Step 5: Test Unique Keys Concurrently
    print("\n--- Step 5: Testing Unique Keys Concurrently ---")
    # Corrected block for handling no unique keys found *after* processing
    if not unique_keys_list:
        print("No unique valid keys found to test after processing. Writing empty file.")
        try:
            with open(OUTPUT_FILE_PATH, 'w') as f: pass
            print(f"Created empty output file: {OUTPUT_FILE_PATH}")
        except IOError as e_f:
            print(f"Warning: Could not create empty output file {OUTPUT_FILE_PATH}: {e_f}", file=sys.stderr)
        sys.exit(0)

    # Continue with testing if unique_keys_list is not empty
    print(f"Starting tests for {len(unique_keys_list)} unique keys...")
    print(f"(Target working keys for early exit: {TARGET_EARLY_EXIT_KEYS})")
    print(f"(Max Workers: {MAX_WORKERS}, Ping Timeout: {TEST_PING_TIMEOUT}s per key)")

    all_working_keys = []; tested_count = 0; start_test_time = time.time(); futures_cancelled = 0; stop_early = False
    random.shuffle(unique_keys_list)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_list}; active_futures = list(future_to_key.keys())
        for future in as_completed(active_futures):
            if stop_early:
                if not future.done(): future.cancel()
                continue
            key_original = future_to_key[future]; tested_count += 1
            try:
                if future.cancelled(): continue
                _key_returned, is_working = future.result()
                if is_working:
                    all_working_keys.append(key_original); found_count = len(all_working_keys)
                    if not stop_early and found_count >= TARGET_EARLY_EXIT_KEYS:
                        stop_early = True; print(f"\nTarget of {TARGET_EARLY_EXIT_KEYS} working keys reached! Stopping testing early."); print("Attempting to cancel remaining pending tests...")
                        cancelled_now = 0
                        for f_obj in active_futures:
                            if not f_obj.done():
                                if f_obj.cancel(): cancelled_now += 1
                        futures_cancelled = cancelled_now; print(f"Attempted to cancel {futures_cancelled} tests.")
            except Exception as e_future: print(f"\nWarning: Error processing test result for key starting with '{key_original[:40]}...': {e_future}", file=sys.stderr)
            if tested_count % 50 == 0 or tested_count == len(unique_keys_list) or (stop_early and tested_count > 0):
                 current_time = time.time(); elapsed = current_time - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
                 progress_message = f"Progress: Tested {tested_count}/{len(unique_keys_list)} | Found: {len(all_working_keys)} | Rate: {rate:.1f} keys/s | Elapsed: {elapsed:.0f}s"
                 if stop_early: progress_message += " (Stopping Early)"
                 print(progress_message, end='\n' if stop_early or tested_count == len(unique_keys_list) else '\r')
    print(); print(f"Finished testing phase. Total keys submitted for testing: {len(unique_keys_list)}. Keys actually processed: {tested_count}."); test_duration = time.time() - start_test_time; print(f"Total testing time: {test_duration:.2f} seconds.")
    if stop_early: print(f"({futures_cancelled} tests were flagged for cancellation after reaching target)")

    # Step 6: Write Working Keys to Output File
    print("\n--- Step 6: Writing Results to File ---")
    num_working_found = len(all_working_keys); print(f"Total working keys collected after testing: {num_working_found} (Target was {TARGET_EARLY_EXIT_KEYS})")
    random.shuffle(all_working_keys); print(f"Shuffled {num_working_found} working keys.")
    if num_working_found > TARGET_EARLY_EXIT_KEYS: print(f"Limiting final output to the target of {TARGET_EARLY_EXIT_KEYS} keys."); keys_to_write = all_working_keys[:TARGET_EARLY_EXIT_KEYS]
    else: keys_to_write = all_working_keys
    num_keys_to_write = len(keys_to_write); print(f"Number of keys to be written to file: {num_keys_to_write}")
    try:
        with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f:
            for key_to_write in keys_to_write: f.write(key_to_write.replace('\r\n', '\n').replace('\r', '\n') + '\n')
        print(f"Successfully wrote {num_keys_to_write} working keys to: {OUTPUT_FILE_PATH}"); print(f"Absolute path: {os.path.abspath(OUTPUT_FILE_PATH)}")
    except IOError as e_w: print(f"ERROR: Failed to write output file {OUTPUT_FILE_PATH}: {e_w}", file=sys.stderr); sys.exit(1)

    # Step 7: Final Summary
    print("\n--- Script Summary ---")
    script_end_time = time.time(); total_script_time = script_end_time - script_start_time
    print(f"Total working keys COLLECTED during testing: {num_working_found}"); print(f"Total working keys WRITTEN to file (limit: {TARGET_EARLY_EXIT_KEYS}): {num_keys_to_write}"); print(f"Output file location: {os.path.abspath(OUTPUT_FILE_PATH)}")
    print(f"Script finished execution in {total_script_time:.2f} seconds."); print("======================================================")

# --- Script Entry Point ---
if __name__ == "__main__":
    # Define signal handler function
    def handle_signal(sig, frame):
        """Signal handler for SIGINT and SIGTERM."""
        print(f"\nSignal {sig} received. Initiating graceful shutdown...")
        # No complex cleanup needed here as resources (files, subprocesses)
        # are generally handled within their respective blocks or contexts.
        sys.exit(1) # Exit with a non-zero code indicating interruption

    # Set up signal handlers
    try:
        signal.signal(signal.SIGINT, handle_signal)  # Handle Ctrl+C
        signal.signal(signal.SIGTERM, handle_signal) # Handle termination signal (e.g., from Actions timeout)
        print("Signal handlers set up.")
    except (AttributeError, ValueError, OSError) as e_signal:
        # Catch errors if signal module is not available or setting fails
        print(f"Warning: Could not set signal handlers ({e_signal}). Graceful shutdown via signal might not work.")
        pass # Continue execution even if signal handlers fail to set

    # Run the main function
    main()
