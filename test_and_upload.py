#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# FILE: test_and_upload.py
# Description: Fetches V2Ray/Xray keys, tests using xray-knife check command,
#              handles early exit, saves working keys. Adds help check.
# Version: 3.1 (Added --help check for diagnostics)

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
import signal # For graceful shutdown attempt on SIGINT/SIGTERM

# --- Configuration ---
print("--- Script Configuration ---")
SOURCE_URLS_RAW = os.environ.get('SOURCE_URLS_SECRET', '')
SOURCE_URLS_LIST = [url.strip() for url in SOURCE_URLS_RAW.splitlines() if url.strip()]

if not SOURCE_URLS_LIST:
    print("ERROR: SOURCE_URLS_SECRET environment variable is empty or not set.", file=sys.stderr)
    sys.exit(1)
else:
    print(f"Loaded {len(SOURCE_URLS_LIST)} URLs from SOURCE_URLS_SECRET.")

OUTPUT_DIR = "subscription"
OUTPUT_FILENAME = "working_keys.txt"
OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)
print(f"Output file path: {OUTPUT_FILE_PATH}")

XRAY_KNIFE_PATH = "./xray-knife"
print(f"Expected xray-knife path: {XRAY_KNIFE_PATH}")

MAX_WORKERS = 15
print(f"Max worker threads for testing: {MAX_WORKERS}")

REQUEST_TIMEOUT = 25
print(f"Subscription fetch timeout: {REQUEST_TIMEOUT}s")
TEST_TIMEOUT = 10
print(f"xray-knife check --timeout flag: {TEST_TIMEOUT}s")
SUBPROCESS_TIMEOUT = TEST_TIMEOUT + 5
print(f"Subprocess execution timeout: {SUBPROCESS_TIMEOUT}s")

TARGET_EARLY_EXIT_KEYS = 700
print(f"Target working keys to stop testing early: {TARGET_EARLY_EXIT_KEYS}")

SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"]
print(f"Supported protocols for testing: {SUPPORTED_PROTOCOLS}")

REQUEST_HEADERS = {
    'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36 KeyTester/3.1' # Version bump
}
print(f"Subscription Fetch Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

# --- xray-knife Installation/Verification ---
def download_and_extract_xray_knife():
    """Downloads and extracts xray-knife."""
    print("\n--- Checking/Downloading xray-knife ---")
    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)
    if os.path.exists(abs_xray_knife_path) and os.access(abs_xray_knife_path, os.X_OK):
         print(f"xray-knife executable already exists: {abs_xray_knife_path}. Skipping.")
         return True
    try:
        api_url = "https://api.github.com/repos/lilendian0x00/xray-knife/releases/latest"
        github_token = os.environ.get('GH_TOKEN')
        headers = {'Accept': 'application/vnd.github.v3+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if github_token: headers['Authorization'] = f'Bearer {github_token}'; print("Using GH_TOKEN for API request.")
        else: print("Warning: GH_TOKEN not found.")
        print(f"Fetching release info: {api_url}")
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers); response.raise_for_status()
        release_info = response.json(); tag_name = release_info.get('tag_name', 'N/A'); print(f"Latest tag: {tag_name}")
        system = platform.system().lower(); machine = platform.machine().lower(); print(f"System: {system}, Machine: {machine}")
        asset_name = None
        if system == 'linux':
            if machine in ['x86_64', 'amd64']: asset_name = "Xray-knife-linux-64.zip"
            elif machine in ['aarch64', 'arm64']: asset_name = "Xray-knife-linux-arm64-v8a.zip"
            else: raise ValueError(f"Unsupported Linux arch: {machine}")
        else: raise ValueError(f"Unsupported OS: {system}")
        if not asset_name: raise ValueError("Could not determine asset name.")
        asset_url = None; print(f"Searching for asset: {asset_name}")
        available_assets = [a.get('name') for a in release_info.get('assets', [])]
        for asset in release_info.get('assets', []):
            if asset.get('name') == asset_name: asset_url = asset.get('browser_download_url'); print(f"Found asset URL: {asset_url}"); break
        if not asset_url: raise ValueError(f"Asset '{asset_name}' not found in release '{tag_name}'. Available: {available_assets}")
        print(f"Downloading: {asset_url}..."); download_response = requests.get(asset_url, stream=True, timeout=180); download_response.raise_for_status()
        print(f"Extracting: {asset_name}...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray-knife.exe' if system == 'windows' else 'xray-knife'; extracted = False
                for member in zf.namelist():
                    if member.endswith('/'): continue
                    member_base_name = os.path.basename(member)
                    if member_base_name == exe_name and not member.startswith('__MACOSX'):
                        print(f"  Found executable: {member}"); zf.extract(member, path="."); extracted_path = os.path.normpath(os.path.join(".", member)); print(f"  Extracted to: {extracted_path}")
                        if os.path.abspath(extracted_path) != abs_xray_knife_path:
                            print(f"  Moving to: {abs_xray_knife_path}..."); os.makedirs(os.path.dirname(abs_xray_knife_path) or '.', exist_ok=True)
                            if os.path.exists(abs_xray_knife_path) or os.path.islink(abs_xray_knife_path): print(f"  Removing existing: {abs_xray_knife_path}"); os.remove(abs_xray_knife_path)
                            os.rename(extracted_path, abs_xray_knife_path)
                        else: print(f"  Extracted to target path: {abs_xray_knife_path}")
                        member_dir = os.path.dirname(member)
                        if member_dir and os.path.exists(os.path.join(".", member_dir)) and not os.listdir(os.path.join(".", member_dir)):
                            try: os.rmdir(os.path.join(".", member_dir)); print(f"  Removed empty source dir: {os.path.join('.', member_dir)}")
                            except OSError as rmdir_e: print(f"  Warning: Could not remove source dir {os.path.join('.', member_dir)}: {rmdir_e}")
                        print(f"  Executable placed at: '{abs_xray_knife_path}'"); extracted = True; break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' not found in {asset_name}. Contents: {zf.namelist()}")
        else: raise NotImplementedError(f"Extraction not implemented for: {asset_name}")
        if not os.path.exists(abs_xray_knife_path): raise FileNotFoundError(f"Executable not found at '{abs_xray_knife_path}' post-extraction.")
        if system != 'windows':
            try:
                print(f"Setting execute permissions..."); current_mode = os.stat(abs_xray_knife_path).st_mode; new_mode = current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                if current_mode != new_mode: os.chmod(abs_xray_knife_path, new_mode); print(f"Permissions set: {oct(new_mode)}.")
                else: print("Execute permissions ok.")
                if not os.access(abs_xray_knife_path, os.X_OK): raise OSError("Execute check failed.")
            except Exception as chmod_e:
                print(f"ERROR: Failed making executable: {chmod_e}. Fallback...", file=sys.stderr)
                try: subprocess.run(['chmod', '+x', abs_xray_knife_path], check=True); print("Fallback chmod +x ok.")
                except Exception as fallback_e: print(f"ERROR: Fallback chmod failed: {fallback_e}.", file=sys.stderr); return False
        print(f"Verifying xray-knife: {abs_xray_knife_path} -v")
        try:
            version_process = subprocess.run( [abs_xray_knife_path, "-v"], capture_output=True, text=True, timeout=15, check=False, encoding='utf-8', errors='replace')
            print(f"--- VERSION ---"); print(f"Cmd: {' '.join(version_process.args)}"); print(f"Code: {version_process.returncode}"); stdout_strip = version_process.stdout.strip() if version_process.stdout else ""; stderr_strip = version_process.stderr.strip() if version_process.stderr else ""; print(f"Out: {stdout_strip}");
            if stderr_strip: print(f"Err: {stderr_strip}"); print(f"--- END ---")
            if version_process.returncode != 0 or "xray-knife" not in stdout_strip.lower(): print("Warning: Version check failed.", file=sys.stderr)
            else: print("xray-knife version ok.")
        except subprocess.TimeoutExpired: print(f"ERROR: Timeout verifying.", file=sys.stderr); return False
        except FileNotFoundError: print(f"ERROR: Cannot execute.", file=sys.stderr); return False
        except Exception as verify_e: print(f"ERROR: Verification failed: {verify_e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return False
        print("xray-knife setup ok.")
        return True
    except requests.exceptions.RequestException as req_e: print(f"ERROR: Download failed: {req_e}", file=sys.stderr); return False
    except zipfile.BadZipFile as zip_e: print(f"ERROR: Bad ZIP: {zip_e}", file=sys.stderr); return False
    except (ValueError, NotImplementedError, FileNotFoundError, OSError) as setup_e: print(f"ERROR: Setup failed: {setup_e}", file=sys.stderr); return False
    except Exception as e: print(f"ERROR: Unexpected setup error: {e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return False

# --- Key Testing Function ---
def test_v2ray_key(key_url):
    """Tests a single key using xray-knife check."""
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
        if not host: final_fail_reason = "No host"; return key_url, False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3.0); s.connect((host, port))
    except socket.gaierror: final_fail_reason = "DNS fail"; return key_url, False
    except (socket.timeout, ConnectionRefusedError, OSError) as e_sock: final_fail_reason = f"Conn fail ({type(e_sock).__name__})"; pass
    except Exception as e_pre_other: print(f"Warn: Pre-check err {key_url[:30]}: {e_pre_other}", file=sys.stderr); pass

    # Main Test using xray-knife check
    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)
    # *** Using 'check' command - VERIFY THIS IS CORRECT via --help output ***
    cmd = [abs_xray_knife_path, "check", "link", key_url, "--timeout", str(TEST_TIMEOUT) + "s"]

    try:
        process = subprocess.run(
            cmd, capture_output=True, text=True, timeout=SUBPROCESS_TIMEOUT,
            check=False, encoding='utf-8', errors='replace'
        )
        stdout_data = process.stdout.strip() if process.stdout else ""
        stderr_data = process.stderr.strip() if process.stderr else ""

        # Determine Success/Failure
        success_pattern = r'Success,.*(RTT|Delay):\s*\d+ms'

        if process.returncode == 0 and re.search(success_pattern, stdout_data, re.IGNORECASE):
            is_working = True
            final_fail_reason = ""
        else:
            is_working = False
            if process.returncode != 0:
                final_fail_reason = f"Exit Code {process.returncode}"
                if stderr_data:
                    # Try to extract specific error from stderr
                    error_match = re.search(r'Error:\s*(.*)', stderr_data, re.IGNORECASE)
                    if error_match:
                        final_fail_reason += f" ({error_match.group(1).strip()})"[:150]
                    else: # Fallback to first line of stderr
                        final_fail_reason += f" ({stderr_data.splitlines()[0]})"[:150]
            elif "timeout" in stdout_data.lower() or "timeout" in stderr_data.lower():
                 final_fail_reason = f"Check Timeout"
            elif stderr_data: # Exit code 0 but stderr has content
                 final_fail_reason = f"Stderr (Exit 0): {stderr_data.splitlines()[0]}"[:150]
            elif stdout_data: # Exit code 0, no stderr, but stdout doesn't match success
                 final_fail_reason = f"No Success Pattern: {stdout_data.splitlines()[0]}"[:150]
            else: # Exit code 0, no output
                final_fail_reason = f"Exit Code 0, No Output"

        return key_url, is_working

    except subprocess.TimeoutExpired:
        final_fail_reason = f"Subprocess Timeout"
        print(f"ERROR: {final_fail_reason} Key: {key_url[:50]}...", file=sys.stderr)
        return key_url, False
    except FileNotFoundError:
        final_fail_reason = f"Not Found {abs_xray_knife_path}"
        print(f"ERROR: {final_fail_reason}", file=sys.stderr)
        return key_url, False
    except Exception as e_test:
        final_fail_reason = f"Unexpected check error: {e_test}"
        print(f"ERROR: {final_fail_reason} Key: {key_url[:50]}...", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return key_url, False
    finally:
        if not is_working:
             log_message = f"DEBUG: FAIL Key: {key_url[:60]}... Reason: {final_fail_reason}"
             # Avoid printing redundant stderr if already included in reason
             if stderr_data and "Stderr" not in final_fail_reason and "Exit Code" not in final_fail_reason:
                 log_message += f" | Stderr: {stderr_data.splitlines()[0]}"[:150]
             print(log_message, file=sys.stderr)

# --- Main Execution Logic ---
def main():
    """Main function."""
    script_start_time = time.time()
    print(f"\n=== Starting Key Tester (v3.1 - added help check) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

    # Step 1: Setup xray-knife
    if not download_and_extract_xray_knife():
        print("FATAL: Setup failed.", file=sys.stderr)
        sys.exit(1)
    abs_path = os.path.abspath(XRAY_KNIFE_PATH)
    if not os.path.exists(abs_path) or not os.access(abs_path, os.X_OK):
        print(f"FATAL: Not ready: {abs_path}.", file=sys.stderr)
        sys.exit(1)
    print(f"Confirmed executable: {abs_path}")

    # *** ADDED: Run --help to see available commands ***
    print("\n--- Checking available xray-knife commands ---")
    try:
        help_process = subprocess.run(
            [abs_path, "--help"], capture_output=True, text=True,
            timeout=10, check=False, encoding='utf-8', errors='replace'
        )
        print(f"Exit Code: {help_process.returncode}")
        print("--- Help Output START ---")
        # Print both stdout and stderr as help might go to either
        if help_process.stdout:
            print(help_process.stdout)
        if help_process.stderr:
            print(help_process.stderr, file=sys.stderr) # Print stderr to stderr stream
        print("--- Help Output END ---")
        # Optional: Check if 'check' command is listed
        # combined_help_output = (help_process.stdout or "") + (help_process.stderr or "")
        # if 'check' not in combined_help_output: # Adjust check based on actual help format
        #    print("WARNING: 'check' command might not be listed in help output!", file=sys.stderr)

    except Exception as help_e:
        print(f"ERROR: Failed to execute '{abs_path} --help': {help_e}", file=sys.stderr)
        print("WARNING: Could not verify available commands. Proceeding with 'check' command.", file=sys.stderr)
    # *** END ADDED SECTION ***

    # Step 2: Output Dir
    print(f"\n--- Step 2: Output Dir ({OUTPUT_DIR}) ---")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"Output dir ok.")
    except OSError as e:
        print(f"FATAL: Cannot create dir {OUTPUT_DIR}: {e}", file=sys.stderr)
        sys.exit(1)

    # Step 3: Fetch Keys
    print("\n--- Step 3: Fetching Keys ---")
    all_fetched_keys_raw = []
    fetch_errors = 0
    total_lines_fetched = 0
    for index, url in enumerate(SOURCE_URLS_LIST):
        print(f"\nFetching {index+1}/{len(SOURCE_URLS_LIST)}: {url[:100]}...")
        try:
            response = requests.get( url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True)
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
            # Process lines with correct indentation
            lines = raw_data.splitlines()
            count_for_source = 0
            for line in lines:
                line = line.strip()
                if line:
                    all_fetched_keys_raw.append(line)
                    count_for_source += 1
            total_lines_fetched += count_for_source
            print(f" -> Fetched {count_for_source} non-empty lines from this source.")
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

    # Check if any keys fetched
    print(f"\nFetch done. Lines: {total_lines_fetched}. Errors: {fetch_errors}.")
    if not all_fetched_keys_raw:
        print("Error: No keys fetched. Writing empty file.", file=sys.stderr)
        try:
            with open(OUTPUT_FILE_PATH, 'w') as f:
                 pass # Create empty file
            print(f"Created empty: {OUTPUT_FILE_PATH}")
        except IOError as e_f:
            print(f"Warning: Cannot create empty file: {e_f}", file=sys.stderr)
        print(f"Exiting. Errors: {fetch_errors}, Sources: {len(SOURCE_URLS_LIST)}")
        sys.exit(0 if fetch_errors < len(SOURCE_URLS_LIST) else 1)

    # Step 4: Process Keys
    print("\n--- Step 4: Processing & Deduplicating ---")
    unique_keys_to_test = set()
    processed_line_count = 0
    decode_attempts = 0
    keys_found_in_base64 = 0
    skipped_invalid_lines = 0
    for line in all_fetched_keys_raw:
        processed_line_count += 1
        if any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
            unique_keys_to_test.add(line)
        else:
            decode_attempts += 1
            try: # Start try block for Base64 decode
                line_padded = line + '=' * (-len(line) % 4)
                decoded_content = base64.b64decode(line_padded).decode('utf-8', errors='replace')
                found_keys = re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>\`\\]+', decoded_content)
                if found_keys:
                    # Corrected indentation and structure
                    for key in found_keys:
                        key = key.strip()
                        if any(key.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
                            unique_keys_to_test.add(key)
                            keys_found_in_base64 += 1
            # Correctly placed except blocks
            except (base64.binascii.Error, UnicodeDecodeError):
                skipped_invalid_lines += 1
            except Exception as e_dec:
                print(f"Warning: Base64 process error: {e_dec}", file=sys.stderr)
                skipped_invalid_lines += 1
    unique_keys_list = list(unique_keys_to_test)
    print(f"Processed: {processed_line_count}. Unique found: {len(unique_keys_list)}.")
    print(f"(Base64: {decode_attempts} attempts, {keys_found_in_base64} found. Skipped: {skipped_invalid_lines})")

    # Step 5: Test Keys
    print("\n--- Step 5: Testing Keys ---")
    if not unique_keys_list:
        print("No keys to test. Writing empty file.")
        try:
            with open(OUTPUT_FILE_PATH, 'w') as f: pass
            print(f"Created empty: {OUTPUT_FILE_PATH}")
        except IOError as e_f: print(f"Warn: Cannot create empty file: {e_f}", file=sys.stderr)
        sys.exit(0)

    print(f"Testing {len(unique_keys_list)} keys (Target: {TARGET_EARLY_EXIT_KEYS})...")
    print(f"(Workers: {MAX_WORKERS}, Timeout: {TEST_TIMEOUT}s)")
    all_working_keys = []
    tested_count = 0
    start_test_time = time.time()
    futures_cancelled = 0
    stop_early = False
    random.shuffle(unique_keys_list)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_list}
        active_futures = list(future_to_key.keys())
        for future in as_completed(active_futures):
            if stop_early:
                if not future.done(): future.cancel()
                continue
            key_original = future_to_key[future]
            tested_count += 1
            try:
                if future.cancelled(): continue
                _key_returned, is_working = future.result()
                if is_working:
                    all_working_keys.append(key_original)
                    found_count = len(all_working_keys)
                    if not stop_early and found_count >= TARGET_EARLY_EXIT_KEYS:
                        stop_early = True
                        print(f"\nTarget {TARGET_EARLY_EXIT_KEYS} reached! Stopping.")
                        print("Cancelling...")
                        cancelled_now = 0
                        for f_obj in active_futures:
                            if not f_obj.done():
                                if f_obj.cancel(): cancelled_now += 1
                        futures_cancelled = cancelled_now
                        print(f"Cancelled {futures_cancelled}.")
            except Exception as e_future:
                 print(f"\nWarn: Error processing result '{key_original[:40]}...': {e_future}", file=sys.stderr)

            if tested_count % 50 == 0 or tested_count == len(unique_keys_list) or (stop_early and tested_count > 0):
                 current_time = time.time()
                 elapsed = current_time - start_test_time
                 rate = tested_count / elapsed if elapsed > 0 else 0
                 progress = f"Progress: {tested_count}/{len(unique_keys_list)} | Found: {len(all_working_keys)} | Rate: {rate:.1f} k/s | Elapsed: {elapsed:.0f}s"
                 if stop_early: progress += " (Stopping)"
                 print(progress, end='\n' if stop_early or tested_count == len(unique_keys_list) else '\r')

    print() # Newline after progress
    print(f"Test finished. Processed: {tested_count}.")
    test_duration = time.time() - start_test_time
    print(f"Duration: {test_duration:.2f}s.")
    if stop_early: print(f"({futures_cancelled} tests cancelled)")

    # Step 6: Write Results
    print("\n--- Step 6: Writing Results ---")
    num_working = len(all_working_keys)
    print(f"Collected: {num_working} (Target: {TARGET_EARLY_EXIT_KEYS})")
    random.shuffle(all_working_keys)
    print(f"Shuffled {num_working}.")
    keys_to_write = all_working_keys[:TARGET_EARLY_EXIT_KEYS] if num_working > TARGET_EARLY_EXIT_KEYS else all_working_keys
    num_to_write = len(keys_to_write)
    print(f"Writing: {num_to_write}.")
    try:
        with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f:
            for key in keys_to_write:
                f.write(key.replace('\r\n', '\n').replace('\r', '\n') + '\n')
        print(f"Wrote to: {OUTPUT_FILE_PATH}")
        print(f"Abs path: {os.path.abspath(OUTPUT_FILE_PATH)}")
    except IOError as e_w:
        print(f"ERROR writing file {OUTPUT_FILE_PATH}: {e_w}", file=sys.stderr)
        sys.exit(1)

    # Step 7: Final Summary
    print("\n--- Script Summary ---")
    script_end_time = time.time()
    total_time = script_end_time - script_start_time
    print(f"Keys COLLECTED: {num_working}")
    print(f"Keys WRITTEN: {num_to_write}")
    print(f"Output: {os.path.abspath(OUTPUT_FILE_PATH)}")
    print(f"Finished in {total_time:.2f} seconds.")
    print("======================================================")

# --- Entry Point ---
if __name__ == "__main__":
    # Define signal handler function
    def handle_signal(sig, frame):
        """Signal handler for SIGINT and SIGTERM."""
        print(f"\nSignal {sig} received. Exiting...")
        sys.exit(1)

    # Set up signal handlers
    try:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
        print("Signal handlers set up.")
    except Exception as e_signal:
        print(f"Warning: Could not set signals ({e_signal}).")
        pass # Continue execution

    # Run the main function
    main()

