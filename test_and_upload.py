# FILE: test_and_upload.py
# Description: Fetches V2Ray/Xray keys, tests them using xray-knife ping,
#              stops testing early when target working keys are found,
#              and saves working keys.

import requests
import subprocess
import os
import json
import tempfile
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
import traceback # For printing tracebacks on errors
import signal # For graceful shutdown attempt

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

# --- CHANGED: Path for xray-knife ---
XRAY_KNIFE_PATH = "./xray-knife"
print(f"Expected xray-knife path: {XRAY_KNIFE_PATH}")

MAX_WORKERS = 15
print(f"Max worker threads: {MAX_WORKERS}")

REQUEST_TIMEOUT = 20 # Timeout for fetching subscription URLs
print(f"Subscription fetch timeout: {REQUEST_TIMEOUT}s")

# --- CHANGED: Timeout for xray-knife ping command ---
TEST_PING_TIMEOUT = 10 # Timeout value passed to xray-knife --timeout flag
print(f"xray-knife ping --timeout flag: {TEST_PING_TIMEOUT}s")
# Timeout for the subprocess running xray-knife (should be slightly longer)
SUBPROCESS_TIMEOUT = TEST_PING_TIMEOUT + 5
print(f"Subprocess execution timeout: {SUBPROCESS_TIMEOUT}s")

TARGET_EARLY_EXIT_KEYS = 700 # Stop testing when this many working keys are found
print(f"Target working keys to stop testing early: {TARGET_EARLY_EXIT_KEYS}")

SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"]
print(f"Supported protocols: {SUPPORTED_PROTOCOLS}")

# Removed PROXY_PORT and TEST_URLS as they are not needed for xray-knife ping
# REQUEST_HEADERS are still used for fetching subscription URLs
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 KeyTester/2.0'
}
print(f"Subscription Fetch Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

# --- CHANGED: xray-knife Installation ---
def download_and_extract_xray_knife():
    """Downloads and extracts the latest xray-knife binary using GitHub token."""
    print("Checking/Downloading xray-knife...")
    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)
    if os.path.exists(abs_xray_knife_path) and os.access(abs_xray_knife_path, os.X_OK):
         print(f"xray-knife executable already exists at {abs_xray_knife_path} and is executable. Skipping download.")
         return True
    try:
        # --- CHANGED: Repository URL ---
        api_url = "https://api.github.com/repos/lilendian0x00/xray-knife/releases/latest"
        github_token = os.environ.get('GH_TOKEN') # Use GITHUB_TOKEN passed from workflow
        headers = {'Accept': 'application/vnd.github.v3+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if github_token: headers['Authorization'] = f'Bearer {github_token}'; print("Using GH_TOKEN/GITHUB_TOKEN for GitHub API request.")
        else: print("Warning: GH_TOKEN/GITHUB_TOKEN not found. Making unauthenticated API request.")

        print(f"Fetching latest release info from {api_url}"); response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers); response.raise_for_status()
        release_info = response.json(); tag_name = release_info['tag_name']; print(f"Latest xray-knife version tag: {tag_name}")

        system = platform.system().lower(); machine = platform.machine().lower(); print(f"Detected System: {system}, Machine: {machine}")

        # --- CHANGED: Asset name logic for xray-knife ---
        asset_name = None
        if system == 'linux':
            if machine in ['x86_64', 'amd64']: asset_suffix = "linux-amd64.zip"
            elif machine in ['aarch64', 'arm64']: asset_suffix = "linux-arm64.zip"
            else: raise ValueError(f"Unsupported Linux architecture: {machine}")
            # Common naming pattern: xray-knife-linux-amd64.zip
            asset_name = f"xray-knife-{asset_suffix}"
        else: raise ValueError(f"Unsupported operating system: {system}")

        asset_url = None; print(f"Searching for asset: {asset_name}")
        for asset in release_info.get('assets', []):
            if asset.get('name') == asset_name: asset_url = asset.get('browser_download_url'); print(f"Found asset URL: {asset_url}"); break
        if not asset_url: raise ValueError(f"Could not find asset '{asset_name}' in release {tag_name}.")

        print(f"Downloading {asset_url}..."); download_response = requests.get(asset_url, stream=True, timeout=180); download_response.raise_for_status() # Increased download timeout

        print(f"Extracting {asset_name}...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                # --- CHANGED: Executable name ---
                exe_name = 'xray-knife.exe' if system == 'windows' else 'xray-knife'; extracted = False
                for member in zf.namelist():
                     # Handle potential directory structures in zip
                    if member.endswith('/'): continue # Skip directories
                    member_base_name = os.path.basename(member)
                    if member_base_name == exe_name and not member.startswith('__MACOSX'):
                        print(f"  Found executable member: {member}"); zf.extract(member, path="."); extracted_path = os.path.normpath(os.path.join(".", member)); print(f"  Extracted to: {extracted_path}")

                        # Ensure the final path is correct
                        if os.path.abspath(extracted_path) != abs_xray_knife_path:
                             print(f"  Moving/Renaming from {extracted_path} to {abs_xray_knife_path}...");
                             os.makedirs(os.path.dirname(abs_xray_knife_path) or '.', exist_ok=True) # Create dir if needed
                             if os.path.exists(abs_xray_knife_path) or os.path.islink(abs_xray_knife_path): print(f"  Removing existing file/link at {abs_xray_knife_path}"); os.remove(abs_xray_knife_path)
                             os.rename(extracted_path, abs_xray_knife_path)
                        else:
                            print(f"  Extracted directly to target path: {abs_xray_knife_path}")

                        # Clean up empty extracted directory if needed
                        member_dir = os.path.dirname(member)
                        if member_dir and os.path.exists(os.path.join(".", member_dir)) and not os.listdir(os.path.join(".", member_dir)):
                            try: os.rmdir(os.path.join(".", member_dir)); print(f"  Removed empty source directory: {os.path.join('.', member_dir)}")
                            except OSError as rmdir_e: print(f"  Warning: Could not remove source directory {os.path.join('.', member_dir)}: {rmdir_e}")

                        print(f"  xray-knife executable placed at '{abs_xray_knife_path}'"); extracted = True; break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' executable not found in {asset_name}. Contents: {zf.namelist()}")
        else: raise NotImplementedError(f"Extraction not implemented for asset type: {asset_name}")

        if not os.path.exists(abs_xray_knife_path): raise FileNotFoundError(f"xray-knife executable not found at '{abs_xray_knife_path}' after extraction attempt.")

        # Set execute permissions
        if system != 'windows':
            try:
                print(f"Setting execute permissions for '{abs_xray_knife_path}'..."); st_mode = os.stat(abs_xray_knife_path).st_mode; new_mode = st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                if st_mode != new_mode: os.chmod(abs_xray_knife_path, new_mode); print(f"Permissions set to {oct(new_mode)}.")
                else: print("Execute permission already set.")
                if not os.access(abs_xray_knife_path, os.X_OK): raise OSError("Execute permission check failed.")
            except Exception as chmod_e:
                print(f"ERROR: Failed to make '{abs_xray_knife_path}' executable: {chmod_e}", file=sys.stderr)
                try: print("Attempting fallback chmod command..."); subprocess.run(['chmod', '+x', abs_xray_knife_path], check=True); print("Fallback chmod +x succeeded.")
                except Exception as fallback_e: print(f"ERROR: Fallback chmod failed: {fallback_e}.", file=sys.stderr); return False

        # --- CHANGED: Verification command ---
        print(f"Verifying xray-knife installation: {abs_xray_knife_path} -v")
        try:
            version_process = subprocess.run([abs_xray_knife_path, "-v"], capture_output=True, text=True, timeout=15, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY-KNIFE VERSION OUTPUT ---"); print(f"Command: {abs_xray_knife_path} -v"); print(f"Exit Code: {version_process.returncode}"); stdout_strip = version_process.stdout.strip() if version_process.stdout else ""; stderr_strip = version_process.stderr.strip() if version_process.stderr else ""; print(f"Stdout: {stdout_strip}");
            if stderr_strip: print(f"Stderr: {stderr_strip}"); print(f"--- END XRAY-KNIFE VERSION OUTPUT ---")
            if version_process.returncode != 0 or "xray-knife" not in stdout_strip.lower(): print("Warning: xray-knife version command failed or output unexpected.", file=sys.stderr)
            else: print("xray-knife version verified successfully.")
        except subprocess.TimeoutExpired: print(f"ERROR: Timeout running '{abs_xray_knife_path} -v'.", file=sys.stderr); return False
        except FileNotFoundError: print(f"ERROR: Cannot execute '{abs_xray_knife_path}'.", file=sys.stderr); return False
        except Exception as verify_e: print(f"ERROR: xray-knife verification failed: {verify_e}", file=sys.stderr); return False

        print("xray-knife download and setup appears complete."); return True

    except requests.exceptions.RequestException as req_e: print(f"ERROR: xray-knife download network error: {req_e}", file=sys.stderr); return False
    except zipfile.BadZipFile as zip_e: print(f"ERROR: Invalid ZIP file: {zip_e}", file=sys.stderr); return False
    except (ValueError, NotImplementedError, FileNotFoundError, OSError) as setup_e: print(f"ERROR: xray-knife setup failed: {setup_e}", file=sys.stderr); return False
    except Exception as e: print(f"ERROR: Unexpected error in download_and_extract_xray_knife: {e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return False


# --- REMOVED: generate_config function is no longer needed ---


# --- REWRITTEN: Key Testing using xray-knife ping ---
def test_v2ray_key(key_url):
    """Tests a single key using xray-knife ping and returns (key_url, is_working)."""
    key_url = key_url.strip()
    if not key_url or not any(key_url.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
        # print(f"DEBUG: Skipping invalid or unsupported key format: {key_url[:50]}...")
        return key_url, False

    is_working = False
    final_fail_reason = "Unknown Test Failure"
    stdout_data = ""
    stderr_data = ""

    # Pre-check (optional, but can quickly filter dead hosts)
    host = None; port = None
    try:
        parsed = urlparse(key_url); host = parsed.hostname
        # Attempt to guess port if not explicit
        port = parsed.port if parsed.port else {'vmess': 443, 'vless': 443, 'trojan': 443, 'ss': 8388}.get(parsed.scheme, 443)
        if not host: return key_url, False # Cannot test without host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3.0); s.connect((host, port)); s.close()
    except (socket.gaierror): final_fail_reason = "Pre-check DNS Fail"; return key_url, False # Definite fail
    except (socket.timeout, ConnectionRefusedError, OSError): final_fail_reason = "Pre-check Connect Fail"; pass # Might still work, continue
    except Exception as e_pre_other: print(f"Warning: Pre-check error {key_url[:30]}: {e_pre_other}", file=sys.stderr); pass


    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)
    cmd = [
        abs_xray_knife_path,
        "ping",
        "link",
        key_url,
        "--timeout", str(TEST_PING_TIMEOUT) + "s", # Pass timeout to xray-knife
        # "--verbose" # Uncomment for more detailed output from xray-knife if needed for debugging
    ]

    try:
        # print(f"DEBUG: Running command: {' '.join(cmd)}") # Uncomment for command debugging
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT, # Timeout for the entire subprocess run
            check=False, # Don't raise exception on non-zero exit code, we check manually
            encoding='utf-8',
            errors='replace'
        )
        stdout_data = process.stdout.strip() if process.stdout else ""
        stderr_data = process.stderr.strip() if process.stderr else ""

        # --- Check for Success ---
        # Condition 1: Exit code must be 0
        # Condition 2: Standard output should indicate success (contains RTT or Success)
        if process.returncode == 0 and (re.search(r'(Success|RTT: \d+ms)', stdout_data, re.IGNORECASE)):
            is_working = True
            final_fail_reason = "" # Clear fail reason on success
        else:
            # Determine failure reason
            if process.returncode != 0:
                final_fail_reason = f"Exit Code {process.returncode}"
            elif "timeout" in stdout_data.lower() or "timeout" in stderr_data.lower():
                 final_fail_reason = "Ping Timeout"
            elif stderr_data:
                 # Use first line of stderr if available and not empty
                 final_fail_reason = f"Error: {stderr_data.splitlines()[0]}"[:100] # Limit length
            elif stdout_data:
                 # Use first line of stdout if it looks like an error
                 final_fail_reason = f"Output: {stdout_data.splitlines()[0]}"[:100]
            else:
                final_fail_reason = "Non-zero Exit or No Success Output"

        return key_url, is_working

    except subprocess.TimeoutExpired:
        final_fail_reason = f"Subprocess Timeout ({SUBPROCESS_TIMEOUT}s)"
        print(f"ERROR: {final_fail_reason} Key: {key_url[:50]}...", file=sys.stderr)
        return key_url, False
    except FileNotFoundError:
        final_fail_reason = f"xray-knife execution failed (Not Found at {abs_xray_knife_path})"
        print(f"ERROR: {final_fail_reason}", file=sys.stderr)
        # Consider exiting script if xray-knife is missing globally? For now, just fail the key.
        return key_url, False
    except Exception as e_test:
        final_fail_reason = f"Unexpected ping error: {e_test}"
        print(f"ERROR: {final_fail_reason} Key: {key_url[:50]}...", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return key_url, False
    finally:
        # Print failure details only if it failed
        if not is_working:
             print(f"DEBUG: Test FAIL Key: {key_url[:50]}... Reason: {final_fail_reason}", file=sys.stderr)
             # Optionally print non-empty stdout/stderr on failure for more context
             # if stdout_data: print(f"DEBUG: Stdout: {stdout_data[:200]}...", file=sys.stderr)
             # if stderr_data: print(f"DEBUG: Stderr: {stderr_data[:200]}...", file=sys.stderr)
        # No process to kill like before, subprocess.run handles it.


# --- Main Execution Logic ---
def main():
    script_start_time = time.time()
    print(f"\n=== Starting Key Tester Script (using xray-knife) at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

    # --- Step 1: Setup xray-knife ---
    print("\n--- Step 1: Setting up xray-knife ---")
    # --- CHANGED: Call the correct download function ---
    if not download_and_extract_xray_knife(): print("FATAL: Failed to setup xray-knife.", file=sys.stderr); sys.exit(1)
    abs_xray_knife_path = os.path.abspath(XRAY_KNIFE_PATH)
    if not os.path.exists(abs_xray_knife_path) or not os.access(abs_xray_knife_path, os.X_OK): print(f"FATAL: xray-knife not ready at {abs_xray_knife_path}.", file=sys.stderr); sys.exit(1)
    print(f"Confirmed xray-knife executable: {abs_xray_knife_path}")

    # --- Step 2: Prepare Output Directory ---
    print(f"\n--- Step 2: Preparing Output Directory ({OUTPUT_DIR}) ---")
    try: os.makedirs(OUTPUT_DIR, exist_ok=True); print(f"Output directory '{OUTPUT_DIR}' ensured.")
    except OSError as e: print(f"FATAL: Could not create output directory {OUTPUT_DIR}: {e}", file=sys.stderr); sys.exit(1)

    # --- Step 3: Fetch Keys ---
    print("\n--- Step 3: Fetching Keys ---")
    all_fetched_keys_raw = []; fetch_errors = 0; total_lines_fetched = 0
    for index, url in enumerate(SOURCE_URLS_LIST):
        print(f"\nFetching from URL {index+1}/{len(SOURCE_URLS_LIST)}: {url[:100]}...")
        try:
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=REQUEST_HEADERS, allow_redirects=True); response.raise_for_status(); raw_data = None
            try: raw_data = response.content.decode('utf-8');
            except UnicodeDecodeError:
                 try: encoding = response.encoding if response.encoding else response.apparent_encoding; raw_data = response.content.decode(encoding if encoding else 'iso-8859-1', errors='replace'); print(f"  Decoded as {encoding if encoding else 'iso-8859-1'}.")
                 except Exception: raw_data = response.content.decode('iso-8859-1', errors='replace'); print(f"  Warning: Fallback decode iso-8859-1.")

            lines = raw_data.splitlines(); count_for_source = 0
            for line in lines:
                line = line.strip()
                if line:
                    all_fetched_keys_raw.append(line)
                    count_for_source += 1
            total_lines_fetched += count_for_source; print(f" -> Fetched {count_for_source} non-empty lines.")
        except requests.exceptions.Timeout: print(f"ERROR: Timeout fetching {url[:100]}", file=sys.stderr); fetch_errors += 1
        except requests.exceptions.RequestException as e: print(f"ERROR: Failed fetching {url[:100]}: {e}", file=sys.stderr); fetch_errors += 1
        except Exception as e: print(f"ERROR: Processing {url[:100]}: {e}", file=sys.stderr); fetch_errors += 1; traceback.print_exc(file=sys.stderr)

    print(f"\nFinished fetching. Total lines: {total_lines_fetched}. Errors: {fetch_errors}.")
    if not all_fetched_keys_raw: print("Error: No lines fetched. Writing empty output.", file=sys.stderr); try: open(OUTPUT_FILE_PATH, 'w').close(); print(f"Created empty: {OUTPUT_FILE_PATH}") ; except IOError as e_f: print(f"Warning: Cannot create empty file: {e_f}", file=sys.stderr); sys.exit(0 if fetch_errors < len(SOURCE_URLS_LIST) else 1)

    # --- Step 4: Process Keys ---
    print("\n--- Step 4: Processing/Deduplicating Keys ---")
    unique_keys_to_test = set(); processed_count = 0; decode_attempts = 0; base64_decoded_keys = 0; unsupported_skips = 0
    for line in all_fetched_keys_raw:
         if any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
              if line not in unique_keys_to_test: unique_keys_to_test.add(line); processed_count += 1
         else:
             decode_attempts += 1
             try:
                 # Try decoding base64, handle potential padding errors
                 line_padded = line + '=' * (-len(line) % 4)
                 decoded = base64.b64decode(line_padded).decode('utf-8', errors='replace')
                 # Find potential keys within the decoded string
                 found_keys_in_line = re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>\`\\]+', decoded) # Added backslash exclude
                 if found_keys_in_line:
                      for key in found_keys_in_line:
                          key = key.strip()
                          if any(key.startswith(proto) for proto in SUPPORTED_PROTOCOLS): # Extra check
                              if key not in unique_keys_to_test:
                                  unique_keys_to_test.add(key)
                                  processed_count += 1
                                  base64_decoded_keys += 1
                          else: unsupported_skips +=1 # Found something, but not supported proto
                 # else: unsupported_skips += 1 # Decoded, but no keys found pattern
             except (base64.binascii.Error, UnicodeDecodeError): unsupported_skips += 1 # Not valid base64 or cannot decode
             except Exception: unsupported_skips += 1 # Other unexpected errors during decode/regex

    unique_keys_list = list(unique_keys_to_test)
    print(f"Processed {len(all_fetched_keys_raw)} lines. Found {len(unique_keys_list)} unique potential keys matching {SUPPORTED_PROTOCOLS}.")
    print(f"(Base64 attempts: {decode_attempts}, Keys found in Base64: {base64_decoded_keys}, Skipped/Invalid lines: {unsupported_skips})")


    # --- Step 5: Test Keys with Early Exit ---
    print("\n--- Step 5: Testing Keys ---")
    if not unique_keys_list: print("No unique valid keys found to test. Writing empty file."); try: open(OUTPUT_FILE_PATH, 'w').close(); print(f"Created empty: {OUTPUT_FILE_PATH}"); except IOError as e_f: print(f"Warning: Cannot create empty file: {e_f}", file=sys.stderr); sys.exit(0)
    print(f"Starting tests for {len(unique_keys_list)} keys (will stop early at {TARGET_EARLY_EXIT_KEYS} working)..."); print(f"(Max Workers: {MAX_WORKERS}, Ping Timeout: {TEST_PING_TIMEOUT}s)")
    all_working_keys = []; tested_count = 0; start_test_time = time.time(); futures_cancelled = 0; stop_early = False
    random.shuffle(unique_keys_list) # Shuffle keys before testing

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all test jobs
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_list}
        active_futures = list(future_to_key.keys()) # Keep track for potential cancellation

        for future in as_completed(active_futures):
            if stop_early: # If early stop triggered, cancel pending futures
                if not future.done(): future.cancel()
                continue # Skip processing results for already completed/cancelled futures

            key_original = future_to_key[future]; tested_count += 1 # Increment tested count here

            try:
                if future.cancelled():
                    # print(f"DEBUG: Test cancelled for key {key_original[:40]}...") # Optional debug msg
                    continue # Skip processing cancelled future

                _key_returned, is_working = future.result() # Get result (can raise exception)

                if is_working:
                    all_working_keys.append(key_original); found_count = len(all_working_keys)
                    # Check for early exit condition
                    if not stop_early and found_count >= TARGET_EARLY_EXIT_KEYS:
                        stop_early = True; print(f"\nTarget of {TARGET_EARLY_EXIT_KEYS} working keys reached! Stopping testing early."); print("Attempting to cancel remaining pending tests...")
                        cancelled_now = 0
                        # Iterate through all original futures to cancel pending ones
                        for f_key, f_obj in future_to_key.items():
                            if not f_obj.done():
                                if f_obj.cancel(): cancelled_now += 1
                        futures_cancelled = cancelled_now; print(f"Attempted to cancel {futures_cancelled} tests.")
                        # Break from the as_completed loop after triggering stop
                        # break # Removed break here to allow already running tasks to finish and log progress correctly

            except Exception as e_future:
                print(f"\nWarning: Error processing test result for key {key_original[:40]}...: {e_future}", file=sys.stderr)
                # traceback.print_exc(file=sys.stderr) # Uncomment for full traceback

            # Update progress indicator
            if tested_count % 50 == 0 or tested_count == len(unique_keys_list) or (stop_early and tested_count > 0): # Ensure progress prints on stop_early
                 current_time = time.time(); elapsed = current_time - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
                 progress_message = f"Progress: Tested {tested_count}/{len(unique_keys_list)} | Found: {len(all_working_keys)} | Rate: {rate:.1f} keys/s | Elapsed: {elapsed:.0f}s"
                 if stop_early: progress_message += " (Stopping Early)"
                 # Use newline only at the end or when stopping early
                 print(progress_message, end='\n' if stop_early or tested_count == len(unique_keys_list) else '\r')

    print() # Ensure final newline after progress indicator
    print(f"Finished testing phase. Tested {tested_count} keys."); test_duration = time.time() - start_test_time; print(f"Total testing time: {test_duration:.2f} seconds.")
    if stop_early: print(f"({futures_cancelled} tests potentially cancelled after reaching target)")

    # --- Step 6: Write Results ---
    print("\n--- Step 6: Writing Results ---")
    num_working_found = len(all_working_keys); print(f"Total working keys collected: {num_working_found} (Target was {TARGET_EARLY_EXIT_KEYS})")
    random.shuffle(all_working_keys); print(f"Shuffled {num_working_found} working keys.")
    if num_working_found > TARGET_EARLY_EXIT_KEYS: print(f"Limiting final output to {TARGET_EARLY_EXIT_KEYS} keys."); keys_to_write = all_working_keys[:TARGET_EARLY_EXIT_KEYS]
    else: keys_to_write = all_working_keys
    num_keys_to_write = len(keys_to_write); print(f"Number of keys to write to file: {num_keys_to_write}")
    try:
        with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f:
            # Ensure consistent newline endings just in case
            for key_to_write in keys_to_write: f.write(key_to_write.replace('\r\n', '\n').replace('\r', '\n') + '\n')
        print(f"Successfully wrote {num_keys_to_write} keys to {OUTPUT_FILE_PATH}")
    except IOError as e_w: print(f"ERROR writing output file {OUTPUT_FILE_PATH}: {e_w}", file=sys.stderr); sys.exit(1)

    # --- Final Summary ---
    print("\n--- Script Summary ---")
    script_end_time = time.time(); total_script_time = script_end_time - script_start_time
    print(f"Total working keys COLLECTED: {num_working_found}"); print(f"Total working keys WRITTEN (limit: {TARGET_EARLY_EXIT_KEYS}): {num_keys_to_write}"); print(f"Output file: {os.path.abspath(OUTPUT_FILE_PATH)}")
    print(f"Script finished in {total_script_time:.2f} seconds."); print("======================================================")

# --- Entry Point ---
if __name__ == "__main__":
    # Add signal handling for graceful termination if needed
    def handle_signal(sig, frame):
        print(f"\nSignal {sig} received. Exiting gracefully...")
        # Future cancellations are handled within the main loop now
        sys.exit(1)
    try:
        signal.signal(signal.SIGINT, handle_signal) # Handle Ctrl+C
        signal.signal(signal.SIGTERM, handle_signal) # Handle termination signal
    except (AttributeError, ValueError, OSError) as e_signal:
        # Catch errors if signal module is not available or setting fails
        print(f"Warning: Could not set signal handlers ({e_signal}).")
        pass

    main()
