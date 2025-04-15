import requests
import subprocess
import os
import time
import random
import base64
import platform
import zipfile
import io
import stat
import tempfile
import json
from urllib.parse import urlparse, parse_qs, unquote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Configuration ---
OUTPUT_DIR = "." # Changed from OUTPUT_FILE to a directory for multiple output files
XRAY_PATH = "./xray"
REQUEST_TIMEOUT = 15
TEST_TIMEOUT = 20
MAX_WORKERS = 50 # Increased for faster testing, adjust as needed

# --- Xray Installation ---
def download_and_extract_xray():
    """Downloads and extracts the latest Xray core binary using GitHub token."""
    print("Checking/Downloading Xray...")
    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        github_token = os.environ.get('GH_TOKEN')
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if github_token:
            headers['Authorization'] = f'token {github_token}'
        else:
            print("Warning: GitHub token (GH_TOKEN) not found in environment. Making unauthenticated API request (may hit rate limits).")

        response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status()
        release_info = response.json()
        tag_name = release_info['tag_name']
        print(f"Latest Xray version tag: {tag_name}")

        system = platform.system().lower(); machine = platform.machine().lower()
        asset_name = "Xray-linux-64.zip"
        if system == 'linux' and machine == 'aarch64': asset_name = "Xray-linux-arm64-v8a.zip"
        asset_url = None
        for asset in release_info['assets']:
            if asset['name'] == asset_name: asset_url = asset['browser_download_url']; break
        if not asset_url: raise ValueError(f"Could not find asset '{asset_name}' for {system} {machine}")
        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=90); download_response.raise_for_status()

        print("Extracting Xray...")
        extracted = False
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray.exe' if system == 'windows' else 'xray'
                for member in zf.namelist():
                    if member.endswith(exe_name) and not member.startswith('__MACOSX'):
                        extracted_path = os.path.join(".", member)
                        if os.path.exists(XRAY_PATH): os.remove(XRAY_PATH)
                        zf.extract(member, path=".")
                        print(f"Extracted file path: {extracted_path}")
                        target_name = "xray"
                        if extracted_path != target_name:
                            print(f"Renaming extracted file from {extracted_path} to {target_name}")
                            os.rename(extracted_path, target_name)
                            extracted = True
                        else:
                            extracted = True
                        break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' not found within the zip file {asset_name}.")
        else: raise NotImplementedError(f"Extraction not implemented for {asset_name}")

        if extracted:
            if not os.path.exists(XRAY_PATH): raise FileNotFoundError(f"Xray executable not found at '{XRAY_PATH}' after extraction.")
            if system != 'windows':
                try: st = os.stat(XRAY_PATH); os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC); print(f"Made '{XRAY_PATH}' executable.")
                except Exception as chmod_e: print(f"ERROR: Failed to make '{XRAY_PATH}' executable: {chmod_e}"); return False

            print(f"Attempting to verify {XRAY_PATH}...")
            try:
                version_cmd = [XRAY_PATH, "version"]
                version_process = subprocess.run(version_cmd, capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
                print(f"--- XRAY VERSION ---"); print(f"Exit Code: {version_process.returncode}"); print(f"Stdout: {version_process.stdout.strip()}"); print(f"Stderr: {version_process.stderr.strip()}"); print(f"--- END XRAY VERSION ---")
                if version_process.returncode != 0: print("Warning: Xray version command failed!")
                help_cmd = [XRAY_PATH, "help"]
                help_process = subprocess.run(help_cmd, capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
                print(f"--- XRAY HELP (searching for 'test' command) ---"); help_output = help_process.stdout + help_process.stderr
                if ' test ' in help_output: print("  'test' command seems to be available in help output.")
                else: print("  Warning: 'test' command NOT found explicitly in help output. Relying on 'run -test'.")
                print(f"--- END XRAY HELP ---")
            except Exception as verify_e: print(f"ERROR: Could not run Xray for verification: {verify_e}"); return False
            print("Xray download and extraction complete.")
            return True # Success
        else:
            print("Error: Xray executable not found in the downloaded zip file.")
            return False

    except requests.exceptions.RequestException as req_e: print(f"ERROR: Failed GitHub API request: {req_e}"); return False
    except Exception as e: print(f"Error in download_and_extract_xray function: {e}"); return False

# --- Config Generation (generate_config) ---
def generate_config(key_url):
    """Generates a minimal Xray JSON config for testing various key types."""
    try:
        key_url = key_url.strip()
        if not key_url or '://' not in key_url: return None
        parsed_url = urlparse(key_url); protocol = parsed_url.scheme; config = None
        base_config = {"log": {"loglevel": "warning"},"inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": False}}],"outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]}; outbound = base_config["outbounds"][0]
        if protocol == "vmess":
            try:
                try: vmess_b64 = key_url[8:]; vmess_b64 += '=' * (-len(vmess_b64) % 4); vmess_json_str = base64.b64decode(vmess_b64).decode('utf-8', errors='replace'); vmess_params = json.loads(vmess_json_str)
                except Exception as e: print(f"DEBUG: Error decoding vmess: {e} for {key_url[:50]}"); return None
                outbound["settings"]["vnext"] = [{"address": vmess_params.get("add", ""), "port": int(vmess_params.get("port", 443)), "users": [{"id": vmess_params.get("id", ""), "alterId": int(vmess_params.get("aid", 0)), "security": vmess_params.get("scy", "auto")}]}]; stream_settings = {"network": vmess_params.get("net", "tcp"), "security": vmess_params.get("tls", "none")}
                if stream_settings["security"] == "tls": sni = vmess_params.get("sni", vmess_params.get("host", "")); sni = sni if sni else vmess_params.get("add", ""); stream_settings["tlsSettings"] = {"serverName": sni, "allowInsecure": False}
                net_type = stream_settings["network"]; host = vmess_params.get("host", vmess_params.get("add", "")); path = vmess_params.get("path", "/")
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "tcp" and vmess_params.get("type") == "http": host_list = [h.strip() for h in host.split(',') if h.strip()] or [vmess_params.get("add", "")]; stream_settings["tcpSettings"] = {"header": {"type": "http", "request": {"path": [path], "headers": {"Host": host_list}}}}
                outbound["streamSettings"] = stream_settings; config = base_config
            except Exception as e: print(f"DEBUG: Error generating vmess config: {e} for {key_url[:50]}"); return None
        elif protocol == "vless":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None; uuid = parsed_url.username; address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                outbound["settings"]["vnext"] = [{"address": address, "port": port, "users": [{"id": uuid, "flow": params.get('flow', [None])[0] or ""}]}]; stream_settings = {"network": params.get('type', ['tcp'])[0], "security": params.get('security', ['none'])[0]}; sec_type = stream_settings["security"]; sni = params.get('sni', [params.get('peer', [address])[0]])[0]; fingerprint = params.get('fp', [''])[0]
                if sec_type == "tls": stream_settings["tlsSettings"] = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1'}
                elif sec_type == "reality": pbk = params.get('pbk', [''])[0]; sid = params.get('sid', [''])[0]; spx = params.get('spx', ['/'])[0]; stream_settings["realitySettings"] = {"serverName": sni, "fingerprint": fingerprint, "shortId": sid, "publicKey": pbk, "spiderX": spx}
                net_type = stream_settings["network"]; host = params.get('host', [address])[0]; path = unquote_plus(params.get('path', ['/'])[0]); service_name = unquote_plus(params.get('serviceName', [''])[0])
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc": stream_settings["grpcSettings"] = {"serviceName": service_name}
                outbound["streamSettings"] = stream_settings; config = base_config
            except Exception as e: print(f"DEBUG: Error generating vless config: {e} for {key_url[:50]}"); return None
        elif protocol == "trojan":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None; password = unquote_plus(parsed_url.username); address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                outbound["settings"]["servers"] = [{"address": address, "port": port, "password": password}]; stream_settings = {"network": params.get('type', ['tcp'])[0], "security": params.get('security', ['tls'])[0]}; sni = params.get('sni', [params.get('peer', [address])[0]])[0]; fingerprint = params.get('fp', [''])[0]
                if stream_settings["security"] == "tls": stream_settings["tlsSettings"] = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": params.get('allowInsecure', ['0'])[0] == '1'}
                net_type = stream_settings["network"]; host = params.get('host', [address])[0]; path = unquote_plus(params.get('path', ['/'])[0]); service_name = unquote_plus(params.get('serviceName', [''])[0])
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc": stream_settings["grpcSettings"] = {"serviceName": service_name}
                outbound["streamSettings"] = stream_settings; config = base_config
            except Exception as e: print(f"DEBUG: Error generating trojan config: {e} for {key_url[:50]}"); return None
        elif protocol == "ss":
             try:
                 if '@' not in parsed_url.netloc: return None; user_info_part = parsed_url.netloc.split('@')[0]; server_part = parsed_url.netloc.split('@')[1]; address = server_part.split(':')[0]; port = int(server_part.split(':')[1]); decoded_user_info = None
                 try: user_info_b64 = user_info_part; user_info_b64 += '=' * (-len(user_info_b64) % 4); decoded_user_info = base64.b64decode(user_info_b64).decode('utf-8', errors='replace')
                 except Exception as e: print(f"DEBUG: Error decoding ss user info: {e} for {key_url[:50]}"); return None
                 if ':' not in decoded_user_info: return None; method, password = decoded_user_info.split(':', 1)
                 outbound["settings"]["servers"] = [{"address": address, "port": port, "method": method, "password": password}]; outbound["streamSettings"]["network"] = "tcp"
                 if "security" in outbound["streamSettings"]: del outbound["streamSettings"]["security"]
                 config = base_config
             except Exception as e: print(f"DEBUG: Error generating ss config: {e} for {key_url[:50]}"); return None
        else: return None
        if "streamSettings" in outbound and not outbound["streamSettings"]: del outbound["streamSettings"]
        elif "streamSettings" in outbound:
             if "tlsSettings" in outbound["streamSettings"] and not outbound["streamSettings"]["tlsSettings"]: del outbound["streamSettings"]["tlsSettings"]
             if "wsSettings" in outbound["streamSettings"] and not outbound["streamSettings"]["wsSettings"]: del outbound["streamSettings"]["wsSettings"]
        return json.dumps(config, indent=2) if config else None
    except Exception as e: print(f"DEBUG: Outer error in generate_config: {e} for {key_url[:50]}"); return None


# --- Key Testing (test_v2ray_key) ---
def test_v2ray_key(key_url):
    """Tests a single V2Ray key using xray run -test and logs failures."""
    config_json = generate_config(key_url)
    if not config_json: return key_url, False
    temp_config_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tf: tf.write(config_json); temp_config_file = tf.name
        command = [XRAY_PATH, "run", "-test", "-config", temp_config_file]
        is_working = False; process_stderr = "Unknown test error"; process_returncode = -1
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=TEST_TIMEOUT, check=False, encoding='utf-8', errors='replace')
            process_stderr = process.stderr.strip(); process_returncode = process.returncode; is_working = process.returncode == 0
            if is_working and process_stderr: failure_keywords = ["failed to dial", "proxy connection failed", "timeout", "authentication failed"]; is_working = not any(keyword in process_stderr.lower() for keyword in failure_keywords)
        except subprocess.TimeoutExpired: process_stderr = f"Timeout ({TEST_TIMEOUT}s)"; print(f"DEBUG: [FAIL] {process_stderr} for key: {key_url[:70]}..."); is_working = False
        except Exception as e: process_stderr = f"Subprocess execution error: {e}"; print(f"DEBUG: [FAIL] {process_stderr} testing key {key_url[:70]}..."); is_working = False
        if not is_working:
            print(f"DEBUG: [FAIL] Key: {key_url[:70]}...")
            if "Timeout" not in process_stderr and "Subprocess execution error" not in process_stderr: print(f"DEBUG:   Final Exit Code: {process_returncode}"); print(f"DEBUG:   Final Stderr: {process_stderr}") if process_stderr and "config file not readable" not in process_stderr.lower() else None
        # else: print(f"DEBUG: [OK] Key: {key_url[:70]}...")
        return key_url, is_working
    except Exception as e: print(f"DEBUG: [FAIL] Outer Error in test_v2ray_key for {key_url[:70]}...: {e}"); return key_url, False
    finally:
        if temp_config_file and os.path.exists(temp_config_file):
            try: os.remove(temp_config_file)
            except Exception as e_rem: print(f"Warning: Failed to remove temp config file {temp_config_file}: {e_rem}")


# --- Main Execution (main) ---
def main():
    start_time = time.time(); print("Starting V2Ray Key Testing Script...")
    if not download_and_extract_xray(): print("FATAL: Failed to get/verify Xray binary. Aborting."); return
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK): print(f"FATAL: Xray executable not found or not executable at {XRAY_PATH}. Aborting."); return
    print(f"Using Xray executable at: {os.path.abspath(XRAY_PATH)}")

    # Ensure output directory exists
    if not os.path.exists(OUTPUT_DIR): print(f"Creating output directory: {OUTPUT_DIR}"); os.makedirs(OUTPUT_DIR, exist_ok=True)
    else: print(f"Output directory already exists: {OUTPUT_DIR}")

    source_urls_secret = os.environ.get("SOURCE_URLS_SECRET")
    if not source_urls_secret:
        print("ERROR: SOURCE_URLS_SECRET environment variable not found.")
        return

    SOURCE_URLS = {}
    for i, url in enumerate(source_urls_secret.strip().split('\n')):
        SOURCE_URLS[f"url_{i+1}"] = url.strip()

    all_keys_to_test = []; source_map = {}
    print("\n--- Fetching Keys ---")
    for command, url in SOURCE_URLS.items():
        keys_from_source = []
        try:
            print(f"Fetching {command} from {url}...")
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers={'User-Agent': 'Mozilla/5.0 V2RayKeyTester/1.0'})
            response.raise_for_status()
            try: raw_data = response.content.decode(response.encoding or 'utf-8', errors='replace')
            except Exception: raw_data = response.text
            processed_data = raw_data
            if command in ["tw"]: # tw အတွက် Base64 ကို သီးခြားစီမံမယ်
                decoded_keys = []
                for line in processed_data.splitlines():
                    line = line.strip()
                    if line.startswith("vmess://"):
                        try:
                            vmess_b64 = line[8:]
                            vmess_b64 += '=' * (-len(vmess_b64) % 4)
                            base64.b64decode(vmess_b64).decode('utf-8', errors='replace')
                            decoded_keys.append(line)
                        except Exception:
                            print(f"  DEBUG: Failed to decode Base64 for vmess key: {line[:50]}...")
                    elif line and any(line.startswith(p) for p in ["vless://", "trojan://", "ss://"]):
                        decoded_keys.append(line)
                keys_from_source = decoded_keys
                print(f"  Processed {len(keys_from_source)} keys for {command}.")

            else:
                print(f"  Content for {command} treated as plain text.")
                keys_from_source = [line.strip() for line in processed_data.splitlines() if line.strip() and any(line.strip().startswith(p) for p in ["vmess://", "vless://", "trojan://", "ss://"])]
                print(f"  Found {len(keys_from_source)} potential keys for {command} after final processing.")

            if keys_from_source:
                for key in keys_from_source:
                    if key not in source_map: all_keys_to_test.append(key); source_map[key] = command
        except requests.exceptions.RequestException as e: print(f"ERROR: Failed to fetch keys for {command} from {url}: {e}")
        except Exception as e: print(f"ERROR: Failed to process source {command} from {url}: {e}")

    unique_keys_to_test = list(dict.fromkeys(all_keys_to_test))
    print(f"\nTotal unique potential keys to test: {len(unique_keys_to_test)}")
    if not unique_keys_to_test:
         print("No unique keys found or extracted, nothing to test.");
         for command in SOURCE_URLS.keys():
             output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
             try:
                 with open(output_filename, 'w', encoding='utf-8', newline='\n') as f: pass # Write empty file with correct format
                 print(f"  Created empty file: {output_filename}")
             except Exception as e_f: print(f"Warning: Could not create empty file {output_filename}: {e_f}")
         print("Finished creating empty output files (if possible)."); return

    working_keys_by_command = {cmd: [] for cmd in SOURCE_URLS.keys()}
    tested_count = 0; start_test_time = time.time()
    print(f"\n--- Starting Tests (Workers: {MAX_WORKERS}, Timeout: {TEST_TIMEOUT}s) ---")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_to_test}
        for future in as_completed(future_to_key):
            key = future_to_key[future]; command_source = source_map.get(key); tested_count += 1
            try:
                _key_url_ignored, is_working = future.result()
                if is_working and command_source: working_keys_by_command[command_source].append(key)
            except Exception as e_res: print(f"Warning: Error getting result for key {key[:40]}...: {e_res}"); pass
            if tested_count % 100 == 0 or tested_count == len(unique_keys_to_test):
                elapsed = time.time() - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
                print(f"Progress: Tested {tested_count}/{len(unique_keys_to_test)} keys... ({elapsed:.1f}s, {rate:.1f} keys/s)")

    print("\n--- Test Results Summary ---"); total_working = 0; processed_commands = set()
    for command, keys in working_keys_by_command.items():
        source_yielded_keys = any(source_map.get(k) == command for k in unique_keys_to_test)
        if keys or source_yielded_keys:
            num_keys_found = len(keys) # Total working keys found for this command
            print(f"  {command}: {num_keys_found} working keys found.")
            total_working += num_keys_found
            output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
            processed_commands.add(command)
            try:
                keys.sort();
                with open(output_filename, 'w', encoding='utf-8', newline='\n') as f:
                    for key in keys:
                        f.write(key + '\n')
            except Exception as e_w: print(f"    ERROR writing file {output_filename}: {e_w}")

    print("\n--- Ensuring output files exist for all sources ---")
    for command in SOURCE_URLS.keys():
         if command not in processed_commands:
              output_filename = os.path.join(OUTPUT_DIR, f"working_{command.lstrip('/')}.txt")
              try:
                  with open(output_filename, 'w', encoding='utf-8', newline='\n') as f: pass
                  print(f"  {command}: 0 working keys processed (created/ensured empty file: {output_filename}).")
              except Exception as e_f: print(f"Warning: Could not create empty file {output_filename}: {e_f}")

    end_time = time.time()
    print(f"\nTotal working keys found and saved: {total_working}")
    print(f"Script finished in {end_time - start_time:.2f} seconds.")
    print("----------------------------------------")

if __name__ == "__main__":
    main()
