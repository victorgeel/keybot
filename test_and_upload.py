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
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import random # To shuffle keys later

# --- Configuration ---
# SOURCE_URLS_SECRET မှ URL list ကို ဖတ်မည်
SOURCE_URLS_RAW = os.environ.get('SOURCE_URLS_SECRET', '')
SOURCE_URLS_LIST = [url.strip() for url in SOURCE_URLS_RAW.splitlines() if url.strip()]

if not SOURCE_URLS_LIST:
    print("ERROR: SOURCE_URLS_SECRET is empty or not set.", file=sys.stderr)
    print("Please provide a list of URLs (one per line) in the secret.", file=sys.stderr)
    sys.exit(1)
else:
    print(f"Loaded {len(SOURCE_URLS_LIST)} URLs from SOURCE_URLS_SECRET.")

# Output directory
OUTPUT_DIR = "subscription"
# Single output filename
OUTPUT_FILENAME = "working_keys.txt"
OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)

XRAY_PATH = "./xray"
MAX_WORKERS = 15
REQUEST_TIMEOUT = 20
TEST_TIMEOUT = 25

# စုစုပေါင်း output file ထဲတွင် ထားရှိမည့် အများဆုံး Key အရေအတွက်
MAX_TOTAL_KEYS = 1500 # Bot အတွက် pool များများရှိအောင်ထားနိုင်သည် (adjust as needed)

# Supported protocols prefix list
SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"]

# --- Xray Installation ---
def download_and_extract_xray():
    """Downloads and extracts the latest Xray core binary using GitHub token."""
    print("Checking/Downloading Xray...")
    if os.path.exists(XRAY_PATH) and os.access(XRAY_PATH, os.X_OK):
         print(f"Xray executable already exists at {os.path.abspath(XRAY_PATH)} and is executable. Skipping download.")
         return True

    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        github_token = os.environ.get('GH_TOKEN') # Provided by Actions typically
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if github_token:
            headers['Authorization'] = f'token {github_token}'
        else:
            print("Warning: GitHub token (GH_TOKEN) not found. Making unauthenticated API request (may hit rate limits).")

        print(f"Fetching latest release info from {api_url}")
        response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        release_info = response.json()
        tag_name = release_info['tag_name']
        print(f"Latest Xray version tag: {tag_name}")

        system = platform.system().lower()
        machine = platform.machine().lower()

        # Determine asset name based on OS and architecture
        if system == 'linux':
            if machine in ['x86_64', 'amd64']: asset_name = "Xray-linux-64.zip"
            elif machine == 'aarch64': asset_name = "Xray-linux-arm64-v8a.zip"
            else: raise ValueError(f"Unsupported Linux architecture: {machine}")
        else:
            raise ValueError(f"Unsupported operating system: {system}")

        asset_url = None
        print(f"Searching for asset: {asset_name}")
        for asset in release_info['assets']:
            if asset['name'] == asset_name:
                asset_url = asset['browser_download_url']
                print(f"Found asset URL: {asset_url}")
                break

        if not asset_url:
            raise ValueError(f"Could not find asset '{asset_name}' for {system} {machine} in release {tag_name}")

        print(f"Downloading {asset_url}...")
        download_response = requests.get(asset_url, stream=True, timeout=120)
        download_response.raise_for_status()

        print("Extracting Xray...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray' # Linux/macOS default
                extracted = False
                for member in zf.namelist():
                    if member.endswith(exe_name) and not member.startswith('__MACOSX') and not member.endswith('/'):
                        print(f"  Found executable member: {member}")
                        if os.path.exists(XRAY_PATH):
                            print(f"  Removing existing file at {XRAY_PATH}")
                            os.remove(XRAY_PATH)
                        zf.extract(member, path=".")
                        extracted_path = os.path.join(".", member)
                        target_path = XRAY_PATH
                        print(f"  Extracted to: {extracted_path}")
                        if extracted_path != target_path:
                             print(f"  Moving/Renaming extracted file from {extracted_path} to {target_path}")
                             os.rename(extracted_path, target_path)
                             member_dir = os.path.dirname(member)
                             if member_dir and os.path.exists(os.path.join(".", member_dir)):
                                 try:
                                     os.rmdir(os.path.join(".", member_dir))
                                     print(f"  Removed empty source directory: {os.path.join('.', member_dir)}")
                                 except OSError:
                                     print(f"  Could not remove source directory (might not be empty): {os.path.join('.', member_dir)}")
                                     pass
                        print(f"  Extracted '{member}' successfully to '{target_path}'")
                        extracted = True
                        break
                if not extracted:
                    raise FileNotFoundError(f"'{exe_name}' not found within the zip file {asset_name}.")
        else:
            raise NotImplementedError(f"Extraction not implemented for asset type: {asset_name}")

        if not os.path.exists(XRAY_PATH):
            raise FileNotFoundError(f"Xray executable not found at '{XRAY_PATH}' after extraction attempt.")

        if system != 'windows':
            try:
                print(f"Making '{XRAY_PATH}' executable...")
                st = os.stat(XRAY_PATH)
                os.chmod(XRAY_PATH, st.st_mode | stat.S_IEXEC)
                print(f"'{XRAY_PATH}' is now executable.")
            except Exception as chmod_e:
                print(f"ERROR: Failed to make '{XRAY_PATH}' executable: {chmod_e}", file=sys.stderr)
                return False

        print(f"Attempting to verify Xray installation by running: {XRAY_PATH} version")
        try:
            version_process = subprocess.run([XRAY_PATH, "version"], capture_output=True, text=True, timeout=10, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY VERSION ---")
            print(f"Exit Code: {version_process.returncode}")
            print(f"Stdout: {version_process.stdout.strip()}")
            stderr_output = version_process.stderr.strip()
            if stderr_output: print(f"Stderr: {stderr_output}")
            print(f"--- END XRAY VERSION ---")
            if version_process.returncode != 0 or "Xray-core" not in version_process.stdout:
                 print("Warning: Xray version command failed or output unexpected. Check Stderr.", file=sys.stderr)
        except subprocess.TimeoutExpired:
            print(f"ERROR: Timeout expired while running '{XRAY_PATH} version'. Xray might be unresponsive.", file=sys.stderr)
            return False
        except FileNotFoundError:
             print(f"ERROR: Cannot execute '{XRAY_PATH}'. File not found or permission issue.", file=sys.stderr)
             return False
        except Exception as verify_e:
            print(f"ERROR: Could not run Xray for verification: {verify_e}", file=sys.stderr)
            return False

        print("Xray download and setup seems complete.")
        return True

    except requests.exceptions.RequestException as req_e:
        print(f"ERROR: Failed network request during Xray download: {req_e}", file=sys.stderr); return False
    except zipfile.BadZipFile:
        print(f"ERROR: Downloaded file is not a valid ZIP archive.", file=sys.stderr); return False
    except (ValueError, NotImplementedError, FileNotFoundError) as setup_e:
         print(f"ERROR: Failed during Xray setup: {setup_e}", file=sys.stderr); return False
    except Exception as e:
        print(f"ERROR: An unexpected error occurred in download_and_extract_xray: {e}", file=sys.stderr); return False

# --- Config Generation (Corrected SS Parsing) ---
def generate_config(key_url):
    """Generates a minimal Xray JSON config for testing various key types."""
    try:
        key_url = key_url.strip()
        if not key_url or '://' not in key_url:
            return None

        parsed_url = urlparse(key_url)
        protocol = parsed_url.scheme
        config = None

        base_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"port": 10808, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]
        }
        outbound = base_config["outbounds"][0]

        # --- VMess ---
        if protocol == "vmess":
            try:
                vmess_b64 = key_url[len("vmess://"):]
                vmess_b64 += '=' * (-len(vmess_b64) % 4)
                vmess_json_str = base64.b64decode(vmess_b64).decode('utf-8', errors='replace')
                vmess_params = json.loads(vmess_json_str)
                outbound["settings"]["vnext"] = [{"address": vmess_params.get("add", ""),"port": int(vmess_params.get("port", 443)),"users": [{"id": vmess_params.get("id", ""),"alterId": int(vmess_params.get("aid", 0)),"security": vmess_params.get("scy", "auto")}]}]
                stream_settings = outbound["streamSettings"]
                stream_settings["network"] = vmess_params.get("net", "tcp")
                stream_settings["security"] = vmess_params.get("tls", "none")
                if stream_settings["security"] == "tls":
                    sni = vmess_params.get("sni", vmess_params.get("host", ""))
                    sni = sni if sni else vmess_params.get("add", "")
                    stream_settings["tlsSettings"] = {"serverName": sni, "allowInsecure": False}
                net_type = stream_settings["network"]
                host = vmess_params.get("host", "")
                path = vmess_params.get("path", "/")
                if net_type == "ws":
                    ws_host = host if host else vmess_params.get("add", "")
                    stream_settings["wsSettings"] = {"path": path, "headers": {"Host": ws_host}}
                elif net_type == "tcp" and vmess_params.get("type") == "http":
                    host_list = [h.strip() for h in host.split(',') if h.strip()] or [vmess_params.get("add", "")]
                    stream_settings["tcpSettings"] = {"header": {"type": "http","request": {"path": [path],"headers": {"Host": host_list}}}}
                elif net_type == "grpc":
                     service_name = vmess_params.get("path", "")
                     mode = vmess_params.get("mode", "gun")
                     stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode == "multi"}
                config = base_config
            except Exception as e: print(f"DEBUG: Error processing VMess link ({e}): {key_url[:70]}..."); return None
        # --- VLESS ---
        elif protocol == "vless":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None
                uuid = parsed_url.username; address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                outbound["settings"]["vnext"] = [{"address": address,"port": port,"users": [{"id": uuid,"flow": params.get('flow', [None])[0] or "","encryption": params.get('encryption', ['none'])[0]}]}]
                if outbound["settings"]["vnext"][0]["encryption"] != 'none': outbound["settings"]["vnext"][0]["encryption"] = 'none'
                stream_settings = outbound["streamSettings"]; stream_settings["network"] = params.get('type', ['tcp'])[0]; stream_settings["security"] = params.get('security', ['none'])[0]
                sec_type = stream_settings["security"]; sni = params.get('sni', params.get('peer', [address]))[0]; fingerprint = params.get('fp', [''])[0]; allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'
                if sec_type == "tls":
                    alpn = params.get('alpn', [None])[0]; tls_settings = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                    if alpn: tls_settings["alpn"] = [p.strip() for p in alpn.split(',')]
                    stream_settings["tlsSettings"] = tls_settings
                elif sec_type == "reality":
                    pbk = params.get('pbk', [''])[0]; sid = params.get('sid', [''])[0]; spx = unquote_plus(params.get('spx', ['/'])[0])
                    if not pbk or not sid: return None
                    stream_settings["realitySettings"] = {"serverName": sni,"fingerprint": fingerprint,"shortId": sid,"publicKey": pbk,"spiderX": spx}
                    if "tlsSettings" in stream_settings: del stream_settings["tlsSettings"]
                net_type = stream_settings["network"]; host = params.get('host', [address])[0]; path = unquote_plus(params.get('path', ['/'])[0]); service_name = unquote_plus(params.get('serviceName', [''])[0])
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc": mode = params.get('mode', ['gun'])[0]; stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode=="multi"}
                elif net_type == "tcp" and params.get('headerType', ['none'])[0] == 'http':
                     host_list = [h.strip() for h in host.split(',') if h.strip()] or [address]; path_list = [path]
                     stream_settings["tcpSettings"] = {"header": {"type": "http","request": { "path": path_list, "headers": { "Host": host_list } }}}
                config = base_config
            except Exception as e: print(f"DEBUG: Error processing VLESS link ({e}): {key_url[:70]}..."); return None
        # --- Trojan ---
        elif protocol == "trojan":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None
                password = unquote_plus(parsed_url.username); address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                outbound["settings"]["servers"] = [{"address": address, "port": port, "password": password}]
                stream_settings = outbound["streamSettings"]; stream_settings["network"] = params.get('type', ['tcp'])[0]; stream_settings["security"] = params.get('security', ['tls'])[0]
                sec_type = stream_settings["security"]
                if sec_type == "tls":
                    sni = params.get('sni', params.get('peer', [address]))[0]; fingerprint = params.get('fp', [''])[0]; allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'; alpn = params.get('alpn', [None])[0]
                    tls_settings = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                    if alpn: tls_settings["alpn"] = [p.strip() for p in alpn.split(',')]
                    stream_settings["tlsSettings"] = tls_settings
                elif sec_type == "reality": stream_settings["security"] = "tls"; sni = params.get('sni', params.get('peer', [address]))[0]; fingerprint = params.get('fp', [''])[0]; allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'; stream_settings["tlsSettings"] = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                elif sec_type != "none": stream_settings["security"] = "tls"; sni = params.get('sni', params.get('peer', [address]))[0]; fingerprint = params.get('fp', [''])[0]; allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'; stream_settings["tlsSettings"] = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                net_type = stream_settings["network"]; host = params.get('host', [address])[0]; path = unquote_plus(params.get('path', ['/'])[0]); service_name = unquote_plus(params.get('serviceName', [''])[0])
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc": mode = params.get('mode', ['gun'])[0]; stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode=="multi"}
                elif net_type == "tcp" and params.get('headerType', ['none'])[0] == 'http':
                     host_list = [h.strip() for h in host.split(',') if h.strip()] or [address]; path_list = [path]
                     stream_settings["tcpSettings"] = {"header": {"type": "http","request": { "path": path_list, "headers": { "Host": host_list } }}}
                config = base_config
            except Exception as e: print(f"DEBUG: Error processing Trojan link ({e}): {key_url[:70]}..."); return None

        # --- Shadowsocks (SS) --- SyntaxError fix applied below ---
        elif protocol == "ss":
            try:
                password = None
                method = None
                address = None
                port = None

                # Format 1: ss://method:password@hostname:port#remarks OR ss://BASE64(method:password)@hostname:port
                if '@' in parsed_url.netloc and ':' in parsed_url.netloc:
                    user_info_part = parsed_url.netloc.split('@')[0]
                    server_part = parsed_url.netloc.split('@')[1]

                    # --- CORRECTED SECTION for SyntaxError ---
                    # Parse server_part (hostname:port)
                    if ':' in server_part:
                        address = server_part.split(':')[0]
                        try:
                            # Attempt to convert port to integer
                            port = int(server_part.split(':')[1])
                        except ValueError:
                            # Handle invalid port format
                            print(f"DEBUG: Invalid port in SS URL server part: {server_part.split(':')[1]} for {key_url[:70]}")
                            return None # Cannot proceed without valid port
                    else:
                        # Handle missing port in server part
                        print(f"DEBUG: Missing port in SS URL server part: {server_part} for {key_url[:70]}")
                        return None # Cannot proceed without port
                    # --- END CORRECTED SECTION ---

                    # Parse user_info_part (method:password or base64 thereof)
                    if ':' in user_info_part:
                        is_base64 = False
                        try:
                            # Try decoding user_info_part as Base64(method:password)
                            user_info_b64 = user_info_part + '=' * (-len(user_info_part) % 4)
                            decoded_user_info = base64.b64decode(user_info_b64).decode('utf-8', errors='replace')
                            if ':' in decoded_user_info:
                                method, password = decoded_user_info.split(':', 1)
                                is_base64 = True
                        except Exception:
                            # Decoding failed or result invalid, assume plain text
                            pass
                        if not is_base64:
                            # Treat as plain method:password
                            try:
                                method, password = user_info_part.split(':', 1)
                            except ValueError:
                                # Plain format also missing colon
                                print(f"DEBUG: Invalid user info format (no colon): {user_info_part} for {key_url[:70]}")
                                return None
                    else:
                        # User info part has no colon at all
                        print(f"DEBUG: Invalid user info format (no colon): {user_info_part} for {key_url[:70]}")
                        return None

                # Format 2: ss://BASE64(method:password@hostname:port)#remarks
                elif not parsed_url.netloc and parsed_url.path:
                    try:
                        ss_b64 = parsed_url.path + '=' * (-len(parsed_url.path) % 4)
                        decoded_str = base64.b64decode(ss_b64).decode('utf-8', errors='replace')
                        # Now parse the decoded string like format 1
                        if '@' in decoded_str and ':' in decoded_str.split('@')[0] and ':' in decoded_str.split('@')[1]:
                             user_info_part = decoded_str.split('@')[0]
                             server_part = decoded_str.split('@')[1]
                             # Parse decoded parts
                             method, password = user_info_part.split(':', 1)
                             address = server_part.split(':')[0]
                             try:
                                 port = int(server_part.split(':')[1])
                             except ValueError:
                                 print(f"DEBUG: Invalid port in decoded SS Base64: {server_part.split(':')[1]} for {key_url[:70]}")
                                 return None
                        else:
                            # Decoded string doesn't match expected format
                            print(f"DEBUG: Decoded SS Base64 does not match expected format: {decoded_str[:50]}... for {key_url[:70]}")
                            return None
                    except Exception as e:
                        print(f"DEBUG: Failed to decode/parse full SS Base64 URL ({e}): {key_url[:70]}")
                        return None

                # Unrecognized SS format
                else:
                    print(f"DEBUG: Unrecognized SS URL format: {key_url[:70]}")
                    return None

                # Final check if all parts were successfully extracted
                if not all([password, method, address, port]):
                    print(f"DEBUG: Failed to extract all required SS parts (password/method/address/port missing) for: {key_url[:70]}")
                    return None # Exit if any part is missing

                # Construct the outbound settings
                outbound["settings"]["servers"] = [{"address": address,"port": port,"method": method,"password": password}]
                outbound["streamSettings"]["network"] = "tcp" # SS typically uses TCP directly
                # Remove security settings if present, not standard for basic SS config
                if "security" in outbound["streamSettings"]: del outbound["streamSettings"]["security"]
                if "tlsSettings" in outbound.get("streamSettings", {}): del outbound["streamSettings"]["tlsSettings"]

                config = base_config # Assign the generated config

            # Catch errors during the overall SS processing block
            except Exception as e:
                print(f"DEBUG: Error processing SS link ({e}): {key_url[:70]}...")
                return None

        # --- End of SS handling ---
        else: return None # Unsupported protocol

        # Cleanup Empty Settings
        stream_settings = outbound.get("streamSettings")
        if stream_settings:
            for key in list(stream_settings.keys()):
                if isinstance(stream_settings[key], dict) and not stream_settings[key]: del stream_settings[key]
            if not stream_settings: del outbound["streamSettings"]
        elif "streamSettings" in outbound: del outbound["streamSettings"]

        return json.dumps(config, indent=2) if config else None
    except Exception as e: print(f"DEBUG: Outer error in generate_config for {key_url[:70]}...: {e}"); return None

# --- Key Testing ---
def test_v2ray_key(key_url):
    """Tests a single V2Ray/Xray key using xray run -test and logs failures."""
    config_json = generate_config(key_url)
    if not config_json: return key_url, False

    temp_config_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tf:
            tf.write(config_json); temp_config_file = tf.name
        command = [XRAY_PATH, "run", "-test", "-config", temp_config_file]
        is_working = False; process_stderr = "Unknown test error"; process_returncode = -1
        try:
            process = subprocess.run(command,capture_output=True,text=True,timeout=TEST_TIMEOUT,check=False,encoding='utf-8', errors='replace')
            process_stderr = process.stderr.strip() if process.stderr else ""; process_returncode = process.returncode; is_working = (process_returncode == 0)
            if is_working and process_stderr:
                failure_keywords = ["failed to dial", "proxy connection failed","timeout", "authentication failed", "connection refused","tls: handshake failure", "tls: bad certificate","reality verification failed", "invalid user"]
                if any(keyword in process_stderr.lower() for keyword in failure_keywords): is_working = False
        except subprocess.TimeoutExpired: process_stderr = f"Timeout ({TEST_TIMEOUT}s)"; is_working = False
        except Exception as e: process_stderr = f"Subprocess execution error: {e}"; print(f"DEBUG: [FAIL] {process_stderr} testing key {key_url[:70]}..."); is_working = False
        if not is_working:
             key_prefix = key_url[:70] + ('...' if len(key_url) > 70 else '')
             if "Timeout" not in process_stderr and "generation failed" not in process_stderr and "Subprocess execution error" not in process_stderr:
                  if process_stderr and "config file not readable" not in process_stderr.lower(): print(f"DEBUG: [FAIL] Key: {key_prefix} | RC={process_returncode} | Error: {process_stderr}")
        return key_url, is_working
    except Exception as e: print(f"DEBUG: [FAIL] Outer Error in test_v2ray_key for {key_url[:70]}...: {e}"); return key_url, False
    finally:
        if temp_config_file and os.path.exists(temp_config_file):
            try: os.remove(temp_config_file)
            except Exception as e_rem: print(f"Warning: Failed to remove temp config file {temp_config_file}: {e_rem}")

# --- Main Execution ---
def main():
    start_time = time.time()
    print(f"Starting Consolidated Key Tester Script at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*40)

    # 1. Setup Xray
    print("\n--- Step 1: Setting up Xray ---")
    if not download_and_extract_xray():
        print("FATAL: Failed to get/verify Xray binary. Aborting.", file=sys.stderr); sys.exit(1)
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK):
        print(f"FATAL: Xray executable not found or not executable at {XRAY_PATH}. Aborting.", file=sys.stderr); sys.exit(1)
    print(f"Using Xray executable at: {os.path.abspath(XRAY_PATH)}")

    # 2. Ensure output directory exists
    print(f"\n--- Step 2: Preparing Output Directory ({OUTPUT_DIR}) ---")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True); print(f"Output directory ensured: {OUTPUT_DIR}")
    except OSError as e: print(f"FATAL: Could not create output directory {OUTPUT_DIR}: {e}", file=sys.stderr); sys.exit(1)

    # 3. Fetch Keys from All Sources
    print("\n--- Step 3: Fetching Keys from All Sources ---")
    all_fetched_keys = []
    processed_urls_count = 0
    fetch_errors = 0

    for index, url in enumerate(SOURCE_URLS_LIST):
        print(f"\nFetching from URL {index+1}/{len(SOURCE_URLS_LIST)}: {url}...")
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 V2RayKeyTester/1.2'}
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers)
            response.raise_for_status()
            try: raw_data = response.content.decode(response.encoding or 'utf-8', errors='replace')
            except Exception: raw_data = response.text

            fetched_count = 0; valid_protocol_count = 0; source_keys = []
            processed_lines = set()
            lines = raw_data.splitlines()
            fetched_count = len(lines)

            for line in lines:
                line = line.strip()
                if not line or line in processed_lines: continue
                processed_lines.add(line)
                for prefix in SUPPORTED_PROTOCOLS:
                    if line.startswith(prefix):
                        source_keys.append(line); valid_protocol_count += 1; break

            print(f"  Fetched {fetched_count} lines, found {valid_protocol_count} potential keys.")
            all_fetched_keys.extend(source_keys)
            processed_urls_count += 1

        except requests.exceptions.Timeout: print(f"ERROR: Timeout fetching from {url}"); fetch_errors += 1
        except requests.exceptions.RequestException as e: print(f"ERROR: Failed fetching from {url}: {e}"); fetch_errors += 1
        except Exception as e: print(f"ERROR: Failed processing source {url}: {e}"); fetch_errors += 1

    print(f"\nFinished fetching. Processed {processed_urls_count}/{len(SOURCE_URLS_LIST)} URLs successfully.")
    if fetch_errors > 0: print(f"Encountered {fetch_errors} errors during fetching.")

    # Remove duplicates across all sources
    seen_keys = set()
    unique_keys_to_test = []
    for key in all_fetched_keys:
        if key and key not in seen_keys:
            unique_keys_to_test.append(key); seen_keys.add(key)

    # 4. Test Keys
    print("\n--- Step 4: Testing Keys ---")
    print(f"Total unique potential keys to test: {len(unique_keys_to_test)}")

    if not unique_keys_to_test:
         print("No unique keys found to test. Writing empty output file.")
         try:
             with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f: pass
             print(f"Ensured empty file: {OUTPUT_FILE_PATH}")
         except Exception as e_f: print(f"Warning: Could not create empty file {OUTPUT_FILE_PATH}: {e_f}")
         print("Script finished.")
         return

    all_working_keys = []
    tested_count = 0
    start_test_time = time.time()

    print(f"Starting tests (Max Workers: {MAX_WORKERS}, Test Timeout: {TEST_TIMEOUT}s)...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_to_test}
        for future in as_completed(future_to_key):
            key = future_to_key[future]; tested_count += 1
            try:
                _key_url_ignored, is_working = future.result()
                if is_working: all_working_keys.append(key)
            except Exception as e_res: print(f"Warning: Error getting result for key {key[:40]}...: {e_res}"); pass
            if tested_count % 100 == 0 or tested_count == len(unique_keys_to_test):
                 elapsed = time.time() - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
                 print(f"Progress: Tested {tested_count}/{len(unique_keys_to_test)} keys... ({elapsed:.1f}s, {rate:.1f} keys/s)")

    # 5. Write Consolidated Results
    print("\n--- Step 5: Writing Consolidated Results ---")
    num_working_found = len(all_working_keys)
    print(f"Total working keys found: {num_working_found}")

    # Shuffle the working keys before limiting (optional, gives variety)
    random.shuffle(all_working_keys)
    print(f"Shuffled working keys.")

    # Apply total key limit
    if num_working_found > MAX_TOTAL_KEYS:
        print(f"Limiting output to first {MAX_TOTAL_KEYS} working keys (out of {num_working_found}).")
        keys_to_write = all_working_keys[:MAX_TOTAL_KEYS]
    else:
        keys_to_write = all_working_keys

    num_keys_to_write = len(keys_to_write)

    try:
        # Sort keys again after limiting and shuffling if desired for final output order
        # keys_to_write.sort() # Or sort based on some criteria

        # Write the final list to the single output file
        with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f:
            for key_to_write in keys_to_write:
                f.write(key_to_write + '\n')
        print(f"Successfully wrote {num_keys_to_write} keys to {OUTPUT_FILE_PATH}")

    except Exception as e_w:
        print(f"ERROR writing output file {OUTPUT_FILE_PATH}: {e_w}")

    # --- Final Summary ---
    print("\n--- Script Summary ---")
    end_time = time.time()
    total_time = end_time - start_time
    print(f"Total working keys FOUND: {num_working_found}")
    print(f"Total working keys WRITTEN (after limit of {MAX_TOTAL_KEYS}): {num_keys_to_write}")
    print(f"Output file: {OUTPUT_FILE_PATH}")
    print(f"Script finished in {total_time:.2f} seconds.")
    print("="*40)

if __name__ == "__main__":
    main()
