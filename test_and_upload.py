# FILE: test_and_upload_merged.py
# Description: Fetches V2Ray keys, tests them using Xray (Proxy Method), and saves working keys.
# Merged from user's working script and previous upgraded script.

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
import socket
import re
import random

# --- Configuration ---

# Fetch URLs from environment variable, split by lines, filter empty lines
SOURCE_URLS_RAW = os.environ.get('SOURCE_URLS_SECRET', '')
SOURCE_URLS_LIST = [url.strip() for url in SOURCE_URLS_RAW.splitlines() if url.strip()]

if not SOURCE_URLS_LIST:
    print("ERROR: SOURCE_URLS_SECRET is empty or not set in GitHub Secrets.", file=sys.stderr)
    sys.exit(1)
else:
    print(f"Loaded {len(SOURCE_URLS_LIST)} URLs from SOURCE_URLS_SECRET.")

OUTPUT_DIR = "subscription"
OUTPUT_FILENAME = "working_keys.txt"
OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)

XRAY_PATH = "./xray" # Path where xray executable will be placed
MAX_WORKERS = 15     # Number of concurrent tests
REQUEST_TIMEOUT = 20 # Timeout for fetching subscription URLs (seconds)
TEST_PROXY_TIMEOUT = 10 # Timeout for the actual proxy test request (seconds)
MAX_TOTAL_KEYS = 1500 # Maximum number of working keys to save
SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"] # Supported prefixes

# Proxy Test Configuration
PROXY_PORT = 10808 # Local port Xray will listen on for SOCKS proxy
TEST_URLS = [
    "https://www.google.com/generate_204", # Standard check, expects 204
    "http://detectportal.firefox.com/success.txt" # HTTP check, expects 200 with content
]
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'
}

# --- Xray Installation ---
# Using the refined version from the user's script
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
            print("Using GH_TOKEN for GitHub API request.")
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
            elif machine in ['aarch64', 'arm64']: asset_name = "Xray-linux-arm64-v8a.zip" # Include arm64 alias
            else: raise ValueError(f"Unsupported Linux architecture: {machine}")
        # Add elif for other OS if needed (e.g., darwin for macOS)
        # elif system == 'darwin': asset_name = "Xray-macos-64.zip" # Example for macOS
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
        download_response = requests.get(asset_url, stream=True, timeout=120) # Longer timeout for download
        download_response.raise_for_status()

        print("Extracting Xray...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray' # Linux/macOS default executable name
                extracted = False
                for member in zf.namelist():
                    # Check if it's the executable we want (might be in a subdir)
                    if member.endswith(exe_name) and not member.startswith('__MACOSX') and not member.endswith('/'):
                        print(f"  Found executable member: {member}")
                        # Extract to current directory, preserving path if needed temporarily
                        zf.extract(member, path=".")
                        extracted_path = os.path.join(".", member) # Path where it was actually extracted
                        print(f"  Extracted to: {extracted_path}")

                        # Ensure the final path is exactly XRAY_PATH ('./xray')
                        if os.path.abspath(extracted_path) != os.path.abspath(XRAY_PATH):
                             if os.path.exists(XRAY_PATH):
                                  print(f"  Removing existing file at {XRAY_PATH}")
                                  os.remove(XRAY_PATH)
                             print(f"  Moving/Renaming extracted file from {extracted_path} to {XRAY_PATH}")
                             os.rename(extracted_path, XRAY_PATH)

                        # Clean up empty directory if extraction created one
                        member_dir = os.path.dirname(member)
                        if member_dir and os.path.exists(os.path.join(".", member_dir)) and not os.listdir(os.path.join(".", member_dir)):
                            try:
                                os.rmdir(os.path.join(".", member_dir))
                                print(f"  Removed empty source directory: {os.path.join('.', member_dir)}")
                            except OSError:
                                print(f"  Could not remove source directory (might not be empty): {os.path.join('.', member_dir)}")
                                pass # Ignore if removal fails

                        print(f"  Xray executable placed at '{XRAY_PATH}'")
                        extracted = True
                        break # Stop after finding the first match
                if not extracted:
                    raise FileNotFoundError(f"'{exe_name}' executable not found within the zip file {asset_name}.")
        else:
            # Handle other archive types like .tar.gz if needed
            raise NotImplementedError(f"Extraction not implemented for asset type: {asset_name}")

        if not os.path.exists(XRAY_PATH):
            raise FileNotFoundError(f"Xray executable not found at '{XRAY_PATH}' after extraction attempt.")

        # Set execute permissions
        if system != 'windows':
            try:
                print(f"Making '{XRAY_PATH}' executable...")
                st = os.stat(XRAY_PATH)
                # Set execute permission for user, group, and others
                os.chmod(XRAY_PATH, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                if not os.access(XRAY_PATH, os.X_OK):
                     raise OSError("Execute permission check failed after chmod.")
                print(f"'{XRAY_PATH}' is now executable.")
            except Exception as chmod_e:
                print(f"ERROR: Failed to make '{XRAY_PATH}' executable: {chmod_e}", file=sys.stderr)
                # Attempt to use intermediate shell command as fallback (less ideal)
                try:
                    subprocess.run(['chmod', '+x', XRAY_PATH], check=True)
                    if not os.access(XRAY_PATH, os.X_OK): raise OSError("Fallback chmod +x failed")
                    print("Fallback chmod +x succeeded.")
                except Exception as fallback_e:
                     print(f"ERROR: Fallback chmod also failed: {fallback_e}", file=sys.stderr)
                     return False # Cannot proceed if not executable

        # --- Verification Step ---
        print(f"Attempting to verify Xray installation by running: {XRAY_PATH} version")
        try:
            # Use absolute path for robustness
            abs_xray_path = os.path.abspath(XRAY_PATH)
            version_process = subprocess.run([abs_xray_path, "version"],
                                             capture_output=True, text=True, timeout=10, check=False,
                                             encoding='utf-8', errors='replace')
            print(f"--- XRAY VERSION ---")
            print(f"Command: {abs_xray_path} version")
            print(f"Exit Code: {version_process.returncode}")
            stdout_strip = version_process.stdout.strip()
            stderr_strip = version_process.stderr.strip()
            print(f"Stdout: {stdout_strip}")
            if stderr_strip: print(f"Stderr: {stderr_strip}")
            print(f"--- END XRAY VERSION ---")

            # Basic check on output
            if version_process.returncode != 0 or "Xray-core" not in stdout_strip:
                 print("Warning: Xray version command failed or output unexpected. Check Stderr. Continuing cautiously...", file=sys.stderr)
                 # Optionally return False here if strict verification is needed
                 # return False
            else:
                 print("Xray version verified successfully.")

        except subprocess.TimeoutExpired:
            print(f"ERROR: Timeout expired while running '{XRAY_PATH} version'. Xray might be unresponsive.", file=sys.stderr)
            return False
        except FileNotFoundError:
             # This should ideally not happen if chmod worked, but check again
             print(f"ERROR: Cannot execute '{XRAY_PATH}'. File not found or permission issue.", file=sys.stderr)
             return False
        except Exception as verify_e:
            print(f"ERROR: Could not run Xray for verification: {verify_e}", file=sys.stderr)
            return False

        print("Xray download and setup complete.")
        return True

    except requests.exceptions.RequestException as req_e:
        print(f"ERROR: Failed network request during Xray download: {req_e}", file=sys.stderr); return False
    except zipfile.BadZipFile:
        print(f"ERROR: Downloaded file is not a valid ZIP archive.", file=sys.stderr); return False
    except (ValueError, NotImplementedError, FileNotFoundError, OSError) as setup_e: # Added OSError
         print(f"ERROR: Failed during Xray setup: {setup_e}", file=sys.stderr); return False
    except Exception as e:
        # Catch any other unexpected errors
        import traceback
        print(f"ERROR: An unexpected error occurred in download_and_extract_xray: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr) # Print traceback for unexpected errors
        return False


# --- Config Generation (Merged and Refined) ---
def generate_config(key_url):
    """Generates an Xray JSON configuration for proxy testing."""
    try:
        key_url = key_url.strip()
        if not key_url or '://' not in key_url:
            print(f"DEBUG: Invalid key format (no protocol): {key_url[:70]}...")
            return None

        parsed_url = urlparse(key_url)
        protocol = parsed_url.scheme

        # Base config for proxy mode testing
        base_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "port": PROXY_PORT,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, # Enable UDP, listen locally
                "listen": "127.0.0.1"
            }],
            "outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]
        }
        outbound = base_config["outbounds"][0]
        stream_settings = outbound["streamSettings"] # Use reference for easier access
        config = None # Will be assigned base_config if parsing succeeds

        # --- VMess --- (Logic from user's script)
        if protocol == "vmess":
            print(f"DEBUG: Processing VMess: {key_url[:40]}...")
            try:
                vmess_b64 = key_url[len("vmess://"):]
                vmess_b64 += '=' * (-len(vmess_b64) % 4) # Ensure padding
                vmess_json_str = base64.b64decode(vmess_b64).decode('utf-8', errors='replace')
                vmess_params = json.loads(vmess_json_str)

                address = vmess_params.get("add", "")
                port = int(vmess_params.get("port", 443))
                user_id = vmess_params.get("id", "")
                alter_id = int(vmess_params.get("aid", 0))
                security = vmess_params.get("scy", "auto")
                net_type = vmess_params.get("net", "tcp")
                tls_setting = vmess_params.get("tls", "none")
                sni_val = vmess_params.get("sni", vmess_params.get("host", ""))
                host_val = vmess_params.get("host", "")
                path_val = vmess_params.get("path", "/")
                header_type = vmess_params.get("type", "none") # For http headers

                if not address or not user_id:
                    print(f"DEBUG: VMess missing address or id: {key_url[:70]}...")
                    return None

                outbound["settings"]["vnext"] = [{
                    "address": address,
                    "port": port,
                    "users": [{"id": user_id, "alterId": alter_id, "security": security}]
                }]
                stream_settings["network"] = net_type
                stream_settings["security"] = tls_setting

                if tls_setting == "tls":
                    # Use SNI, fallback to host, fallback to address
                    effective_sni = sni_val if sni_val else (host_val if host_val else address)
                    stream_settings["tlsSettings"] = {"serverName": effective_sni, "allowInsecure": False} # Adjust allowInsecure if needed

                if net_type == "ws":
                    # Use host header, fallback to address
                    effective_ws_host = host_val if host_val else address
                    stream_settings["wsSettings"] = {"path": path_val, "headers": {"Host": effective_ws_host}}
                elif net_type == "tcp" and header_type == "http":
                    # Use host header list, fallback to address
                    host_list = [h.strip() for h in host_val.split(',') if h.strip()] or [address]
                    stream_settings["tcpSettings"] = {
                        "header": {"type": "http", "request": {"path": [path_val], "headers": {"Host": host_list}}}
                    }
                elif net_type == "grpc":
                     service_name = path_val # gRPC often uses path for serviceName
                     mode = vmess_params.get("mode", "gun") # gun or multi
                     stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode == "multi"}
                # Add other network types like h2, quic if needed

                config = base_config
                print(f"DEBUG: VMess processing SUCCESS: {key_url[:40]}...")
            except json.JSONDecodeError as e:
                print(f"DEBUG: VMess Base64 decode or JSON parse error ({e}): {key_url[:70]}...")
                return None
            except Exception as e:
                print(f"DEBUG: Unexpected error processing VMess link ({e}): {key_url[:70]}...")
                return None

        # --- VLESS --- (Logic from user's script, adapted)
        elif protocol == "vless":
            print(f"DEBUG: Processing VLESS: {key_url[:40]}...")
            try:
                if not parsed_url.username or not parsed_url.hostname:
                    print(f"DEBUG: VLESS missing UUID or Hostname: {key_url[:70]}...")
                    return None

                uuid = parsed_url.username
                address = parsed_url.hostname
                port = int(parsed_url.port or 443)
                params = parse_qs(parsed_url.query)

                # Extract parameters safely using .get() with defaults
                flow = params.get('flow', [None])[0] or "" # Default flow is often empty string in Xray
                encryption = params.get('encryption', ['none'])[0] # Should always be 'none' for VLESS

                # VLESS MUST use 'none' encryption in settings.vnext
                if encryption != 'none':
                    print(f"DEBUG: VLESS encryption is not 'none', correcting. Key: {key_url[:70]}...")
                    encryption = 'none' # Force it

                outbound["settings"]["vnext"] = [{
                    "address": address,
                    "port": port,
                    "users": [{"id": uuid, "flow": flow, "encryption": encryption}]
                }]

                net_type = params.get('type', ['tcp'])[0]
                sec_type = params.get('security', ['none'])[0]
                sni = params.get('sni', params.get('peer', [address]))[0] # SNI > Peer > Address
                fingerprint = params.get('fp', [''])[0]
                allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'

                stream_settings["network"] = net_type
                stream_settings["security"] = sec_type

                print(f"DEBUG: VLESS Parsed: net={net_type}, sec={sec_type}, sni={sni}, fp={fingerprint}, flow={flow}")

                if sec_type == "tls":
                    alpn = params.get('alpn', [None])[0]
                    tls_settings = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                    if alpn:
                        tls_settings["alpn"] = [p.strip() for p in alpn.split(',') if p.strip()]
                        print(f"DEBUG: VLESS TLS ALPN: {tls_settings['alpn']}")
                    stream_settings["tlsSettings"] = tls_settings
                elif sec_type == "reality":
                    pbk = params.get('pbk', [''])[0]
                    sid = params.get('sid', [''])[0]
                    # Use unquote_plus for potentially encoded spx
                    spx = unquote_plus(params.get('spx', ['/'])[0])
                    if not pbk or not sid:
                         print(f"DEBUG: VLESS REALITY missing pbk or sid: {key_url[:70]}...")
                         return None # REALITY requires pbk and sid
                    # REALITY uses serverName from SNI parameter preferentially
                    reality_server_name = sni if sni else address
                    # Fingerprint is also essential for REALITY
                    reality_fp = fingerprint if fingerprint else "chrome" # Default to chrome if not provided
                    stream_settings["realitySettings"] = {
                        "serverName": reality_server_name,
                        "fingerprint": reality_fp,
                        "shortId": sid,
                        "publicKey": pbk,
                        "spiderX": spx
                    }
                    print(f"DEBUG: VLESS REALITY Settings: {stream_settings['realitySettings']}")
                    # Ensure tlsSettings is removed if reality is used
                    if "tlsSettings" in stream_settings: del stream_settings["tlsSettings"]
                else: # Handle 'none' security or others
                    if "tlsSettings" in stream_settings: del stream_settings["tlsSettings"]
                    if "realitySettings" in stream_settings: del stream_settings["realitySettings"]


                # Network specific settings
                host = params.get('host', [address])[0] # Host header > Address
                path = unquote_plus(params.get('path', ['/'])[0])
                service_name = unquote_plus(params.get('serviceName', [''])[0])
                mode = params.get('mode', ['gun'])[0] # For gRPC, ws, etc.

                if net_type == "ws":
                    stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                    print(f"DEBUG: VLESS WS Settings: {stream_settings['wsSettings']}")
                elif net_type == "grpc":
                    stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode == "multi"}
                    print(f"DEBUG: VLESS GRPC Settings: {stream_settings['grpcSettings']}")
                elif net_type == "tcp" and params.get('headerType', ['none'])[0] == 'http':
                     # Use host list, fallback to address
                     host_list = [h.strip() for h in host.split(',') if h.strip()] or [address]
                     path_list = [path] # Path should be a list for http header request
                     stream_settings["tcpSettings"] = {
                         "header": {"type": "http", "request": {"path": path_list, "headers": {"Host": host_list}}}
                     }
                     print(f"DEBUG: VLESS TCP HTTP Header Settings: {stream_settings['tcpSettings']}")
                # Add other network types (h2, quic) if needed

                config = base_config
                print(f"DEBUG: VLESS processing SUCCESS: {key_url[:40]}...")
            except Exception as e:
                import traceback
                print(f"DEBUG: Unexpected error processing VLESS link ({e}): {key_url[:70]}...")
                print(traceback.format_exc(), file=sys.stderr)
                return None

        # --- Trojan --- (Logic from user's script, adapted)
        elif protocol == "trojan":
            print(f"DEBUG: Processing Trojan: {key_url[:40]}...")
            try:
                if not parsed_url.username or not parsed_url.hostname:
                     print(f"DEBUG: Trojan missing password or hostname: {key_url[:70]}...")
                     return None

                # Password might contain special characters
                password = unquote_plus(parsed_url.username)
                address = parsed_url.hostname
                port = int(parsed_url.port or 443) # Default Trojan port is 443
                params = parse_qs(parsed_url.query)

                outbound["settings"]["servers"] = [{"address": address, "port": port, "password": password}]

                # Trojan almost always uses TLS, handle other params similarly to VLESS
                net_type = params.get('type', ['tcp'])[0]
                # Default security to 'tls' for Trojan if not specified or 'none'
                sec_type = params.get('security', ['tls'])[0]
                if sec_type == 'none': sec_type = 'tls'

                sni = params.get('sni', params.get('peer', [address]))[0] # SNI > Peer > Address
                fingerprint = params.get('fp', [''])[0]
                allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'
                alpn = params.get('alpn', [None])[0]

                stream_settings["network"] = net_type
                stream_settings["security"] = sec_type

                print(f"DEBUG: Trojan Parsed: net={net_type}, sec={sec_type}, sni={sni}, fp={fingerprint}")

                # Trojan typically uses TLS. Reality is not standard for Trojan.
                if sec_type == "tls":
                    tls_settings = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                    if alpn:
                         tls_settings["alpn"] = [p.strip() for p in alpn.split(',') if p.strip()]
                         print(f"DEBUG: Trojan TLS ALPN: {tls_settings['alpn']}")
                    stream_settings["tlsSettings"] = tls_settings
                # If security is something else, treat it as TLS anyway for Trojan standard practice
                elif sec_type != "none":
                     stream_settings["security"] = "tls" # Force TLS
                     tls_settings = {"serverName": sni, "fingerprint": fingerprint, "allowInsecure": allow_insecure}
                     if alpn: tls_settings["alpn"] = [p.strip() for p in alpn.split(',') if p.strip()]
                     stream_settings["tlsSettings"] = tls_settings
                     print(f"DEBUG: Trojan security forced to TLS.")


                # Network specific settings
                host = params.get('host', [address])[0] # Host header > Address
                path = unquote_plus(params.get('path', ['/'])[0])
                service_name = unquote_plus(params.get('serviceName', [''])[0])
                mode = params.get('mode', ['gun'])[0] # For gRPC

                if net_type == "ws":
                    stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                    print(f"DEBUG: Trojan WS Settings: {stream_settings['wsSettings']}")
                elif net_type == "grpc":
                    stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode=="multi"}
                    print(f"DEBUG: Trojan GRPC Settings: {stream_settings['grpcSettings']}")
                elif net_type == "tcp" and params.get('headerType', ['none'])[0] == 'http':
                     host_list = [h.strip() for h in host.split(',') if h.strip()] or [address]
                     path_list = [path]
                     stream_settings["tcpSettings"] = {
                         "header": {"type": "http", "request": {"path": path_list, "headers": {"Host": host_list}}}
                     }
                     print(f"DEBUG: Trojan TCP HTTP Header Settings: {stream_settings['tcpSettings']}")
                # Add other network types if applicable

                config = base_config
                print(f"DEBUG: Trojan processing SUCCESS: {key_url[:40]}...")
            except Exception as e:
                import traceback
                print(f"DEBUG: Unexpected error processing Trojan link ({e}): {key_url[:70]}...")
                print(traceback.format_exc(), file=sys.stderr)
                return None

        # --- Shadowsocks (SS) --- (Logic from user's script, reviewed and adapted)
        elif protocol == "ss":
            print(f"DEBUG: Processing SS: {key_url[:40]}...")
            try:
                password = None; method = None; address = None; port = None

                # Format 1: ss://method:password@hostname:port#remarks
                # Format 2: ss://BASE64(method:password)@hostname:port#remarks
                # Format 3: ss://BASE64(method:password@hostname:port)#remarks (Less common but possible)

                user_info = None; host_info = None; remark = None

                # Separate remark first
                if '#' in key_url:
                    key_url_no_remark, remark = key_url.split('#', 1)
                else:
                    key_url_no_remark = key_url

                link_part = key_url_no_remark[len("ss://"):]

                # Check for @ symbol to separate user/host info
                if '@' in link_part:
                    user_info, host_info = link_part.split('@', 1)
                    print(f"DEBUG: SS Format 1/2 detected: User={user_info[:10]}..., Host={host_info}")

                    # --- Parse host_info (hostname:port) ---
                    if ':' not in host_info:
                        print(f"DEBUG: SS host info missing port: {host_info} for {key_url[:70]}")
                        return None
                    address, port_str = host_info.rsplit(':', 1) # Use rsplit for IPv6 addresses
                    try: port = int(port_str)
                    except ValueError:
                        print(f"DEBUG: SS invalid port: {port_str} for {key_url[:70]}")
                        return None

                    # --- Parse user_info (method:password or base64 thereof) ---
                    try:
                        # Attempt Base64 decode first - common for obfuscation
                        user_info_padded = user_info + '=' * (-len(user_info) % 4)
                        decoded_user_info = base64.urlsafe_b64decode(user_info_padded).decode('utf-8', errors='replace')
                        if ':' in decoded_user_info:
                            method, password = decoded_user_info.split(':', 1)
                            print(f"DEBUG: SS user info decoded from Base64: method={method}")
                        else:
                            # Decoded successfully but no colon, maybe plain text?
                            raise ValueError("Decoded Base64 user info lacks colon")
                    except Exception:
                        # Decoding failed or invalid format, assume plain text method:password
                        print(f"DEBUG: SS user info not valid Base64 or format error, trying plain text.")
                        if ':' in user_info:
                            method, password = user_info.split(':', 1)
                            print(f"DEBUG: SS user info parsed as plain text: method={method}")
                        else:
                            # Plain text also lacks colon
                            print(f"DEBUG: SS Invalid user info format (no colon): {user_info} for {key_url[:70]}")
                            return None
                else:
                     # No '@' symbol, assume Format 3: ss://BASE64(method:password@hostname:port)
                     print(f"DEBUG: SS Format 3 detected (or invalid): {link_part[:30]}...")
                     try:
                         full_b64 = link_part + '=' * (-len(link_part) % 4)
                         decoded_full = base64.urlsafe_b64decode(full_b64).decode('utf-8', errors='replace')
                         print(f"DEBUG: SS Format 3 decoded: {decoded_full[:50]}...")
                         # Now parse the decoded string like format 1
                         if '@' in decoded_full and ':' in decoded_full.split('@')[0] and ':' in decoded_full.split('@')[1]:
                              user_info_part = decoded_full.split('@')[0]
                              server_part = decoded_full.split('@')[1]
                              # Parse decoded parts
                              method, password = user_info_part.split(':', 1)
                              address, port_str = server_part.rsplit(':', 1)
                              try: port = int(port_str)
                              except ValueError:
                                  print(f"DEBUG: Invalid port in decoded SS Base64: {port_str} for {key_url[:70]}")
                                  return None
                              print(f"DEBUG: SS Format 3 parsed: method={method}, host={address}:{port}")
                         else:
                              print(f"DEBUG: Decoded SS Base64 (Format 3) does not match expected structure: {decoded_full[:50]}... for {key_url[:70]}")
                              return None
                     except Exception as e:
                         print(f"DEBUG: Failed to decode/parse full SS Base64 URL (Format 3) ({e}): {key_url[:70]}")
                         return None

                # Final check if all parts were successfully extracted
                if not all([password is not None, method, address, port is not None]): # Check password specifically for None
                    print(f"DEBUG: Failed to extract all required SS parts (password/method/address/port missing) for: {key_url[:70]}")
                    return None

                # Construct the outbound settings for SS
                outbound["settings"]["servers"] = [{
                    "address": address,
                    "port": port,
                    "method": method,
                    "password": password,
                    "uot": True # Enable UDP Over TCP for SS by default? Optional.
                }]
                # SS generally doesn't use complex stream settings like others
                stream_settings["network"] = "tcp" # SS primarily uses TCP
                stream_settings["security"] = "none" # No TLS/Reality for standard SS outbound
                # Remove other stream settings if they exist
                for key in ["tlsSettings", "realitySettings", "wsSettings", "grpcSettings", "tcpSettings", "kcpSettings", "quicSettings"]:
                     stream_settings.pop(key, None)

                config = base_config # Assign the generated config
                print(f"DEBUG: SS processing SUCCESS: {key_url[:40]}...")

            except Exception as e:
                import traceback
                print(f"DEBUG: Unexpected error processing SS link ({e}): {key_url[:70]}...")
                print(traceback.format_exc(), file=sys.stderr)
                return None
        else:
            print(f"DEBUG: Unsupported protocol: {protocol} for {key_url[:70]}...")
            return None # Unsupported protocol

        # --- Final JSON Generation ---
        if config:
            # Optional: Clean up empty stream settings dictionaries just before returning
            if outbound.get("streamSettings"):
                 for key in list(stream_settings.keys()):
                     # Remove empty dicts like tlsSettings: {}
                     if isinstance(stream_settings[key], dict) and not stream_settings[key]:
                         del stream_settings[key]
                 # Remove streamSettings itself if it becomes empty
                 if not stream_settings:
                     del outbound["streamSettings"]
            elif "streamSettings" in outbound: # Remove if present but shouldn't be (e.g., after SS)
                 del outbound["streamSettings"]

            # print(f"DEBUG: Generated Config JSON: {json.dumps(config, indent=2)}")
            return json.dumps(config) # Return compact JSON string
        else:
            return None # Parsing failed

    except Exception as e:
        import traceback
        print(f"DEBUG: Outer error in generate_config for {key_url[:70]}...: {e}")
        print(traceback.format_exc(), file=sys.stderr)
        return None

# --- Key Testing (Proxy Method) ---
def test_v2ray_key(key_url):
    """Tests a single key using Xray in proxy mode and returns (key_url, is_working)."""
    print(f"DEBUG: Starting test for: {key_url[:50]}...")

    # 1. Generate Config
    config_json = generate_config(key_url)
    if not config_json:
        print(f"DEBUG: Test failed (Config generation failed): {key_url[:50]}...")
        return key_url, False

    # 2. Pre-check (Optional but recommended) - Resolve Hostname & Basic Port Check
    try:
        parsed = urlparse(key_url)
        host = parsed.hostname
        # Determine port more reliably
        port = parsed.port
        if not port:
             # Try getting from generated config (more reliable than guessing)
             try:
                 config_data = json.loads(config_json)
                 outbound_settings = config_data.get("outbounds", [{}])[0].get("settings", {})
                 if "vnext" in outbound_settings: # VMess/VLESS
                     port = outbound_settings["vnext"][0].get("port")
                 elif "servers" in outbound_settings: # Trojan/SS
                     port = outbound_settings["servers"][0].get("port")
             except Exception: pass # Ignore errors here, fallback below
             # Fallback to default ports if still not found
             if not port:
                  port = {'vmess': 443, 'vless': 443, 'trojan': 443, 'ss': 8388}.get(parsed.scheme, 443)

        if not host:
            print(f"DEBUG: Test failed (Pre-check: Could not parse hostname): {key_url[:50]}...")
            return key_url, False

        print(f"DEBUG: Pre-checking Host {host}:{port} for {key_url[:30]}...")
        socket.gethostbyname(host) # Resolve DNS
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0) # Slightly longer timeout for basic connect
        s.connect((host, port))
        s.close()
        print(f"DEBUG: Pre-check OK for {host}:{port}")

    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"DEBUG: Test failed (Pre-check failed: {e}): {host}:{port} for {key_url[:30]}...")
        return key_url, False
    except Exception as e:
        print(f"Warning: Error during pre-check for key {key_url[:30]}...: {e}", file=sys.stderr)
        # Don't necessarily fail the test here, let the proxy test decide
        pass

    # 3. Full Test with Xray Proxy
    temp_config_file = None
    xray_proc = None
    is_working = False
    test_start_time = time.time()

    try:
        # Create temp config file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tf:
            tf.write(config_json)
            temp_config_file = tf.name
            # print(f"DEBUG: Xray config for proxy test written to {temp_config_file}")

        # Start Xray process in background
        cmd = [os.path.abspath(XRAY_PATH), "run", "-config", temp_config_file]
        # print(f"DEBUG: Running Xray command: {' '.join(cmd)}")
        xray_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        # Wait briefly for Xray to initialize the proxy
        time.sleep(2.5) # Adjust if needed, 2.5s is usually enough

        # Check if Xray started correctly
        if xray_proc.poll() is not None:
             stderr_output = xray_proc.stderr.read()
             print(f"ERROR: Xray process exited prematurely (Code: {xray_proc.returncode}) for key {key_url[:50]}...", file=sys.stderr)
             print(f"Xray stderr: {stderr_output[:500]}...", file=sys.stderr)
             return key_url, False

        # Define proxies for the test request
        proxies = {
            'http': f'socks5h://127.0.0.1:{PROXY_PORT}', # socks5h for DNS via proxy
            'https': f'socks5h://127.0.0.1:{PROXY_PORT}'
        }

        # --- Perform Test Request(s) ---
        for test_url in TEST_URLS:
            print(f"DEBUG: Attempting request to {test_url} via proxy for {key_url[:30]}...")
            try:
                r = requests.get(test_url, proxies=proxies, timeout=TEST_PROXY_TIMEOUT, headers=REQUEST_HEADERS, verify=False) # Added verify=False
                print(f"DEBUG: Proxy request to {test_url} status: {r.status_code}")
                # Check for successful status codes
                if r.status_code == 204 or (r.status_code == 200 and len(r.content) > 0):
                    is_working = True
                    print(f"DEBUG: Test SUCCESS (Status: {r.status_code}) for {key_url[:50]}...")
                    break # Stop testing URLs if one succeeds
            except requests.exceptions.Timeout:
                 print(f"DEBUG: Proxy request TIMEOUT ({TEST_PROXY_TIMEOUT}s) for {test_url}, key {key_url[:30]}...")
            except requests.exceptions.ProxyError as e:
                 print(f"DEBUG: Proxy request PROXY ERROR ({e}) for {test_url}, key {key_url[:30]}...")
                 # Often indicates Xray couldn't connect outbound or config issue
                 is_working = False # Explicitly set to false on proxy errors
                 break # No point trying other URLs if proxy itself failed
            except requests.exceptions.RequestException as e:
                 print(f"DEBUG: Proxy request FAILED ({e}) for {test_url}, key {key_url[:30]}...")
            # Continue to next test URL if the current one failed (unless it was a ProxyError)

        test_duration = time.time() - test_start_time
        print(f"DEBUG: Test duration: {test_duration:.2f}s for {key_url[:50]}...")
        if not is_working:
             print(f"DEBUG: Test FAILED (No successful response) for {key_url[:50]}...")

        return key_url, is_working

    except FileNotFoundError:
         print(f"ERROR: Xray executable not found at {XRAY_PATH}. Cannot test key {key_url[:50]}...", file=sys.stderr)
         return key_url, False
    except Exception as e:
        # Catch-all for unexpected errors during the test phase
        import traceback
        print(f"ERROR: Unexpected error testing key {key_url[:50]}...: {e}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        return key_url, False
    finally:
        # --- Cleanup ---
        if xray_proc:
            try:
                if xray_proc.poll() is None: # If process is still running
                    print(f"DEBUG: Terminating Xray process (PID: {xray_proc.pid}) for key {key_url[:50]}...")
                    xray_proc.terminate()
                    try: xray_proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                         print(f"DEBUG: Xray (PID: {xray_proc.pid}) did not terminate gracefully, killing...")
                         xray_proc.kill()
                         try: xray_proc.wait(timeout=2)
                         except subprocess.TimeoutExpired: print(f"Warning: Could not kill Xray process (PID: {xray_proc.pid})", file=sys.stderr)
                # Read remaining output? Maybe not necessary unless debugging specific hangs.
                # stdout, stderr = xray_proc.communicate(timeout=1)
                # if stderr: print(f"Xray final stderr: {stderr[:200]}")
            except Exception as e_cleanup:
                print(f"Warning: Error during Xray process cleanup for key {key_url[:50]}: {e_cleanup}", file=sys.stderr)
        if temp_config_file and os.path.exists(temp_config_file):
            try:
                # print(f"DEBUG: Removing temp config file {temp_config_file}")
                os.remove(temp_config_file)
            except OSError as e_rem:
                print(f"Warning: Could not remove temp config file {temp_config_file}: {e_rem}", file=sys.stderr)


# --- Main Execution ---
# Using the flow from user's script with integrated fetching/testing/output
def main():
    start_time = time.time()
    print(f"Starting Merged Key Tester Script at {time.strftime('%Y-%m-%d %H:%M:%S %Z')}") # Added Timezone
    print("="*40)

    # 1. Setup Xray
    print("\n--- Step 1: Setting up Xray ---")
    if not download_and_extract_xray():
        print("FATAL: Failed to get/verify Xray binary. Aborting.", file=sys.stderr); sys.exit(1)
    # Double check existence and executability after download function
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK):
        print(f"FATAL: Xray executable not found or not executable at {os.path.abspath(XRAY_PATH)}. Aborting.", file=sys.stderr); sys.exit(1)
    print(f"Using Xray executable at: {os.path.abspath(XRAY_PATH)}")

    # 2. Ensure output directory exists
    print(f"\n--- Step 2: Preparing Output Directory ({OUTPUT_DIR}) ---")
    try:
        os.makedirs(OUTPUT_DIR, exist_ok=True); print(f"Output directory ensured: {OUTPUT_DIR}")
    except OSError as e:
        print(f"FATAL: Could not create output directory {OUTPUT_DIR}: {e}", file=sys.stderr); sys.exit(1)

    # 3. Fetch Keys from All Sources
    print("\n--- Step 3: Fetching Keys from All Sources ---")
    all_fetched_keys_raw = []
    fetch_errors = 0

    for index, url in enumerate(SOURCE_URLS_LIST):
        print(f"\nFetching from URL {index+1}/{len(SOURCE_URLS_LIST)}: {url}...")
        try:
            # Use a slightly more common UA
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
            response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, allow_redirects=True) # Follow redirects
            response.raise_for_status() # Check for HTTP errors

            # Try decoding with utf-8 first, fall back to apparent_encoding or iso-8859-1
            try:
                raw_data = response.content.decode('utf-8')
            except UnicodeDecodeError:
                 try:
                      raw_data = response.content.decode(response.apparent_encoding)
                      print(f"  Info: Decoded using apparent encoding: {response.apparent_encoding}")
                 except Exception:
                      raw_data = response.content.decode('iso-8859-1', errors='replace')
                      print(f"  Warning: Decoding failed, falling back to iso-8859-1 with replacements.")

            count = 0
            for line in raw_data.splitlines():
                line = line.strip()
                if line: # Ensure line is not empty
                    all_fetched_keys_raw.append(line)
                    count += 1
            print(f" -> Fetched {count} raw lines.")

        except requests.exceptions.Timeout:
            print(f"ERROR: Timeout fetching from {url}", file=sys.stderr); fetch_errors += 1
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed fetching from {url}: {e}", file=sys.stderr); fetch_errors += 1
        except Exception as e:
            print(f"ERROR: An unexpected error occurred while processing {url}: {e}", file=sys.stderr); fetch_errors += 1

    print(f"\nFinished fetching. Processed {len(SOURCE_URLS_LIST)} URLs.")
    if fetch_errors > 0: print(f"Encountered {fetch_errors} errors during fetching.")
    print(f"Fetched a total of {len(all_fetched_keys_raw)} raw lines.")

    # 4. Pre-process keys: Decode base64 if necessary, extract protocols, remove duplicates
    print("\n--- Step 4: Processing and Deduplicating Keys ---")
    unique_keys_to_test = set() # Use set for efficient duplicate checking
    processed_count = 0
    decode_attempts = 0
    unsupported_skips = 0

    for line in all_fetched_keys_raw:
         if any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
              if line not in unique_keys_to_test:
                   unique_keys_to_test.add(line)
                   processed_count +=1
         else:
             # Attempt base64 decode only if it doesn't look like a direct key
             decode_attempts += 1
             try:
                 decoded = base64.b64decode(line + '=' * (-len(line) % 4)).decode('utf-8', errors='replace')
                 # Find all potential keys within the decoded content
                 found_in_decoded = re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>\`]+', decoded)
                 found_new = False
                 for key in found_in_decoded:
                     key = key.strip()
                     if key not in unique_keys_to_test:
                          unique_keys_to_test.add(key)
                          processed_count += 1
                          found_new = True
                 # if found_new: print(f"DEBUG: Found keys in base64: {line[:30]}...")

             except Exception:
                 unsupported_skips += 1 # Ignore lines that are neither direct keys nor valid base64 containing keys

    unique_keys_list = list(unique_keys_to_test) # Convert set back to list for testing
    print(f"Processed {len(all_fetched_keys_raw)} raw lines.")
    print(f"Found {len(unique_keys_list)} unique potential keys after processing.")
    print(f"(Decode attempts: {decode_attempts}, Unsupported/non-key lines skipped: {unsupported_skips})")


    # 5. Test Keys
    print("\n--- Step 5: Testing Keys ---")
    if not unique_keys_list:
         print("No unique keys found to test. Writing empty output file.")
         try:
             with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f: pass # Create empty file
             print(f"Ensured empty file: {OUTPUT_FILE_PATH}")
         except Exception as e_f: print(f"Warning: Could not create empty file {OUTPUT_FILE_PATH}: {e_f}")
         print("Script finished.")
         return

    print(f"Total unique potential keys to test: {len(unique_keys_list)}")
    all_working_keys = []
    tested_count = 0
    start_test_time = time.time()

    print(f"Starting tests using Proxy Method (Max Workers: {MAX_WORKERS}, Test Timeout: {TEST_PROXY_TIMEOUT}s)...")
    # Shuffle the list before testing for better distribution if stopping early
    random.shuffle(unique_keys_list)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_list}
        for future in as_completed(future_to_key):
            key_original = future_to_key[future]
            tested_count += 1
            try:
                _key_returned, is_working = future.result() # Get result from the future
                if is_working:
                    all_working_keys.append(key_original) # Add the original key if it worked
            except Exception as e_res:
                # Log errors from the future/test function itself
                print(f"Warning: Error processing test result for key {key_original[:40]}...: {e_res}", file=sys.stderr);
                pass # Continue to next key

            # Print progress update periodically
            if tested_count % 50 == 0 or tested_count == len(unique_keys_list):
                 elapsed = time.time() - start_test_time
                 rate = tested_count / elapsed if elapsed > 0 else 0
                 print(f"Progress: Tested {tested_count}/{len(unique_keys_list)} keys | Found: {len(all_working_keys)} | Rate: {rate:.1f} keys/s")

            # Optional: Stop testing early if max keys reached
            if len(all_working_keys) >= MAX_TOTAL_KEYS:
                print(f"Reached MAX_TOTAL_KEYS limit ({MAX_TOTAL_KEYS}). Stopping tests early.")
                # Attempt to cancel pending futures (might not always work immediately)
                cancelled_count = 0
                for f in future_to_key:
                    if not f.done():
                        if f.cancel():
                            cancelled_count += 1
                print(f"Attempted to cancel {cancelled_count} pending tests.")
                break # Exit the as_completed loop


    # 6. Write Consolidated Results
    print("\n--- Step 6: Writing Consolidated Results ---")
    num_working_found = len(all_working_keys)
    print(f"Total working keys found: {num_working_found}")

    # Optional: Shuffle the final list before limiting
    random.shuffle(all_working_keys)
    print(f"Shuffled {num_working_found} working keys.")

    # Apply total key limit
    if num_working_found > MAX_TOTAL_KEYS:
        print(f"Limiting output to first {MAX_TOTAL_KEYS} working keys (out of {num_working_found}).")
        keys_to_write = all_working_keys[:MAX_TOTAL_KEYS]
    else:
        keys_to_write = all_working_keys

    num_keys_to_write = len(keys_to_write)

    try:
        # Optional: Sort keys again after limiting/shuffling if desired (e.g., alphabetically)
        # keys_to_write.sort()

        # Write the final list to the single output file
        with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f: # Use newline='\n' for consistency
            for key_to_write in keys_to_write:
                f.write(key_to_write + '\n')
        print(f"Successfully wrote {num_keys_to_write} working keys to {OUTPUT_FILE_PATH}")

    except Exception as e_w:
        print(f"ERROR writing output file {OUTPUT_FILE_PATH}: {e_w}", file=sys.stderr)

    # --- Final Summary ---
    print("\n--- Script Summary ---")
    end_time = time.time()
    total_time = end_time - start_time
    print(f"Total working keys FOUND: {num_working_found}")
    print(f"Total working keys WRITTEN (limit: {MAX_TOTAL_KEYS}): {num_keys_to_write}")
    print(f"Output file: {os.path.abspath(OUTPUT_FILE_PATH)}")
    print(f"Script finished in {total_time:.2f} seconds.")
    print("="*40)

# --- Entry Point ---
if __name__ == "__main__":
    main()
