# FILE: test_and_upload.py
# Description: Fetches V2Ray keys, tests them using Xray (Proxy Method),
#              stops testing early when 700 working keys are found,
#              and saves working keys. (Multiple Syntax Fixes Confirmed)

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

XRAY_PATH = "./xray"
print(f"Expected Xray path: {XRAY_PATH}")

MAX_WORKERS = 15
print(f"Max worker threads: {MAX_WORKERS}")

REQUEST_TIMEOUT = 20
print(f"Subscription fetch timeout: {REQUEST_TIMEOUT}s")

TEST_PROXY_TIMEOUT = 10
print(f"Proxy test request timeout: {TEST_PROXY_TIMEOUT}s")

TARGET_EARLY_EXIT_KEYS = 700 # Stop testing when this many working keys are found
print(f"Target working keys to stop testing early: {TARGET_EARLY_EXIT_KEYS}")

SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"]
print(f"Supported protocols: {SUPPORTED_PROTOCOLS}")

PROXY_PORT = 10808
print(f"Local SOCKS proxy port for testing: {PROXY_PORT}")
TEST_URLS = [
    "https://www.google.com/generate_204",
    "http://detectportal.firefox.com/success.txt",
    "http://ip-api.com/json"
]
print(f"Proxy test URLs: {TEST_URLS}")
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 KeyTester/1.8'
}
print(f"Request Headers: {REQUEST_HEADERS}")
print("--- End Configuration ---")

# --- Xray Installation ---
def download_and_extract_xray():
    """Downloads and extracts the latest Xray core binary using GitHub token."""
    print("Checking/Downloading Xray...")
    abs_xray_path = os.path.abspath(XRAY_PATH)
    if os.path.exists(abs_xray_path) and os.access(abs_xray_path, os.X_OK):
         print(f"Xray executable already exists at {abs_xray_path} and is executable. Skipping download.")
         return True
    try:
        api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
        github_token = os.environ.get('GH_TOKEN')
        headers = {'Accept': 'application/vnd.github.v3+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if github_token: headers['Authorization'] = f'Bearer {github_token}'; print("Using GH_TOKEN/GITHUB_TOKEN for GitHub API request.")
        else: print("Warning: GH_TOKEN/GITHUB_TOKEN not found. Making unauthenticated API request.")
        print(f"Fetching latest release info from {api_url}"); response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers); response.raise_for_status()
        release_info = response.json(); tag_name = release_info['tag_name']; print(f"Latest Xray version tag: {tag_name}")
        system = platform.system().lower(); machine = platform.machine().lower(); print(f"Detected System: {system}, Machine: {machine}")
        if system == 'linux':
            if machine in ['x86_64', 'amd64']: asset_name = "Xray-linux-64.zip"
            elif machine in ['aarch64', 'arm64']: asset_name = "Xray-linux-arm64-v8a.zip"
            else: raise ValueError(f"Unsupported Linux architecture: {machine}")
        else: raise ValueError(f"Unsupported operating system: {system}")
        asset_url = None; print(f"Searching for asset: {asset_name}")
        for asset in release_info.get('assets', []):
            if asset.get('name') == asset_name: asset_url = asset.get('browser_download_url'); print(f"Found asset URL: {asset_url}"); break
        if not asset_url: raise ValueError(f"Could not find asset '{asset_name}' in release {tag_name}.")
        print(f"Downloading {asset_url}..."); download_response = requests.get(asset_url, stream=True, timeout=180); download_response.raise_for_status()
        print(f"Extracting {asset_name}...")
        if asset_name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
                exe_name = 'xray.exe' if system == 'windows' else 'xray'; extracted = False
                for member in zf.namelist():
                    if member.endswith(exe_name) and not member.startswith('__MACOSX') and not member.endswith('/'):
                        print(f"  Found executable member: {member}"); zf.extract(member, path="."); extracted_path = os.path.normpath(os.path.join(".", member)); print(f"  Extracted to: {extracted_path}")
                        if os.path.abspath(extracted_path) != abs_xray_path:
                             print(f"  Moving/Renaming from {extracted_path} to {abs_xray_path}..."); os.makedirs(os.path.dirname(abs_xray_path) or '.', exist_ok=True)
                             if os.path.exists(abs_xray_path) or os.path.islink(abs_xray_path): print(f"  Removing existing file/link at {abs_xray_path}"); os.remove(abs_xray_path)
                             os.rename(extracted_path, abs_xray_path)
                        member_dir = os.path.dirname(member)
                        if member_dir and os.path.exists(os.path.join(".", member_dir)) and not os.listdir(os.path.join(".", member_dir)):
                            try: os.rmdir(os.path.join(".", member_dir)); print(f"  Removed empty source directory: {os.path.join('.', member_dir)}")
                            except OSError as rmdir_e: print(f"  Warning: Could not remove source directory {os.path.join('.', member_dir)}: {rmdir_e}")
                        print(f"  Xray executable placed at '{abs_xray_path}'"); extracted = True; break
                if not extracted: raise FileNotFoundError(f"'{exe_name}' executable not found in {asset_name}. Contents: {zf.namelist()}")
        else: raise NotImplementedError(f"Extraction not implemented for asset type: {asset_name}")
        if not os.path.exists(abs_xray_path): raise FileNotFoundError(f"Xray executable not found at '{abs_xray_path}' after extraction attempt.")
        if system != 'windows':
            try:
                print(f"Setting execute permissions for '{abs_xray_path}'..."); st_mode = os.stat(abs_xray_path).st_mode; new_mode = st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
                if st_mode != new_mode: os.chmod(abs_xray_path, new_mode); print(f"Permissions set to {oct(new_mode)}.")
                else: print("Execute permission already set.")
                if not os.access(abs_xray_path, os.X_OK): raise OSError("Execute permission check failed.")
            except Exception as chmod_e:
                print(f"ERROR: Failed to make '{abs_xray_path}' executable: {chmod_e}", file=sys.stderr)
                try: print("Attempting fallback chmod command..."); subprocess.run(['chmod', '+x', abs_xray_path], check=True); print("Fallback chmod +x succeeded.")
                except Exception as fallback_e: print(f"ERROR: Fallback chmod failed: {fallback_e}.", file=sys.stderr); return False
        print(f"Verifying Xray installation: {abs_xray_path} version")
        try:
            version_process = subprocess.run([abs_xray_path, "version"], capture_output=True, text=True, timeout=15, check=False, encoding='utf-8', errors='replace')
            print(f"--- XRAY VERSION OUTPUT ---"); print(f"Command: {abs_xray_path} version"); print(f"Exit Code: {version_process.returncode}"); stdout_strip = version_process.stdout.strip() if version_process.stdout else ""; stderr_strip = version_process.stderr.strip() if version_process.stderr else ""; print(f"Stdout: {stdout_strip}");
            if stderr_strip: print(f"Stderr: {stderr_strip}"); print(f"--- END XRAY VERSION OUTPUT ---")
            if version_process.returncode != 0 or "Xray" not in stdout_strip: print("Warning: Xray version command failed or output unexpected.", file=sys.stderr)
            else: print("Xray version verified successfully.")
        except subprocess.TimeoutExpired: print(f"ERROR: Timeout running '{abs_xray_path} version'.", file=sys.stderr); return False
        except FileNotFoundError: print(f"ERROR: Cannot execute '{abs_xray_path}'.", file=sys.stderr); return False
        except Exception as verify_e: print(f"ERROR: Xray verification failed: {verify_e}", file=sys.stderr); return False
        print("Xray download and setup appears complete."); return True
    except requests.exceptions.RequestException as req_e: print(f"ERROR: Xray download network error: {req_e}", file=sys.stderr); return False
    except zipfile.BadZipFile as zip_e: print(f"ERROR: Invalid ZIP file: {zip_e}", file=sys.stderr); return False
    except (ValueError, NotImplementedError, FileNotFoundError, OSError) as setup_e: print(f"ERROR: Xray setup failed: {setup_e}", file=sys.stderr); return False
    except Exception as e: print(f"ERROR: Unexpected error in download_and_extract_xray: {e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return False


# --- Config Generation (with SS Parsing Fix) ---
def generate_config(key_url):
    """Generates an Xray JSON configuration for proxy testing."""
    try:
        key_url = key_url.strip();
        if not key_url or '://' not in key_url: return None
        parsed_url = urlparse(key_url); protocol = parsed_url.scheme
        base_config = {"log": {"loglevel": "warning"},"inbounds": [{"port": PROXY_PORT,"protocol": "socks","settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},"listen": "127.0.0.1"}],"outbounds": [{"protocol": protocol, "settings": {}, "streamSettings": {}}]}
        outbound = base_config["outbounds"][0]; stream_settings = outbound["streamSettings"]; config = None
        # --- VMess ---
        if protocol == "vmess":
            try:
                vmess_b64 = key_url[len("vmess://"):]; vmess_b64 += '=' * (-len(vmess_b64) % 4)
                vmess_params = json.loads(base64.b64decode(vmess_b64).decode('utf-8', errors='replace'))
                address = vmess_params.get("add"); port = int(vmess_params.get("port", 443)); user_id = vmess_params.get("id")
                if not address or not user_id: return None
                alter_id = int(vmess_params.get("aid", 0)); security = vmess_params.get("scy", "auto"); net_type = vmess_params.get("net", "tcp"); tls_setting = vmess_params.get("tls", "none"); sni_val = vmess_params.get("sni", vmess_params.get("host", "")); host_val = vmess_params.get("host", ""); path_val = vmess_params.get("path", "/"); header_type = vmess_params.get("type", "none")
                outbound["settings"]["vnext"] = [{"address": address,"port": port,"users": [{"id": user_id, "alterId": alter_id, "security": security}]}]
                stream_settings["network"] = net_type; stream_settings["security"] = tls_setting
                if tls_setting == "tls": effective_sni = sni_val if sni_val else (host_val if host_val else address); stream_settings["tlsSettings"] = {"serverName": effective_sni, "allowInsecure": False}
                if net_type == "ws": effective_ws_host = host_val if host_val else address; stream_settings["wsSettings"] = {"path": path_val, "headers": {"Host": effective_ws_host}}
                elif net_type == "tcp" and header_type == "http": host_list = [h.strip() for h in host_val.split(',') if h.strip()] or [address]; stream_settings["tcpSettings"] = {"header": {"type": "http", "request": {"path": [path_val], "headers": {"Host": host_list}}}}
                elif net_type == "grpc": service_name = vmess_params.get("path", ""); mode = vmess_params.get("mode", "gun"); stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode == "multi"}
                config = base_config
            except (json.JSONDecodeError, ValueError, KeyError, base64.binascii.Error) as e: print(f"DEBUG: VMess FAIL (Parsing/Decode Error: {e}): {key_url[:70]}..."); return None
            except Exception as e_vmess: print(f"DEBUG: VMess FAIL (Unexpected Error: {e_vmess}): {key_url[:70]}..."); traceback.print_exc(file=sys.stderr); return None
        # --- VLESS ---
        elif protocol == "vless":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None
                uuid = parsed_url.username; address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query); flow = params.get('flow', [None])[0] or ""; encryption = 'none'
                outbound["settings"]["vnext"] = [{"address": address,"port": port,"users": [{"id": uuid, "flow": flow, "encryption": encryption}]}]
                net_type = params.get('type', ['tcp'])[0]; sec_type = params.get('security', ['none'])[0]; sni = params.get('sni', params.get('peer', [address]))[0]; fingerprint = params.get('fp', [''])[0]; allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'
                stream_settings["network"] = net_type; stream_settings["security"] = sec_type
                if sec_type == "tls":
                    alpn = params.get('alpn', [None])[0]; tls_settings = {"serverName": sni, "allowInsecure": allow_insecure}; stream_settings.pop("realitySettings", None)
                    if fingerprint: tls_settings["fingerprint"] = fingerprint
                    if alpn: tls_settings["alpn"] = [p.strip() for p in alpn.split(',') if p.strip()]
                    stream_settings["tlsSettings"] = tls_settings
                elif sec_type == "reality":
                    pbk = params.get('pbk', [''])[0]; sid = params.get('sid', [''])[0]; spx = unquote_plus(params.get('spx', ['/'])[0]); stream_settings.pop("tlsSettings", None)
                    if not pbk or not sid: return None
                    reality_server_name = sni if sni else address; reality_fp = fingerprint if fingerprint else "chrome"; stream_settings["realitySettings"] = {"serverName": reality_server_name,"fingerprint": reality_fp,"shortId": sid,"publicKey": pbk,"spiderX": spx}
                else: stream_settings.pop("tlsSettings", None); stream_settings.pop("realitySettings", None)
                host = params.get('host', [address])[0]; path = unquote_plus(params.get('path', ['/'])[0]); service_name = unquote_plus(params.get('serviceName', [''])[0]); mode = params.get('mode', ['gun'])[0]
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc": stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode == "multi"}
                elif net_type == "tcp" and params.get('headerType', ['none'])[0] == 'http': host_list = [h.strip() for h in host.split(',') if h.strip()] or [address]; path_list = [path]; stream_settings["tcpSettings"] = {"header": {"type": "http", "request": {"path": path_list, "headers": {"Host": host_list}}}}
                config = base_config
            except Exception as e_vless: print(f"DEBUG: VLESS FAIL (Unexpected Error: {e_vless}): {key_url[:70]}..."); traceback.print_exc(file=sys.stderr); return None
        # --- Trojan ---
        elif protocol == "trojan":
            try:
                if not parsed_url.username or not parsed_url.hostname: return None
                password = unquote_plus(parsed_url.username); address = parsed_url.hostname; port = int(parsed_url.port or 443); params = parse_qs(parsed_url.query)
                outbound["settings"]["servers"] = [{"address": address, "port": port, "password": password}]
                net_type = params.get('type', ['tcp'])[0]
                sec_type = params.get('security', ['tls'])[0]
                if sec_type == 'none': sec_type = 'tls'
                sni = params.get('sni', params.get('peer', [address]))[0]; fingerprint = params.get('fp', [''])[0]; allow_insecure = params.get('allowInsecure', ['0'])[0] == '1'; alpn = params.get('alpn', [None])[0]
                stream_settings["network"] = net_type; stream_settings["security"] = sec_type
                if sec_type == "tls":
                    tls_settings = {"serverName": sni, "allowInsecure": allow_insecure}
                    if fingerprint: tls_settings["fingerprint"] = fingerprint
                    if alpn: tls_settings["alpn"] = [p.strip() for p in alpn.split(',') if p.strip()]
                    stream_settings["tlsSettings"] = tls_settings
                elif sec_type != "none":
                    stream_settings["security"] = "tls"; tls_settings = {"serverName": sni, "allowInsecure": allow_insecure}
                    if fingerprint: tls_settings["fingerprint"] = fingerprint
                    if alpn: tls_settings["alpn"] = [p.strip() for p in alpn.split(',') if p.strip()]
                    stream_settings["tlsSettings"] = tls_settings
                host = params.get('host', [address])[0]; path = unquote_plus(params.get('path', ['/'])[0]); service_name = unquote_plus(params.get('serviceName', [''])[0]); mode = params.get('mode', ['gun'])[0]
                if net_type == "ws": stream_settings["wsSettings"] = {"path": path, "headers": {"Host": host}}
                elif net_type == "grpc": stream_settings["grpcSettings"] = {"serviceName": service_name, "multiMode": mode=="multi"}
                elif net_type == "tcp" and params.get('headerType', ['none'])[0] == 'http': host_list = [h.strip() for h in host.split(',') if h.strip()] or [address]; path_list = [path]; stream_settings["tcpSettings"] = {"header": {"type": "http","request": { "path": path_list, "headers": { "Host": host_list } }}}
                config = base_config
            except Exception as e_trojan: print(f"DEBUG: Trojan FAIL (Unexpected Error: {e_trojan}): {key_url[:70]}..."); traceback.print_exc(file=sys.stderr); return None
        # --- Shadowsocks (SS) ---
        elif protocol == "ss":
            try:
                password = None; method = None; address = None; port = None; remark = None
                if '#' in key_url: key_url_no_remark, remark = key_url.split('#', 1)
                else: key_url_no_remark = key_url
                link_part = key_url_no_remark[len("ss://"):]
                if '@' in link_part:
                    user_info, host_info = link_part.split('@', 1)
                    host_part = host_info
                    if '?' in host_info: host_part, _ = host_info.split('?', 1)
                    if ':' not in host_part: print(f"DEBUG: SS FAIL (host_part missing port): {host_part} in {key_url[:70]}"); return None
                    address, port_str = host_part.rsplit(':', 1)
                    try: port = int(port_str)
                    except ValueError: print(f"DEBUG: SS FAIL (invalid port): {port_str} in {key_url[:70]}"); return None
                    try:
                        user_info_padded = user_info + '=' * (-len(user_info) % 4); decoded_user_info = base64.urlsafe_b64decode(user_info_padded).decode('utf-8', errors='replace')
                        if ':' in decoded_user_info: method, password = decoded_user_info.split(':', 1)
                        else: raise ValueError("Decoded Base64 user info lacks colon")
                    except Exception:
                         if ':' in user_info: method, password = user_info.split(':', 1)
                         else: print(f"DEBUG: SS FAIL (Invalid user info format): {user_info} in {key_url[:70]}"); return None
                else: # Format 3
                     try:
                         full_b64 = link_part + '=' * (-len(link_part) % 4); decoded_full = base64.urlsafe_b64decode(full_b64).decode('utf-8', errors='replace')
                         if '@' in decoded_full and ':' in decoded_full.split('@')[0] and ':' in decoded_full.split('@')[1]:
                              user_info_part, server_part = decoded_full.split('@', 1)
                              host_part_decoded = server_part
                              if '?' in server_part: host_part_decoded, _ = server_part.split('?', 1)
                              if ':' not in host_part_decoded: print(f"DEBUG: SS FAIL (decoded host_part missing port): {host_part_decoded} in {key_url[:70]}"); return None
                              method, password = user_info_part.split(':', 1)
                              address, port_str = host_part_decoded.rsplit(':', 1)
                              port = int(port_str)
                         else: print(f"DEBUG: SS FAIL (Decoded Base64 (Format 3) wrong structure): {decoded_full[:50]}... in {key_url[:70]}"); return None
                     except ValueError: print(f"DEBUG: SS FAIL (Invalid port in decoded Base64): {port_str} in {key_url[:70]}"); return None
                     except Exception as e_ss3: print(f"DEBUG: SS FAIL (Failed to decode/parse Format 3 Base64: {e_ss3}): {key_url[:70]}"); return None
                if not all([password is not None, method, address, port is not None]): print(f"DEBUG: SS FAIL (Extraction failed - missing parts): {key_url[:70]}"); return None
                outbound["settings"]["servers"] = [{"address": address,"port": port,"method": method,"password": password,"uot": True}]; stream_settings["network"] = "tcp"; stream_settings["security"] = "none"
                for key in ["tlsSettings", "realitySettings", "wsSettings", "grpcSettings", "tcpSettings", "kcpSettings", "quicSettings"]: stream_settings.pop(key, None)
                config = base_config
            except Exception as e_ss: print(f"DEBUG: SS FAIL (Unexpected Error: {e_ss}): {key_url[:70]}..."); traceback.print_exc(file=sys.stderr); return None
        else: return None

        if config:
            if outbound.get("streamSettings"):
                 for key in list(stream_settings.keys()):
                     if isinstance(stream_settings[key], dict) and not stream_settings[key]: del stream_settings[key]
                 if not stream_settings: outbound.pop("streamSettings", None)
            elif "streamSettings" in outbound and protocol == "ss": outbound.pop("streamSettings", None)
            return json.dumps(config)
        else: return None
    except Exception as e: print(f"ERROR: Outer error in generate_config: {e}", file=sys.stderr); traceback.print_exc(file=sys.stderr); return None


# --- Key Testing (Proxy Method with Enhanced Debugging) ---
def test_v2ray_key(key_url):
    """Tests a single key using Xray in proxy mode and returns (key_url, is_working)."""
    config_json = generate_config(key_url)
    if not config_json: return key_url, False # Config gen failed

    host = None; port = None
    try: # Pre-check block
        parsed = urlparse(key_url); host = parsed.hostname; port = parsed.port
        if not port:
             try: config_data = json.loads(config_json); outbound_settings = config_data.get("outbounds", [{}])[0].get("settings", {})
             except Exception: outbound_settings = {}
             if "vnext" in outbound_settings: port = outbound_settings.get("vnext", [{}])[0].get("port")
             elif "servers" in outbound_settings: port = outbound_settings.get("servers", [{}])[0].get("port")
             if not port: port = {'vmess': 443, 'vless': 443, 'trojan': 443, 'ss': 8388}.get(parsed.scheme, 443)
        if not host: return key_url, False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(3.0); s.connect((host, port)); s.close()
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError): pass # Don't fail here
    except Exception as e_pre_other: print(f"Warning: Pre-check error {key_url[:30]}: {e_pre_other}", file=sys.stderr); pass

    temp_config_file = None; xray_proc = None; is_working = False
    xray_stderr_output = ""
    final_fail_reason = "Unknown Test Failure"

    try: # Main test block
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".xray.json", encoding='utf-8') as tf:
            tf.write(config_json); temp_config_file = tf.name
        cmd = [os.path.abspath(XRAY_PATH), "run", "-config", temp_config_file]
        # Use start_new_session=True to create a process group for easier termination
        xray_proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', start_new_session=True)
        time.sleep(2.5) # Wait for xray to start

        if xray_proc.poll() is not None: # Check if xray exited early
             try: xray_stderr_output = xray_proc.stderr.read()
             except Exception: pass
             final_fail_reason = f"Xray exited early (Code: {xray_proc.returncode})"
             return key_url, False

        proxies = {'http': f'socks5h://127.0.0.1:{PROXY_PORT}','https': f'socks5h://127.0.0.1:{PROXY_PORT}'}
        req_exception = None
        status_code = None

        for test_url in TEST_URLS:
            try:
                r = requests.get(test_url, proxies=proxies, timeout=TEST_PROXY_TIMEOUT, headers=REQUEST_HEADERS, verify=False, stream=False)
                status_code = r.status_code
                if r.status_code == 204 or (r.status_code == 200 and len(r.text) > 0):
                    is_working = True; final_fail_reason = ""; break # Success
                else:
                    final_fail_reason = f"Request failed (Status: {status_code} on {test_url})"
            except requests.exceptions.Timeout as e:
                 final_fail_reason = f"Request TIMEOUT on {test_url}"; req_exception = e; pass
            except requests.exceptions.ProxyError as e:
                 final_fail_reason = f"Request PROXY ERROR on {test_url}"; req_exception = e; is_working = False; break
            except requests.exceptions.RequestException as e:
                 final_fail_reason = f"Request FAILED on {test_url}"; req_exception = e; pass

        return key_url, is_working

    except FileNotFoundError: final_fail_reason = f"Xray execution failed (Not Found)"; print(f"ERROR: {final_fail_reason} at {os.path.abspath(XRAY_PATH)}", file=sys.stderr); return key_url, False
    except Exception as e_test: final_fail_reason = f"Unexpected test error: {e_test}"; print(f"ERROR: {final_fail_reason} Key: {key_url[:50]}...", file=sys.stderr); traceback.print_exc(file=sys.stderr); return key_url, False
    finally: # Cleanup
        if xray_proc:
            pid = xray_proc.pid
            if xray_proc.poll() is None:
                # print(f"DEBUG: Terminating Xray PID {pid} for Key: {key_url[:50]}...")
                try:
                    # Kill process group using signal
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                    time.sleep(0.2) # Shorter sleep
                    if xray_proc.poll() is None:
                         os.killpg(os.getpgid(pid), signal.SIGKILL)
                except (ProcessLookupError, PermissionError, AttributeError): # Fallback for non-Linux or errors
                     try: xray_proc.terminate(); xray_proc.wait(timeout=0.5)
                     except Exception:
                          try: xray_proc.kill(); xray_proc.wait(timeout=0.5)
                          except Exception: pass # Ignore final cleanup errors
            # Capture final stderr only if test failed
            if not is_working:
                try:
                    stderr_final = ""
                    if xray_proc.stderr: stderr_final = xray_proc.stderr.read()
                    # Use final stderr if available, otherwise keep early exit stderr if captured
                    xray_stderr_output = stderr_final.strip() if stderr_final else xray_stderr_output
                except Exception: pass # Ignore errors reading stderr

        # Print failure details only if it failed
        if not is_working:
             # Shorten the key URL in debug message for readability
             print(f"DEBUG: Test FAIL Key: {key_url[:50]}... Reason: {final_fail_reason}", file=sys.stderr)
             if xray_stderr_output and "signal: terminated" not in xray_stderr_output.lower() and "signal: killed" not in xray_stderr_output.lower():
                  # Print only first few lines of stderr to avoid flooding logs
                  stderr_lines = xray_stderr_output.splitlines()
                  print(f"DEBUG: Xray Stderr: {' | '.join(stderr_lines[:3])}"[:500] + "...", file=sys.stderr)

        if temp_config_file and os.path.exists(temp_config_file):
            try: os.remove(temp_config_file)
            except Exception: pass


# --- Main Execution Logic ---
def main():
    script_start_time = time.time()
    print(f"\n=== Starting Key Tester Script at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} ===")

    # --- Step 1: Setup Xray ---
    print("\n--- Step 1: Setting up Xray ---")
    if not download_and_extract_xray(): print("FATAL: Failed to setup Xray.", file=sys.stderr); sys.exit(1)
    if not os.path.exists(XRAY_PATH) or not os.access(XRAY_PATH, os.X_OK): print(f"FATAL: Xray not ready at {os.path.abspath(XRAY_PATH)}.", file=sys.stderr); sys.exit(1)
    print(f"Confirmed Xray executable: {os.path.abspath(XRAY_PATH)}")

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
            # Corrected multi-line loop structure for processing lines
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
                 decoded = base64.b64decode(line + '=' * (-len(line) % 4)).decode('utf-8', errors='replace')
                 found_keys_in_line = re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>\`]+', decoded)
                 if found_keys_in_line:
                      # Corrected multi-line loop structure for processing keys within base64
                      for key in found_keys_in_line:
                          key = key.strip()
                          if key not in unique_keys_to_test:
                              unique_keys_to_test.add(key)
                              processed_count += 1
                              base64_decoded_keys += 1
             except Exception: unsupported_skips += 1
    unique_keys_list = list(unique_keys_to_test)
    print(f"Processed {len(all_fetched_keys_raw)} lines. Found {len(unique_keys_list)} unique potential keys.")
    print(f"(Base64 attempts: {decode_attempts}, Keys in Base64: {base64_decoded_keys}, Skipped lines: {unsupported_skips})")

    # --- Step 5: Test Keys with Early Exit ---
    print("\n--- Step 5: Testing Keys ---")
    if not unique_keys_list: print("No unique valid keys found. Writing empty file."); try: open(OUTPUT_FILE_PATH, 'w').close(); print(f"Created empty: {OUTPUT_FILE_PATH}"); except IOError as e_f: print(f"Warning: Cannot create empty file: {e_f}", file=sys.stderr); sys.exit(0)
    print(f"Starting tests for {len(unique_keys_list)} keys (will stop early at {TARGET_EARLY_EXIT_KEYS} working)..."); print(f"(Max Workers: {MAX_WORKERS}, Proxy Test Timeout: {TEST_PROXY_TIMEOUT}s)")
    all_working_keys = []; tested_count = 0; start_test_time = time.time(); futures_cancelled = 0; stop_early = False
    random.shuffle(unique_keys_list)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_key = {executor.submit(test_v2ray_key, key): key for key in unique_keys_list}
        active_futures = list(future_to_key.keys())
        for future in as_completed(active_futures):
            if stop_early:
                if not future.done(): future.cancel()
                continue
            key_original = future_to_key[future]; tested_count += 1
            try:
                _key_returned, is_working = future.result()
                if is_working:
                    all_working_keys.append(key_original); found_count = len(all_working_keys)
                    if found_count >= TARGET_EARLY_EXIT_KEYS:
                        if not stop_early:
                            stop_early = True; print(f"\nTarget of {TARGET_EARLY_EXIT_KEYS} working keys reached! Stopping testing early."); print("Attempting to cancel remaining pending tests...")
                            cancelled_now = 0
                            for f in active_futures:
                                if not f.done():
                                    if f.cancel(): cancelled_now += 1
                            futures_cancelled = cancelled_now; print(f"Attempted to cancel {futures_cancelled} tests.")
            except Exception as e_future: print(f"\nWarning: Error processing test result for key {key_original[:40]}...: {e_future}", file=sys.stderr)
            if tested_count % 50 == 0 or tested_count == len(unique_keys_list) or stop_early:
                 current_time = time.time(); elapsed = current_time - start_test_time; rate = tested_count / elapsed if elapsed > 0 else 0
                 progress_message = f"Progress: Tested {tested_count}/{len(unique_keys_list)} | Found: {len(all_working_keys)} | Rate: {rate:.1f} keys/s | Elapsed: {elapsed:.0f}s"
                 if stop_early: progress_message += " (Stopping Early)"
                 print(progress_message, end='\n' if stop_early or tested_count == len(unique_keys_list) else '\r')
            if stop_early: break
    print(); print(f"Finished testing phase. Tested {tested_count} keys."); test_duration = time.time() - start_test_time; print(f"Total testing time: {test_duration:.2f} seconds.")

    # --- Step 6: Write Results ---
    print("\n--- Step 6: Writing Results ---")
    num_working_found = len(all_working_keys); print(f"Total working keys collected: {num_working_found} (Target was {TARGET_EARLY_EXIT_KEYS})")
    random.shuffle(all_working_keys); print(f"Shuffled {num_working_found} working keys.")
    if num_working_found > TARGET_EARLY_EXIT_KEYS: print(f"Limiting final output to {TARGET_EARLY_EXIT_KEYS} keys."); keys_to_write = all_working_keys[:TARGET_EARLY_EXIT_KEYS]
    else: keys_to_write = all_working_keys
    num_keys_to_write = len(keys_to_write); print(f"Number of keys to write to file: {num_keys_to_write}")
    try:
        with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8', newline='\n') as f:
            for key_to_write in keys_to_write: f.write(key_to_write + '\n')
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
        # Consider adding logic here to stop the thread pool if needed
        sys.exit(1)
    try:
        signal.signal(signal.SIGINT, handle_signal) # Handle Ctrl+C
        signal.signal(signal.SIGTERM, handle_signal) # Handle termination signal
    except (AttributeError, ValueError, OSError) as e_signal:
        # Catch errors if signal module is not available or setting fails
        print(f"Warning: Could not set signal handlers ({e_signal}).")
        pass

    main()
