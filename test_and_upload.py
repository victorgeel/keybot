FILE: test_and_upload.py (Upgraded Full Version)

import requests import subprocess import os import json import tempfile import time import platform import zipfile import io import stat import base64 from urllib.parse import urlparse, parse_qs, unquote, unquote_plus from concurrent.futures import ThreadPoolExecutor, as_completed import sys import socket import re import random

--- Configuration ---

SOURCE_URLS_RAW = os.environ.get('SOURCE_URLS_SECRET', '') SOURCE_URLS_LIST = [url.strip() for url in SOURCE_URLS_RAW.splitlines() if url.strip()]

if not SOURCE_URLS_LIST: print("ERROR: SOURCE_URLS_SECRET is empty or not set.", file=sys.stderr) sys.exit(1) else: print(f"Loaded {len(SOURCE_URLS_LIST)} URLs from SOURCE_URLS_SECRET.")

OUTPUT_DIR = "subscription" OUTPUT_FILENAME = "working_keys.txt" OUTPUT_FILE_PATH = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)

XRAY_PATH = "./xray" MAX_WORKERS = 15 REQUEST_TIMEOUT = 20 TEST_TIMEOUT = 25 MAX_TOTAL_KEYS = 1500 SUPPORTED_PROTOCOLS = ["vmess://", "vless://", "trojan://", "ss://"]

--- Xray Installation ---

def download_and_extract_xray(): if os.path.exists(XRAY_PATH) and os.access(XRAY_PATH, os.X_OK): return True try: api_url = "https://api.github.com/repos/XTLS/Xray-core/releases/latest" headers = {'Accept': 'application/vnd.github.v3+json'} token = os.environ.get('GH_TOKEN') if token: headers['Authorization'] = f'token {token}' response = requests.get(api_url, timeout=REQUEST_TIMEOUT, headers=headers) response.raise_for_status() release_info = response.json() tag = release_info['tag_name']

system = platform.system().lower()
    machine = platform.machine().lower()
    if system == 'linux':
        asset_name = "Xray-linux-64.zip" if machine in ['x86_64', 'amd64'] else "Xray-linux-arm64-v8a.zip"
    else:
        raise ValueError("Unsupported system")

    asset_url = next(a['browser_download_url'] for a in release_info['assets'] if a['name'] == asset_name)
    download_response = requests.get(asset_url, stream=True, timeout=120)
    with zipfile.ZipFile(io.BytesIO(download_response.content)) as zf:
        for member in zf.namelist():
            if member.endswith("xray"):
                zf.extract(member, path=".")
                os.rename(member, XRAY_PATH)
                break
    os.chmod(XRAY_PATH, os.stat(XRAY_PATH).st_mode | stat.S_IEXEC)
    return True
except Exception as e:
    print(f"Xray setup failed: {e}", file=sys.stderr)
    return False

--- Config Generation (as-is from original) ---

Keep your original generate_config() function here (unchanged)

from test_and_upload import generate_config

--- Smart Test Function (latest upgraded version) ---

def test_v2ray_key(key_url): import requests # Smart decode if wrapped if not any(key_url.startswith(proto) for proto in SUPPORTED_PROTOCOLS): try: key_url_decoded = base64.b64decode(key_url.strip() + '=' * (-len(key_url.strip()) % 4)).decode('utf-8', errors='replace') match = re.search(r'(vmess|vless|trojan|ss)://[^\s"']+', key_url_decoded) if match: key_url = match.group(0) except Exception: return key_url, False

config_json = generate_config(key_url)
if not config_json:
    return key_url, False

try:
    parsed = urlparse(key_url.strip())
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return key_url, False
    socket.gethostbyname(host)
    s = socket.socket()
    s.settimeout(1.5)
    s.connect((host, port))
    s.close()
except Exception:
    return key_url, False

temp_config_file = None
xray_proc = None
proxy_port = 10808
is_working = False

try:
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json", encoding='utf-8') as tf:
        tf.write(config_json)
        temp_config_file = tf.name

    xray_proc = subprocess.Popen(
        [XRAY_PATH, "run", "-config", temp_config_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    time.sleep(2.5)
    proxies = {
        'http': f'socks5h://127.0.0.1:{proxy_port}',
        'https': f'socks5h://127.0.0.1:{proxy_port}'
    }

    def proxy_request():
        try:
            r = requests.get("https://www.google.com/generate_204", proxies=proxies, timeout=7)
            return r.status_code == 204
        except:
            return False

    is_working = proxy_request()
    if not is_working:
        time.sleep(1)
        is_working = proxy_request()

    return key_url, is_working
except:
    return key_url, False
finally:
    if xray_proc:
        try:
            xray_proc.kill()
            xray_proc.wait(timeout=3)
        except:
            pass
    if temp_config_file and os.path.exists(temp_config_file):
        try:
            os.remove(temp_config_file)
        except:
            pass

--- Main Execution ---

def main(): if not download_and_extract_xray(): sys.exit(1) os.makedirs(OUTPUT_DIR, exist_ok=True)

all_fetched_keys = []
for url in SOURCE_URLS_LIST:
    try:
        res = requests.get(url, timeout=REQUEST_TIMEOUT)
        res.raise_for_status()
        raw_data = res.text
        for line in raw_data.splitlines():
            line = line.strip()
            if not line:
                continue
            if any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
                all_fetched_keys.append(line)
            else:
                try:
                    decoded = base64.b64decode(line + '=' * (-len(line) % 4)).decode('utf-8', errors='replace')
                    for l in decoded.splitlines():
                        l = l.strip()
                        if any(l.startswith(proto) for proto in SUPPORTED_PROTOCOLS):
                            all_fetched_keys.append(l)
                except:
                    continue
    except Exception as e:
        print(f"Failed fetching {url}: {e}")

print(f"Testing {len(all_fetched_keys)} keys...")
seen = set()
all_fetched_keys = [k for k in all_fetched_keys if k not in seen and not seen.add(k)]

all_working_keys = []
with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
    future_map = {executor.submit(test_v2ray_key, key): key for key in all_fetched_keys}
    for future in as_completed(future_map):
        key, ok = future.result()
        if ok:
            all_working_keys.append(key)

if len(all_working_keys) > MAX_TOTAL_KEYS:
    all_working_keys = all_working_keys[:MAX_TOTAL_KEYS]

with open(OUTPUT_FILE_PATH, 'w', encoding='utf-8') as f:
    for key in all_working_keys:
        f.write(key + '\n')

print(f"Finished. {len(all_working_keys)} working keys saved to {OUTPUT_FILE_PATH}")

if name == "main": main()

