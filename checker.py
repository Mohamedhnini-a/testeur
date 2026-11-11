import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
import threading
import random
from urllib.parse import parse_qs, unquote, urlparse
import requests

SOURCE_URLS = [
    "sub.txt"
]
XRAY = "./xray/xray"

TEST_URLS = [
    "https://www.youtube.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]

TIMEOUT = 15
MAX_WORKERS = 50 # ✅ زدنا العدد باش يمشي أسرع
BASE_PORT = 20000
MAX_LATENCY_MS = 5000

_tls = threading.local()
def get_session():
    if not hasattr(_tls, "s"):
        s = requests.Session()
        s.trust_env = False
        _tls.s = s
    return _tls.s

def test_once(proxies):
    last_error = None
    session = get_session()
    for url in TEST_URLS:
        try:
            start = time.perf_counter()
            response = session.get(url, proxies=proxies, timeout=TIMEOUT, allow_redirects=False)
            elapsed = (time.perf_counter() - start) * 1000
            if response.status_code in (200, 204):
                return round(elapsed), None
            last_error = f"http_{response.status_code}"
            if 500 <= response.status_code < 600:
                continue
            return None, last_error
        except requests.exceptions.Timeout:
            last_error = "timeout"
        except requests.exceptions.ProxyError:
            return None, "proxy_error"
        except Exception as e:
            last_error = type(e).__name__
    return None, last_error

def download_configs():
    configs = []
    for source_url in SOURCE_URLS:
        try:
            # يلا كان رابط http أو https
            if source_url.startswith("http://") or source_url.startswith("https://"):
                print(f"Downloading: {source_url}", flush=True)
                response = requests.get(source_url, timeout=20)
                response.raise_for_status()
                configs.extend([line.strip() for line in response.text.splitlines() if line.strip()])
            # يلا كان ملف محلي (بحال sub.txt)
            else:
                print(f"Reading local file: {source_url}", flush=True)
                with open(source_url, "r", encoding="utf-8") as f:
                    configs.extend([line.strip() for line in f.readlines() if line.strip()])
        except Exception as e:
            print(f"FAILED to load {source_url}: {e}", flush=True)
    return list(dict.fromkeys(configs))

def parse_config(line):
    try:
        if line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0].strip()
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            config = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            return {
                "protocol": "vmess", "server": config.get("add"), "port": int(config.get("port", 443)),
                "id": config.get("id"), "aid": int(config.get("aid", 0)), "scy": config.get("scy", "auto"),
                "net": config.get("net", "tcp"), "tls": config.get("tls", ""), "host": config.get("host", ""),
                "sni": config.get("sni", ""), "path": config.get("path", "/"), "original": line,
            }

        if line.startswith("vless://") or line.startswith("trojan://"):
            parsed = urlparse(line)
            params = parse_qs(parsed.query, keep_blank_values=True)
            get = lambda name: params.get(name, [""])[0]
            return {
                "protocol": parsed.scheme.lower(), "server": parsed.hostname, "port": parsed.port or 443,
                "uuid": parsed.username, "password": parsed.username, "net": get("type") or "tcp",
                "security": get("security") or "none", "sni": get("sni") or parsed.hostname,
                "host": get("host") or "", "path": unquote(get("path")) or "/", "alpn": get("alpn") or "",
                "fp": get("fp") or "", "pbk": get("pbk") or "", "sid": get("sid") or "",
                "spx": get("spx") or "/", "flow": get("flow") or "", "original": line,
            }
    except Exception:
        return None
    return None

def make_xray_config(config, local_port):
    stream_settings = {"network": config.get("net", "tcp"), "security": config.get("security", config.get("tls") or "none")}
    
    if stream_settings["security"] == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": config.get("sni") or config.get("server"), 
            "allowInsecure": False,
            "fingerprint": config.get("fp") or "chrome" # ✅ فرض بصمة chrome إلا ما كانتش
        }
        if config.get("alpn"): 
            stream_settings["tlsSettings"]["alpn"] = config["alpn"].split(",")
            
    elif stream_settings["security"] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": config.get("sni") or config.get("server"), 
            "fingerprint": config.get("fp") or "chrome",
            "publicKey": config.get("pbk"), "shortId": config.get("sid"), "spiderX": config.get("spx"),
        }

    net = config.get("net", "tcp")
    if net == "ws":
        stream_settings["wsSettings"] = {
            "path": config.get("path", "/"), 
            "host": config.get("host") or config.get("sni"),
            "heartbeatPeriod": 10 # ✅ إضافة heartbeat باش يبقى الاتصال ثابت
        }
        # ✅ إجبار ALPN على http/1.1 فـ حال WebSocket + TLS
        if stream_settings["security"] == "tls":
            if "tlsSettings" not in stream_settings: stream_settings["tlsSettings"] = {}
            stream_settings["tlsSettings"]["alpn"] = ["http/1.1"]
            
    elif net == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": config.get("path")}

    if config["protocol"] == "vless":
        user = {"id": config["uuid"], "encryption": "none"}
        if config.get("flow"): user["flow"] = config["flow"]
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": config["server"], "port": config["port"], "users": [user]}]}, "streamSettings": stream_settings}
    elif config["protocol"] == "trojan":
        outbound = {"protocol": "trojan", "settings": {"servers": [{"address": config["server"], "port": config["port"], "password": config["password"]}]}, "streamSettings": stream_settings}
    elif config["protocol"] == "vmess":
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": config["server"], "port": config["port"], "users": [{"id": config["id"], "alterId": config["aid"], "security": config["scy"]}]}]}, "streamSettings": stream_settings}
    else: return None

    return {"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "http", "settings": {}}], "outbounds": [outbound]}

def test_config(index, config):
    # ✅ إدارة منافذ عشوائية باش نتفاداو التعارض بين الثريدات
    local_port = random.randint(20000, 60000)
    config_file, log_file, process = None, None, None
    
    try:
        xray_config = make_xray_config(config, local_port)
        if not xray_config: return {"ok": False, "reason": "make_failed"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(xray_config, f)
            config_file = f.name

        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
        with open(log_file, "w") as log_handle:
            process = subprocess.Popen([XRAY, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=log_handle, start_new_session=True)

        started = False
        for _ in range(15):
            if process.poll() is not None: break
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.3): pass
                started = True
                break
            except OSError: time.sleep(0.1)

        if not started: 
            # ✅ قراءة اللوغ باش نعرفو علاش طاح
            err_details = "unknown"
            if os.path.exists(log_file):
                with open(log_file, "r") as lf:
                    err_details = lf.read().strip().split('\n')[-1][:100] 
            return {"ok": False, "reason": f"xray_died: {err_details}"}

        proxies = {"http": f"http://127.0.0.1:{local_port}", "https": f"http://127.0.0.1:{local_port}"}
        latency, err = test_once(proxies)
        
        if latency is not None and latency <= MAX_LATENCY_MS:
            return {"ok": True, "latency": latency, "line": config["original"], "server": config["server"]}
        return {"ok": False, "reason": err, "server": config["server"]}

    except Exception as e:
        return {"ok": False, "reason": str(type(e).__name__), "server": config["server"]}
    finally:
        if process:
            try: process.terminate(); process.wait(timeout=0.5)
            except: 
                try: process.kill()
                except: pass
        for path in (config_file, log_file):
            if path and os.path.exists(path):
                try: os.remove(path)
                except: pass

def main():
    print("Downloading configs...", flush=True)
    lines = download_configs()
    configs = [c for c in (parse_config(l) for l in lines) if c]
    total = len(configs)
    print(f"\n✅ Total configs to test: {total}\n", flush=True)

    if not configs: return

    tasks = list(enumerate(configs, start=1))
    results = []
    completed = 0
    working_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        iterator = iter(tasks)
        pending = set()
        for _ in range(MAX_WORKERS):
            try: pending.add(executor.submit(test_config, *next(iterator)))
            except StopIteration: break

        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                completed += 1
                try:
                    res = future.result()
                    if res.get("ok"):
                        working_count += 1
                        results.append(res)
                        print(f"[ONLINE] {res['latency']}ms | {res['server']}", flush=True)
                    else:
                        print(f"[FAILED] {res.get('server')} | {res.get('reason')}", flush=True)
                except Exception as e: 
                    pass
                
                if completed % 10 == 0 or completed == total:
                    print(f"--- [Progress] {completed}/{total} | Working: {working_count} | Remaining: {total - completed} ---", flush=True)

                try: pending.add(executor.submit(test_config, *next(iterator)))
                except StopIteration: pass

    results.sort(key=lambda x: x["latency"])

    with open("working.txt", "w", encoding="utf-8") as f:
        for r in results:
            f.write(r["line"] + "\n")

    print(f"\n✅ Done! Saved {len(results)} working configs to working.txt", flush=True)

if __name__ == "__main__":
    main()
