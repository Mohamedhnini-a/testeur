import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
import threading
from statistics import median
from urllib.parse import parse_qs, unquote, urlparse
from collections import Counter

import requests

SOURCE_URLS = [
    "https://github.com/iboxz/free-v2ray-collector/raw/refs/heads/main/main/mix",
    "https://github.com/flaafix/AetrisVPN-black-list/raw/refs/heads/main/configs.txt",
    "https://github.com/Mohamedhnini-a/Neverstops/raw/refs/heads/main/sub.txt",
    "https://github.com/Mohamedhnini-a/testeur/raw/refs/heads/main/working_configs.txt",
]
XRAY = "./xray/xray"

# نستعملو روابط خفيفة باش ما يبلوكيوش
TEST_URLS = [
    "http://cp.cloudflare.com/generate_204",
    "http://www.gstatic.com/generate_204",
]

TIMEOUT = 10
MAX_WORKERS = 40
BASE_PORT = 20000
TEST_ROUNDS = 1
MIN_SUCCESS = 1
MAX_LATENCY_MS = 10000

# Thread-safe session
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
        except requests.exceptions.SSLError:
            last_error = "ssl_error"
        except requests.exceptions.ConnectionError:
            last_error = "conn_error"
        except Exception as e:
            last_error = type(e).__name__

    return None, last_error

def download_configs():
    configs = []
    for source_url in SOURCE_URLS:
        try:
            print(f"Downloading: {source_url}")
            response = requests.get(source_url, timeout=20)
            response.raise_for_status()
            source_configs = [line.strip() for line in response.text.splitlines() if line.strip()]
            print(f"  → {len(source_configs)} lines")
            configs.extend(source_configs)
        except requests.RequestException as error:
            print(f"  → FAILED: {error}")
    configs = list(dict.fromkeys(configs))
    return configs

def parse_config(line):
    try:
        if line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0].strip()
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            config = json.loads(base64.b64decode(b64_str).decode('utf-8'))
            
            return {
                "protocol": "vmess",
                "server": config.get("add"),
                "port": int(config.get("port", 443)),
                "id": config.get("id"),
                "aid": int(config.get("aid", 0)),
                "scy": config.get("scy", "auto"),
                "net": config.get("net", "tcp"),
                "tls": config.get("tls", ""),
                "host": config.get("host", ""),
                "sni": config.get("sni", ""),
                "path": config.get("path", "/"),
                "original": line,
            }

        if line.startswith("vless://") or line.startswith("trojan://"):
            parsed = urlparse(line)
            params = parse_qs(parsed.query, keep_blank_values=True)
            get = lambda name: params.get(name, [""])[0]
            
            return {
                "protocol": parsed.scheme.lower(),
                "server": parsed.hostname,
                "port": parsed.port or 443,
                "uuid": parsed.username, # للـ vless
                "password": parsed.username, # للـ trojan
                "net": get("type") or "tcp",
                "security": get("security") or "none",
                "sni": get("sni") or parsed.hostname,
                "host": get("host") or "",
                "path": unquote(get("path")) or "/",
                "alpn": get("alpn") or "",
                "fp": get("fp") or "",
                "pbk": get("pbk") or "",
                "sid": get("sid") or "",
                "spx": get("spx") or "/",
                "flow": get("flow") or "",
                "original": line,
            }
    except Exception:
        return None
    return None

def make_xray_config(config, local_port):
    # بناء إعدادات الاتصال ديناميكياً (بحال v2rayNG)
    stream_settings = {
        "network": config.get("net", "tcp"),
        "security": config.get("security", config.get("tls") or "none"),
    }
    
    # إعدادات TLS / Reality
    if stream_settings["security"] == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": config.get("sni") or config.get("server"),
            "allowInsecure": False,
        }
        if config.get("alpn"):
            stream_settings["tlsSettings"]["alpn"] = config["alpn"].split(",")
        if config.get("fp"):
            stream_settings["tlsSettings"]["fingerprint"] = config["fp"]
            
    elif stream_settings["security"] == "reality":
        stream_settings["realitySettings"] = {
            "serverName": config.get("sni") or config.get("server"),
            "fingerprint": config.get("fp") or "chrome",
            "publicKey": config.get("pbk"),
            "shortId": config.get("sid"),
            "spiderX": config.get("spx"),
        }

    # إعدادات الشبكة (Network)
    net = config.get("net", "tcp")
    if net == "ws":
        stream_settings["wsSettings"] = {
            "path": config.get("path", "/"),
            "host": config.get("host") or config.get("sni")
        }
    elif net == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": config.get("path")}
    elif net == "tcp" and config.get("header_type") == "http":
        stream_settings["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [config.get("path", "/")],
                    "headers": {"Host": [config.get("host") or config.get("sni")]}
                }
            }
        }

    # بناء الـ Outbound حسب البروتوكول
    if config["protocol"] == "vless":
        user = {"id": config["uuid"], "encryption": "none"}
        if config.get("flow"): user["flow"] = config["flow"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{"address": config["server"], "port": config["port"], "users": [user]}]},
            "streamSettings": stream_settings,
        }
    elif config["protocol"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {"servers": [{"address": config["server"], "port": config["port"], "password": config["password"]}]},
            "streamSettings": stream_settings,
        }
    elif config["protocol"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": config["server"], "port": config["port"], "users": [{"id": config["id"], "alterId": config["aid"], "security": config["scy"]}]}]},
            "streamSettings": stream_settings,
        }
    else:
        return None

    return {
        "log": {"loglevel": "error"},
        "inbounds": [{"listen": "127.0.0.1", "port": local_port, "protocol": "http", "settings": {}}],
        "outbounds": [outbound],
    }

def validate_xray_config(config_file):
    try:
        result = subprocess.run([XRAY, "run", "-test", "-c", config_file], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            msg = (result.stderr or result.stdout or "").strip()
            lines = [ln for ln in msg.splitlines() if ln.strip()]
            return False, " | ".join(lines[-2:])[:250]
        return True, None
    except subprocess.TimeoutExpired:
        return False, "xray_test_timeout"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:150]}"

def _read_log(log_file, max_lines=3, max_chars=250):
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as lf:
            lines = [ln.strip() for ln in lf.read().splitlines() if ln.strip()]
            return " | ".join(lines[:max_lines])[:max_chars]
    except Exception:
        return ""

def test_config(index, config):
    local_port = BASE_PORT + (index % 40000)
    config_file = None
    log_file = None
    process = None
    latencies = []
    last_err = None

    base_result = {
        "index": index,
        "line": config["original"],
        "protocol": config.get("protocol", "?"),
        "server": config.get("server", "?"),
    }

    try:
        xray_config = make_xray_config(config, local_port)
        if not xray_config:
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": "make_config_failed"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(xray_config, f, ensure_ascii=False)
            config_file = f.name

        is_valid, err = validate_xray_config(config_file)
        if not is_valid:
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": f"invalid_config: {err[:120]}"}

        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
        log_handle = open(log_file, "w")
        try:
            process = subprocess.Popen([XRAY, "run", "-c", config_file], stdout=subprocess.DEVNULL, stderr=log_handle, start_new_session=True)
        finally:
            log_handle.close()

        started = False
        for _ in range(20):
            if process.poll() is not None:
                break
            try:
                sock = socket.create_connection(("127.0.0.1", local_port), timeout=0.5)
                sock.close()
                started = True
                break
            except OSError:
                time.sleep(0.1)

        if not started:
            exit_code = process.poll()
            time.sleep(0.2)
            xray_err = _read_log(log_file)
            detail = f"exit={exit_code}|err={xray_err or 'empty'}"
            reason = "xray_died" if exit_code is not None else "xray_no_port"
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": f"{reason}({detail})"}

        proxies = {"http": f"http://127.0.0.1:{local_port}", "https": f"http://127.0.0.1:{local_port}"}

        for round_number in range(TEST_ROUNDS):
            latency, err = test_once(proxies)
            if latency is not None:
                latencies.append(latency)
            else:
                last_err = err
            if round_number < TEST_ROUNDS - 1:
                time.sleep(0.15)

        success_count = len(latencies)
        if success_count < MIN_SUCCESS:
            reason = last_err or "request_failed"
            return {**base_result, "ok": False, "latency": None, "latencies": latencies, "reason": reason}

        final_latency = int(median(latencies))
        return {**base_result, "ok": True, "latency": final_latency, "latencies": latencies, "reason": "ok"}

    except Exception as error:
        return {**base_result, "ok": False, "latency": None, "latencies": latencies, "reason": type(error).__name__}

    finally:
        if process:
            try:
                process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                    process.wait(timeout=1)
                except Exception:
                    pass
        for path in (config_file, log_file):
            if path:
                try:
                    os.remove(path)
                except Exception:
                    pass

def main():
    print("\n==============================")
    print(" UNIVERSAL CHECKER (v2rayNG Style)")
    print("==============================\n")

    if not os.path.isfile(XRAY):
        print(f"ERROR: Xray binary not found at '{XRAY}'")
        return

    print("Downloading configs...")
    lines = download_configs()
    print(f"Downloaded: {len(lines)} lines")

    configs = []
    for line in lines:
        config = parse_config(line)
        if config:
            configs.append(config)

    print(f"Testable configs : {len(configs)}")

    if not configs:
        print("\nNo configs found.")
        open("working.txt", "w", encoding="utf-8").close()
        return

    tasks = list(enumerate(configs, start=1))
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        iterator = iter(tasks)
        pending = set()

        for _ in range(MAX_WORKERS):
            try:
                pending.add(executor.submit(test_config, *next(iterator)))
            except StopIteration:
                break

        while pending:
            done, pending = concurrent.futures.wait(pending, return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                try:
                    results.append(future.result())
                except Exception as e:
                    pass
                try:
                    pending.add(executor.submit(test_config, *next(iterator)))
                except StopIteration:
                    pass

    working_results = [r for r in results if r["ok"]]
    working_results.sort(key=lambda x: (x["latency"], x["index"]))
    
    fast_results = [r for r in working_results if r["latency"] <= MAX_LATENCY_MS]

    with open("working.txt", "w", encoding="utf-8") as f:
        for r in fast_results:
            f.write(r["line"] + "\n")

    print(f"\nWorking configs: {len(fast_results)}")
    print("\nFastest configs:")
    for pos, r in enumerate(fast_results[:10], start=1):
        print(f"{pos:02d}. {r['latency']} ms | {r.get('protocol','?')} | {r.get('server','?')}")

    print("\nOutput: working.txt")

if __name__ == "__main__":
    main()
