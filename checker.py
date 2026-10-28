import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
import base64
from statistics import median
from urllib.parse import parse_qs, unquote, urlparse
from collections import Counter

import requests


SOURCE_URLS = [
    "https://github.com/Mohamedhnini-a/testeur/raw/refs/heads/main/working_configs.txt",
    "https://github.com/Mohamedhnini-a/Neverstops/raw/refs/heads/main/sub.txt"
]
XRAY = "./xray/xray"

# ============ TEST_URL ============
# خيار 1 (المستعمل دابا): gstatic — خفيف و موثوق
TEST_URL = "http://www.gstatic.com/generate_204"
# خيار 2 (بديل): Cloudflare — محايد أكثر
# TEST_URL = "http://cp.cloudflare.com/"

TIMEOUT = 15
MAX_WORKERS = 15
BASE_PORT = 20000
TEST_ROUNDS = 1
MIN_SUCCESS = 1


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
    # ==========================================
    # 1. معالجة VMess (بعد الإصلاح)
    # ==========================================
    if line.startswith("vmess://"):
        try:
            b64_str = line[8:].split("#")[0].strip()
            b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
            json_str = base64.b64decode(b64_str).decode('utf-8')
            config = json.loads(json_str)

            net = str(config.get("net", "")).lower()
            tls = str(config.get("tls", "")).lower()
            port = str(config.get("port", ""))

            if net != "ws" or tls != "tls" or port != "443":
                return None

            # ✅ validation ديال id و add
            vm_id = config.get("id")
            server = config.get("add")
            if not vm_id or not server:
                return None

            # ✅ fallback: sni -> host -> server
            host = (config.get("host") or server).lower()
            sni = (config.get("sni") or host or server).lower()
            path = config.get("path") or "/"

            # ✅ alterId من config (كان ثابت على 0)
            try:
                aid = int(config.get("aid") or 0)
            except (ValueError, TypeError):
                aid = 0

            # ✅ cipher من config (كان ثابت على "auto")
            scy = config.get("scy") or config.get("security") or "auto"

            return {
                "protocol": "vmess",
                "server": server,
                "port": 443,
                "id": vm_id,
                "aid": aid,
                "scy": scy,
                "host": host,
                "sni": sni,
                "path": path,
                "original": line,
            }
        except Exception:
            return None

    # ==========================================
    # 2. معالجة VLESS و Trojan
    # ==========================================
    if not (line.startswith("vless://") or line.startswith("trojan://")):
        return None

    try:
        parsed = urlparse(line)
        protocol = parsed.scheme.lower()
        host = parsed.hostname
        port = parsed.port

        if not host or port is None or port != 443:
            return None

        params = parse_qs(parsed.query, keep_blank_values=True)

        def get(name):
            values = params.get(name)
            return values[0] if values else ""

        network = get("type")
        security = get("security")
        ws_host = get("host")
        sni = get("sni")
        path = unquote(get("path"))

        if network != "ws" or security != "tls":
            return None

        if not path:
            path = "/"
        if not ws_host:
            ws_host = host
        if not sni:
            sni = ws_host

        if protocol == "vless":
            uuid = parsed.username
            if not uuid:
                return None
            return {
                "protocol": "vless",
                "server": host,
                "port": 443,
                "uuid": uuid,
                "host": ws_host,
                "sni": sni,
                "path": path,
                "original": line,
            }

        if protocol == "trojan":
            password = parsed.username
            if not password:
                return None
            return {
                "protocol": "trojan",
                "server": host,
                "port": 443,
                "password": password,
                "host": ws_host,
                "sni": sni,
                "path": path,
                "original": line,
            }
    except Exception:
        return None

    return None


def make_xray_config(config, local_port):
    stream_settings = {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
            "serverName": config["sni"],
            # ✅ تبدلت من False لـ True باش self-signed يقبل
            "allowInsecure": True,
        },
        "wsSettings": {
            "path": config["path"],
            "headers": {"Host": config["host"]},
        },
    }

    if config["protocol"] == "vless":
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": config["server"],
                        "port": 443,
                        "users": [{"id": config["uuid"], "encryption": "none"}],
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    elif config["protocol"] == "trojan":
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [
                    {
                        "address": config["server"],
                        "port": 443,
                        "password": config["password"],
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    # ==========================================
    # 3. VMess (بعد الإصلاح)
    # ==========================================
    elif config["protocol"] == "vmess":
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": config["server"],
                        "port": 443,
                        "users": [
                            {
                                "id": config["id"],
                                # ✅ من config بدل ما كان ثابت على 0
                                "alterId": config["aid"],
                                # ✅ من config بدل ما كان ثابت على "auto"
                                "security": config["scy"],
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    else:
        return None

    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "http",
                "settings": {},
            }
        ],
        "outbounds": [outbound],
    }


def test_once(proxies):
    """كيرجع (latency_ms, error_reason)"""
    try:
        start = time.perf_counter()
        response = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TIMEOUT,
            allow_redirects=False,
            trust_env=False,  # ✅ باش NO_PROXY ما يتدخلش
        )
        elapsed = (time.perf_counter() - start) * 1000
        if response.status_code in (200, 204):
            return round(elapsed), None
        return None, f"http_{response.status_code}"
    except requests.exceptions.Timeout:
        return None, "timeout"
    except requests.exceptions.ProxyError:
        return None, "proxy_error"
    except requests.exceptions.SSLError:
        return None, "ssl_error"
    except requests.exceptions.ConnectionError:
        return None, "conn_error"
    except Exception as e:
        return None, type(e).__name__


def _read_log(log_file, max_lines=3, max_chars=250):
    """كيقرا xray stderr باش نعرفو علاش مات"""
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as lf:
            lines = [ln.strip() for ln in lf.read().splitlines() if ln.strip()]
            return " | ".join(lines[:max_lines])[:max_chars]
    except Exception:
        return ""


def test_config(index, config):
    local_port = BASE_PORT + index
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
            print(f"[FAILED:make_config_failed] {config.get('protocol','?')} | {config.get('server','?')}")
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": "make_config_failed"}

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(xray_config, f, ensure_ascii=False)
            config_file = f.name

        # نكتب stderr ديال xray فـ ملف باش نقدرو نقراوه إلا مات
        log_file = tempfile.NamedTemporaryFile(suffix=".log", delete=False).name
        log_handle = open(log_file, "w")
        try:
            process = subprocess.Popen(
                [XRAY, "run", "-c", config_file],
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
            )
        finally:
            log_handle.close()

        # نتسناو Xray يفتح البورت
        started = False
        for _ in range(10):
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
            # ✅ نعرفو بالضبط: مات ولا غير ما فتحش البورت
            reason = "xray_died" if process.poll() is not None else "xray_no_port"
            xray_err = _read_log(log_file)
            print(f"[FAILED:{reason}] {config.get('protocol','?')} | {config.get('server','?')} | {xray_err}")
            return {**base_result, "ok": False, "latency": None, "latencies": [], "reason": reason}

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

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
            print(f"[FAILED:{reason}] {config.get('protocol','?')} | {config.get('server','?')} | {success_count}/{TEST_ROUNDS}")
            return {**base_result, "ok": False, "latency": None, "latencies": latencies, "reason": reason}

        final_latency = int(median(latencies))
        print(f"[ONLINE] {final_latency} ms | {latencies} | {config.get('protocol','?')} | {config.get('server','?')}")
        return {**base_result, "ok": True, "latency": final_latency, "latencies": latencies, "reason": "ok"}

    except Exception as error:
        err_type = type(error).__name__
        print(f"[FAILED:{err_type}] {config.get('protocol','?')} | {config.get('server','?')} | {str(error)[:100]}")
        return {**base_result, "ok": False, "latency": None, "latencies": latencies, "reason": err_type}

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
    print(" VLESS / TROJAN / VMESS CHECKER")
    print(" FASTEST CONFIG SORTING + DIAGNOSTIC")
    print("==============================\n")

    if not os.path.isfile(XRAY):
        print(f"ERROR: Xray binary not found at '{XRAY}'")
        return

    print("Downloading configs...")
    lines = download_configs()
    print(f"Downloaded: {len(lines)} lines")

    # إحصائيات المرحلة 1 (parse)
    parse_stats = Counter()
    configs = []
    for line in lines:
        config = parse_config(line)
        if config:
            configs.append(config)
            parse_stats[config["protocol"]] += 1
        else:
            parse_stats["dropped (parse/filter)"] += 1

    print(f"\n--- Parse stage ---")
    for key, count in parse_stats.items():
        print(f"  {key:25s}: {count}")

    print(f"\nTestable configs: {len(configs)}")
    print(f"TEST_URL        : {TEST_URL}")
    print(f"Rounds per config: {TEST_ROUNDS}")
    print(f"Min success     : {MIN_SUCCESS}")

    if not configs:
        print("\nNo VLESS/Trojan/VMess WS TLS 443 configs found.")
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
            done, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED
            )

            for future in done:
                try:
                    results.append(future.result())
                except Exception as e:
                    print(f"[FAILED] Worker error: {str(e)[:100]}")

                try:
                    pending.add(executor.submit(test_config, *next(iterator)))
                except StopIteration:
                    pass

    working_results = [r for r in results if r["ok"]]
    failed_results = [r for r in results if not r["ok"]]
    working_results.sort(key=lambda x: (x["latency"], x["index"]))

    with open("working.txt", "w", encoding="utf-8") as f:
        for r in working_results:
            f.write(r["line"] + "\n")

    working_count = len(working_results)
    failed_count = len(failed_results)

    print("\n==============================")
    print(" CHECK FINISHED")
    print("==============================")
    print(f"Total downloaded : {len(lines)}")
    print(f"Tested           : {len(configs)}")
    print(f"Working          : {working_count}")
    print(f"Failed           : {failed_count}")

    # ============ DIAGNOSTIC ============
    if failed_count:
        print("\n--- Failure reasons (overall) ---")
        overall = Counter(r.get("reason", "unknown") for r in failed_results)
        for reason, count in overall.most_common():
            pct = 100 * count / failed_count
            print(f"  {count:5d} ({pct:5.1f}%)  {reason}")

        print("\n--- Failure reasons per protocol ---")
        per_proto = {}
        for r in failed_results:
            proto = r.get("protocol", "?")
            reason = r.get("reason", "unknown")
            per_proto.setdefault(proto, Counter())[reason] += 1

        for proto, counter in sorted(per_proto.items()):
            total_proto = sum(counter.values())
            print(f"  [{proto}]  total failed = {total_proto}")
            for reason, count in counter.most_common():
                pct = 100 * count / total_proto
                print(f"      {count:5d} ({pct:5.1f}%)  {reason}")

        # Success rate per protocol
        print("\n--- Success rate per protocol ---")
        proto_total = Counter(r["protocol"] for r in results)
        proto_ok = Counter(r["protocol"] for r in working_results)
        for proto in proto_total:
            ok = proto_ok.get(proto, 0)
            total = proto_total[proto]
            pct = 100 * ok / total if total else 0
            print(f"  {proto:8s}: {ok:5d}/{total:<5d}  ({pct:5.1f}%)")

    print("\nFastest configs:")
    for pos, r in enumerate(working_results[:10], start=1):
        print(f"{pos:02d}. {r['latency']} ms | {r.get('protocol','?')} | {r.get('server','?')}")

    print("\nOutput: working.txt")


if __name__ == "__main__":
    main()
