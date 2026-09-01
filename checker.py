import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
from statistics import median
from urllib.parse import parse_qs, unquote, urlparse

import requests


SOURCE_URLS = [
    "https://github.com/Mohamedhnini-a/testeur/raw/refs/heads/main/working_configs.txt",
    "https://long-feather-2859.hninisiimoo.workers.dev/"
]
XRAY = "./xray/xray"
TEST_URL = "https://www.google.com/generate_204"
TIMEOUT = 15
MAX_WORKERS = 15
BASE_PORT = 20000
TEST_ROUNDS = 1
MIN_SUCCESS = 1


def download_configs():
    response = requests.get(SOURCE_URL, timeout=20)
    response.raise_for_status()
    return [line.strip() for line in response.text.splitlines() if line.strip()]


def parse_config(line):
    if not (line.startswith("vless://") or line.startswith("trojan://")):
        return None

    try:
        parsed = urlparse(line)
        protocol = parsed.scheme.lower()
        if protocol not in ("vless", "trojan"):
            return None

        host = parsed.hostname
        port = parsed.port

        # FIX: handle case where port is not present in URL
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
            "allowInsecure": False,
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
                        "users": [
                            {
                                "id": config["uuid"],
                                "encryption": "none",
                            }
                        ],
                    }
                ]
            },
            "streamSettings": stream_settings,
        }
    else:  # trojan
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
    try:
        start = time.perf_counter()
        response = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TIMEOUT,
            allow_redirects=False,
        )
        elapsed = (time.perf_counter() - start) * 1000
        if response.status_code in (200, 204):
            return round(elapsed)
        return None
    except Exception:
        return None


def test_config(index, config):
    local_port = BASE_PORT + index
    config_file = None
    process = None
    latencies = []

    try:
        xray_config = make_xray_config(config, local_port)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(xray_config, f, ensure_ascii=False)
            config_file = f.name

        process = subprocess.Popen(
            [XRAY, "run", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for proxy to start
        started = False
        for _ in range(10):
            if process.poll() is not None:
                break
            try:
                sock = socket.create_connection(("127.0.0.1", local_port), timeout=0.2)
                sock.close()
                started = True
                break
            except OSError:
                time.sleep(0.1)

        if not started:
            print(f"[FAILED] {config['protocol']} | {config['server']} | Xray did not start")
            return {
                "index": index,
                "ok": False,
                "line": config["original"],
                "latency": None,
                "latencies": latencies,
                "protocol": config.get("protocol", "?"),
                "server": config.get("server", "?"),
            }

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

        for round_number in range(TEST_ROUNDS):
            latency = test_once(proxies)
            if latency is not None:
                latencies.append(latency)
            if round_number < TEST_ROUNDS - 1:
                time.sleep(0.15)

        success_count = len(latencies)
        if success_count < MIN_SUCCESS:
            print(f"[FAILED] {config['protocol']} | {config['server']} | {success_count}/{TEST_ROUNDS} successful")
            return {
                "index": index,
                "ok": False,
                "line": config["original"],
                "latency": None,
                "latencies": latencies,
                "protocol": config["protocol"],
                "server": config["server"],
            }

        final_latency = int(median(latencies))
        print(f"[ONLINE] {final_latency} ms | {latencies} | {config['protocol']} | {config['server']}")
        return {
            "index": index,
            "ok": True,
            "line": config["original"],
            "latency": final_latency,
            "latencies": latencies,
            "protocol": config["protocol"],
            "server": config["server"],
        }

    except Exception as error:
        print(f"[FAILED] {config.get('protocol', '?')} | {config.get('server', '?')} | {str(error)[:100]}")
        return {
            "index": index,
            "ok": False,
            "line": config["original"],
            "latency": None,
            "latencies": latencies,
            "protocol": config.get("protocol", "?"),
            "server": config.get("server", "?"),
        }

    finally:
        if process:
            try:
                process.terminate()
                process.wait(timeout=1)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        if config_file:
            try:
                os.remove(config_file)
            except Exception:
                pass


def main():
    print("\n==============================")
    print(" VLESS / TROJAN CHECKER")
    print(" FASTEST CONFIG SORTING")
    print("==============================\n")

    # Check if Xray binary exists
    if not os.path.isfile(XRAY):
        print(f"ERROR: Xray binary not found at '{XRAY}'")
        return

    print("Downloading configs...")
    lines = download_configs()
    print(f"Downloaded: {len(lines)} lines")

    # Parse configs
    configs = []
    for line in lines:
        config = parse_config(line)
        if config:
            configs.append(config)

    print(f"Testable configs: {len(configs)}")
    print(f"Latency tests per config: {TEST_ROUNDS}")
    print(f"Minimum successful tests: {MIN_SUCCESS}")

    if not configs:
        print("\nNo VLESS/Trojan WS TLS 443 configs found.")
        open("working.txt", "w", encoding="utf-8").close()
        return

    # Prepare tasks for threading
    tasks = list(enumerate(configs, start=1))
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        iterator = iter(tasks)
        pending = set()

        # Fill the pool initially
        for _ in range(MAX_WORKERS):
            try:
                pending.add(executor.submit(test_config, *next(iterator)))
            except StopIteration:
                break

        # Process completed tasks and keep pool full
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

                # Submit a new task if any remain
                try:
                    pending.add(executor.submit(test_config, *next(iterator)))
                except StopIteration:
                    pass

    # Filter working results
    working_results = [r for r in results if r["ok"]]
    working_results.sort(key=lambda x: (x["latency"], x["index"]))

    # Write output
    with open("working.txt", "w", encoding="utf-8") as f:
        for r in working_results:
            f.write(r["line"] + "\n")

    # Statistics
    working_count = len(working_results)
    failed_count = len(configs) - working_count

    print("\n==============================")
    print(" CHECK FINISHED")
    print("==============================")
    print(f"Total downloaded : {len(lines)}")
    print(f"Tested           : {len(configs)}")
    print(f"Working          : {working_count}")
    print(f"Failed           : {failed_count}\n")

    print("Fastest configs:")
    for pos, r in enumerate(working_results[:10], start=1):
        print(f"{pos:02d}. {r['latency']} ms | {r.get('protocol','?')} | {r.get('server','?')}")

    print("\nOutput: working.txt")


if __name__ == "__main__":
    main()
