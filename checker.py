import concurrent.futures
import json
import os
import socket
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlparse

import requests


SOURCE_URL = "https://long-feather-2859.hninisiimoo.workers.dev/"

XRAY = "./xray/xray"

TEST_URL = "https://www.google.com/generate_204"

TIMEOUT = 8
MAX_WORKERS = 32
BASE_PORT = 20000


def download_configs():
    response = requests.get(
        SOURCE_URL,
        timeout=20,
    )

    response.raise_for_status()

    return [
        line.strip()
        for line in response.text.splitlines()
        if line.strip()
    ]


def parse_config(line):

    if not (
        line.startswith("vless://")
        or line.startswith("trojan://")
    ):
        return None

    try:
        parsed = urlparse(line)

        protocol = parsed.scheme.lower()

        if protocol not in ("vless", "trojan"):
            return None

        host = parsed.hostname
        port = parsed.port

        if not host or port != 443:
            return None

        params = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        def get(name):
            values = params.get(name)
            return values[0] if values else ""

        network = get("type")
        security = get("security")

        ws_host = get("host")
        sni = get("sni")
        path = unquote(get("path"))

        if network != "ws":
            return None

        if security != "tls":
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

            "streamSettings": {
                "network": "ws",
                "security": "tls",

                "tlsSettings": {
                    "serverName": config["sni"],
                    "allowInsecure": False,
                },

                "wsSettings": {
                    "path": config["path"],

                    "headers": {
                        "Host": config["host"],
                    },
                },
            },
        }

    else:

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

            "streamSettings": {
                "network": "ws",
                "security": "tls",

                "tlsSettings": {
                    "serverName": config["sni"],
                    "allowInsecure": False,
                },

                "wsSettings": {
                    "path": config["path"],

                    "headers": {
                        "Host": config["host"],
                    },
                },
            },
        }

    return {
        "log": {
            "loglevel": "error"
        },

        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "http",
                "settings": {},
            }
        ],

        "outbounds": [
            outbound
        ],
    }


def test_config(item):

    index, config = item

    local_port = BASE_PORT + index

    config_file = None
    process = None

    try:

        xray_config = make_xray_config(
            config,
            local_port,
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        ) as file:

            json.dump(
                xray_config,
                file,
                ensure_ascii=False,
            )

            config_file = file.name

        process = subprocess.Popen(
            [
                XRAY,
                "run",
                "-c",
                config_file,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        started = False

        for _ in range(10):

            if process.poll() is not None:
                break

            try:

                sock = socket.create_connection(
                    ("127.0.0.1", local_port),
                    timeout=0.2,
                )

                sock.close()

                started = True
                break

            except OSError:
                time.sleep(0.1)

        if not started:

            return {
                "index": index,
                "ok": False,
                "line": config["original"],
            }

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

        start = time.perf_counter()

        response = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        elapsed = int(
            (time.perf_counter() - start) * 1000
        )

        ok = response.status_code in (200, 204)

        if ok:

            print(
                f"[ONLINE] "
                f"{elapsed} ms | "
                f"{config['protocol']} | "
                f"{config['server']}"
            )

        else:

            print(
                f"[FAILED] "
                f"HTTP {response.status_code} | "
                f"{config['server']}"
            )

        return {
            "index": index,
            "ok": ok,
            "line": config["original"],
        }

    except Exception as error:

        print(
            f"[FAILED] "
            f"{config.get('protocol', '?')} | "
            f"{config.get('server', '?')} | "
            f"{str(error)[:100]}"
        )

        return {
            "index": index,
            "ok": False,
            "line": config["original"],
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

    print()
    print("==============================")
    print(" VLESS / TROJAN CHECKER")
    print("==============================")
    print()

    print("Downloading configs...")

    lines = download_configs()

    print(
        f"Downloaded: {len(lines)} lines"
    )

    configs = []

    for line in lines:

        config = parse_config(line)

        if config:
            configs.append(config)

    print(
        f"Testable configs: {len(configs)}"
    )

    if not configs:

        print(
            "No VLESS/Trojan WS TLS 443 configs found."
        )

        open(
            "working.txt",
            "w",
            encoding="utf-8",
        ).close()

        return

    items = list(
        enumerate(
            configs,
            start=1,
        )
    )

    results = []

    # Keep only a bounded number of tasks queued at once.
    # This is much lighter when the source contains 10,000+ configs.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        iterator = iter(items)
        pending = set()

        # Fill the worker pool.
        for _ in range(MAX_WORKERS):
            try:
                pending.add(
                    executor.submit(test_config, next(iterator))
                )
            except StopIteration:
                break

        while pending:
            done, pending = concurrent.futures.wait(
                pending,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for future in done:
                try:
                    results.append(future.result())
                except Exception as error:
                    print(f"[FAILED] Worker error: {str(error)[:100]}")

                # Immediately replace every completed task with another one.
                try:
                    pending.add(
                        executor.submit(test_config, next(iterator))
                    )
                except StopIteration:
                    pass

    results.sort(
        key=lambda x: x["index"]
    )

    working = [
        result["line"]
        for result in results
        if result["ok"]
    ]

    with open(
        "working.txt",
        "w",
        encoding="utf-8",
    ) as file:

        for line in working:
            file.write(line + "\n")

    print()
    print("==============================")
    print(" CHECK FINISHED")
    print("==============================")

    print(
        f"Total downloaded : {len(lines)}"
    )

    print(
        f"Tested           : {len(configs)}"
    )

    print(
        f"Working          : {len(working)}"
    )

    print(
        f"Failed           : "
        f"{len(configs) - len(working)}"
    )

    print()
    print("Output: working.txt")


if __name__ == "__main__":
    main()
