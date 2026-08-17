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


SOURCE_URL = "https://long-feather-2859.hninisiimoo.workers.dev/"

XRAY = "./xray/xray"

TEST_URL = "https://www.google.com/generate_204"

TIMEOUT = 5

MAX_WORKERS = 20

BASE_PORT = 20000

# عدد الاختبارات لكل Config
TEST_ROUNDS = 3

# أقل عدد من الاختبارات الناجحة حتى تعتبر Config Working
MIN_SUCCESS = 2


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


def test_once(proxies):

    """
    يقوم باختبار واحد فقط ويرجع:
    latency بالـ ms إذا نجح
    أو None إذا فشل
    """

    try:

        start = time.perf_counter()

        response = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TIMEOUT,
            allow_redirects=False,
        )

        elapsed = (
            time.perf_counter() - start
        ) * 1000

        if response.status_code in (200, 204):

            return round(elapsed)

        return None

    except Exception:

        return None


def test_config(item):

    index, config = item

    local_port = BASE_PORT + index

    config_file = None

    process = None

    latencies = []

    try:

        # =========================
        # Xray config
        # =========================

        xray_config = make_xray_config(
            config,
            local_port,
        )

        # =========================
        # Temporary config file
        # =========================

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

        # =========================
        # Start Xray
        # =========================

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

        # =========================
        # Wait for local proxy
        # =========================

        started = False

        for _ in range(10):

            if process.poll() is not None:
                break

            try:

                sock = socket.create_connection(
                    (
                        "127.0.0.1",
                        local_port,
                    ),
                    timeout=0.2,
                )

                sock.close()

                started = True

                break

            except OSError:

                time.sleep(0.1)

        if not started:

            print(
                f"[FAILED] "
                f"{config['protocol']} | "
                f"{config['server']} | "
                f"Xray did not start"
            )

            return {
                "index": index,
                "ok": False,
                "line": config["original"],
                "latency": None,
                "latencies": [],
            }

        # =========================
        # Local proxy
        # =========================

        proxies = {

            "http":
                f"http://127.0.0.1:{local_port}",

            "https":
                f"http://127.0.0.1:{local_port}",

        }

        # =========================
        # Multiple latency tests
        # =========================

        for round_number in range(
            TEST_ROUNDS
        ):

            latency = test_once(
                proxies
            )

            if latency is not None:

                latencies.append(
                    latency
                )

            # pause صغيرة بين الاختبارات
            if (
                round_number
                < TEST_ROUNDS - 1
            ):

                time.sleep(0.15)

        # =========================
        # Check minimum successes
        # =========================

        success_count = len(
            latencies
        )

        if success_count < MIN_SUCCESS:

            print(
                f"[FAILED] "
                f"{config['protocol']} | "
                f"{config['server']} | "
                f"{success_count}/{TEST_ROUNDS} successful"
            )

            return {
                "index": index,
                "ok": False,
                "line": config["original"],
                "latency": None,
                "latencies": latencies,
            }

        # =========================
        # Median latency
        # =========================

        final_latency = int(
            median(latencies)
        )

        print(
            f"[ONLINE] "
            f"{final_latency} ms | "
            f"{latencies} | "
            f"{config['protocol']} | "
            f"{config['server']}"
        )

        return {
            "index": index,
            "ok": True,
            "line": config["original"],
            "latency": final_latency,
            "latencies": latencies,
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
            "latency": None,
            "latencies": latencies,
        }

    finally:

        # =========================
        # Stop Xray
        # =========================

        if process:

            try:

                process.terminate()

                process.wait(
                    timeout=1
                )

            except Exception:

                try:

                    process.kill()

                except Exception:
                    pass

        # =========================
        # Delete temporary config
        # =========================

        if config_file:

            try:

                os.remove(
                    config_file
                )

            except Exception:
                pass


def main():

    print()

    print(
        "=============================="
    )

    print(
        " VLESS / TROJAN CHECKER"
    )

    print(
        " FASTEST CONFIG SORTING"
    )

    print(
        "=============================="
    )

    print()

    print(
        "Downloading configs..."
    )

    # =========================
    # Download
    # =========================

    lines = download_configs()

    print(
        f"Downloaded: {len(lines)} lines"
    )

    # =========================
    # Parse configs
    # =========================

    configs = []

    for line in lines:

        config = parse_config(
            line
        )

        if config:

            configs.append(
                config
            )

    print(
        f"Testable configs: "
        f"{len(configs)}"
    )

    print(
        f"Latency tests per config: "
        f"{TEST_ROUNDS}"
    )

    print(
        f"Minimum successful tests: "
        f"{MIN_SUCCESS}"
    )

    # =========================
    # No configs
    # =========================

    if not configs:

        print()

        print(
            "No VLESS/Trojan "
            "WS TLS 443 configs found."
        )

        open(
            "working.txt",
            "w",
            encoding="utf-8",
        ).close()

        return

    # =========================
    # Number configs
    # =========================

    items = list(
        enumerate(
            configs,
            start=1,
        )
    )

    results = []

    # =========================
    # ThreadPool
    # =========================

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        iterator = iter(items)

        pending = set()

        # =========================
        # Fill worker pool
        # =========================

        for _ in range(
            MAX_WORKERS
        ):

            try:

                pending.add(
                    executor.submit(
                        test_config,
                        next(iterator),
                    )
                )

            except StopIteration:

                break

        # =========================
        # Process completed tasks
        # =========================

        while pending:

            done, pending = (
                concurrent.futures.wait(
                    pending,
                    return_when=(
                        concurrent.futures
                        .FIRST_COMPLETED
                    ),
                )
            )

            for future in done:

                try:

                    results.append(
                        future.result()
                    )

                except Exception as error:

                    print(
                        "[FAILED] "
                        f"Worker error: "
                        f"{str(error)[:100]}"
                    )

                # =========================
                # Replace completed task
                # =========================

                try:

                    pending.add(
                        executor.submit(
                            test_config,
                            next(iterator),
                        )
                    )

                except StopIteration:

                    pass

    # =========================
    # Working configs only
    # =========================

    working_results = [

        result

        for result in results

        if result["ok"]

    ]

    # =========================
    # Sort:
    #
    # fastest → slowest
    #
    # latency ASC
    # =========================

    working_results.sort(
        key=lambda x: (
            x["latency"],
            x["index"],
        )
    )

    # =========================
    # Write working.txt
    # =========================

    with open(
        "working.txt",
        "w",
        encoding="utf-8",
    ) as file:

        for result in working_results:

            file.write(
                result["line"]
                + "\n"
            )

    # =========================
    # Statistics
    # =========================

    working_count = len(
        working_results
    )

    failed_count = (
        len(configs)
        - working_count
    )

    print()

    print(
        "=============================="
    )

    print(
        " CHECK FINISHED"
    )

    print(
        "=============================="
    )

    print(
        f"Total downloaded : "
        f"{len(lines)}"
    )

    print(
        f"Tested           : "
        f"{len(configs)}"
    )

    print(
        f"Working          : "
        f"{working_count}"
    )

    print(
        f"Failed           : "
        f"{failed_count}"
    )

    print()

    # =========================
    # Show fastest configs
    # =========================

    print(
        "Fastest configs:"
    )

    for position, result in enumerate(
        working_results[:10],
        start=1,
    ):

        print(
            f"{position:02d}. "
            f"{result['latency']} ms | "
            f"{result['protocol']} | "
            f"{result['server']}"
        )

    print()

    print(
        "Output: working.txt"
    )


if __name__ == "__main__":

    main()
