import subprocess
import tempfile
import requests
import json
import os
import time
import socket
from urllib.parse import urlparse, parse_qs, unquote


SOURCE_URL = (
    "https://raw.githubusercontent.com/barry-far/"
    "V2ray-Config/refs/heads/main/All_Configs_Sub.txt"
)

XRAY = "./xray/xray"

TEST_URL = "https://www.google.com/generate_204"

TIMEOUT = 10


def download_configs():
    r = requests.get(SOURCE_URL, timeout=20)
    r.raise_for_status()
    return [
        line.strip()
        for line in r.text.splitlines()
        if line.strip()
    ]


def parse_config(line):

    if not (
        line.startswith("vless://")
        or line.startswith("trojan://")
    ):
        return None

    try:
        u = urlparse(line)

        protocol = u.scheme.lower()

        host = u.hostname
        port = u.port

        params = parse_qs(u.query)

        def get(name):
            values = params.get(name)
            return values[0] if values else ""

        network = get("type")
        security = get("security")
        ws_host = get("host")
        sni = get("sni")
        path = unquote(get("path"))

        # Basic requirements
        if network != "ws":
            return None

        if security != "tls":
            return None

        if port != 443:
            return None

        if not host:
            return None

        if not sni:
            sni = ws_host or host

        if not path:
            path = "/"

        if protocol == "vless":

            uuid = u.username

            if not uuid:
                return None

            return {
                "protocol": "vless",
                "server": host,
                "port": 443,
                "uuid": uuid,
                "ws_host": ws_host or host,
                "sni": sni,
                "path": path,
                "original": line,
            }

        if protocol == "trojan":

            password = u.username

            if not password:
                return None

            return {
                "protocol": "trojan",
                "server": host,
                "port": 443,
                "password": password,
                "ws_host": ws_host or host,
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
                                "encryption": "none"
                            }
                        ]
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",

                "tlsSettings": {
                    "serverName": config["sni"],
                    "allowInsecure": False
                },

                "wsSettings": {
                    "path": config["path"],
                    "headers": {
                        "Host": config["ws_host"]
                    }
                }
            }
        }

    else:

        outbound = {
            "protocol": "trojan",

            "settings": {
                "servers": [
                    {
                        "address": config["server"],
                        "port": 443,
                        "password": config["password"]
                    }
                ]
            },

            "streamSettings": {
                "network": "ws",
                "security": "tls",

                "tlsSettings": {
                    "serverName": config["sni"],
                    "allowInsecure": False
                },

                "wsSettings": {
                    "path": config["path"],
                    "headers": {
                        "Host": config["ws_host"]
                    }
                }
            }
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
                "settings": {}
            }
        ],

        "outbounds": [
            outbound
        ]
    }


def test_config(config, index):

    local_port = 18000 + index

    xray_config = make_xray_config(
        config,
        local_port
    )

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False
    ) as f:

        json.dump(
            xray_config,
            f,
            indent=2
        )

        config_file = f.name

    process = None

    try:

        process = subprocess.Popen(
            [
                XRAY,
                "run",
                "-c",
                config_file
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Give Xray time to start
        time.sleep(1)

        # Check that local proxy port is listening
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(2)

        result = sock.connect_ex(
            ("127.0.0.1", local_port)
        )

        sock.close()

        if result != 0:
            return False

        proxies = {
            "http": f"http://127.0.0.1:{local_port}",
            "https": f"http://127.0.0.1:{local_port}",
        }

        start = time.time()

        r = requests.get(
            TEST_URL,
            proxies=proxies,
            timeout=TIMEOUT
        )

        delay = int(
            (time.time() - start) * 1000
        )

        if r.status_code in (200, 204):

            print(
                f"[ONLINE] {delay} ms | "
                f"{config['protocol']} | "
                f"{config['server']}"
            )

            return True

        print(
            f"[FAILED] HTTP {r.status_code} | "
            f"{config['server']}"
        )

        return False

    except Exception as e:

        print(
            f"[FAILED] "
            f"{config['protocol']} | "
            f"{config['server']} | "
            f"{str(e)[:120]}"
        )

        return False

    finally:

        if process:

            process.terminate()

            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

        try:
            os.remove(config_file)
        except Exception:
            pass


def main():

    print("Downloading configs...")

    lines = download_configs()

    configs = []

    for line in lines:

        config = parse_config(line)

        if config:
            configs.append(config)

    print(
        f"Found {len(configs)} "
        f"VLESS/Trojan WS TLS 443 configs."
    )

    working = []

    for index, config in enumerate(
        configs,
        start=1
    ):

        print(
            f"\n[{index}/{len(configs)}] "
            f"Testing {config['server']}"
        )

        if test_config(
            config,
            index
        ):

            working.append(
                config["original"]
            )

    with open(
        "working.txt",
        "w",
        encoding="utf-8"
    ) as f:

        f.write(
            "\n".join(working)
        )

        if working:
            f.write("\n")

    print("\n============================")
    print("CHECK FINISHED")
    print("============================")
    print(
        f"Working configs: "
        f"{len(working)}"
    )
    print(
        f"Total tested: "
        f"{len(configs)}"
    )


if __name__ == "__main__":
    main()
