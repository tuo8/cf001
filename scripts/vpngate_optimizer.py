#!/usr/bin/env python3
"""Fetch the latest VPN Gate directory and publish every reachable Mihomo OpenVPN node."""
import argparse
import base64
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import requests
import yaml

API = "https://www.vpngate.net/api/iphone/"
CONNECTIVITY_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
)



def load_warp_config(raw=None):
    """Load a private WARP WireGuard profile from the Actions secret JSON."""
    raw = os.getenv("VPNGATE_WARP_CONFIG", "") if raw is None else raw
    if not raw:
        raise RuntimeError("Missing VPNGATE_WARP_CONFIG; refusing direct-mode fallback or publication")
    try:
        config = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("VPNGATE_WARP_CONFIG must be valid JSON") from error
    required = ("private_key", "peer_public_key", "ipv4")
    if any(not isinstance(config.get(key), str) or not config[key].strip() for key in required):
        raise ValueError("VPNGATE_WARP_CONFIG is missing private_key, peer_public_key, or ipv4")
    for key in ("private_key", "peer_public_key"):
        try:
            decoded = base64.b64decode(config[key], validate=True)
        except Exception as error:
            raise ValueError(f"Invalid base64 in WARP {key}") from error
        if len(decoded) != 32:
            raise ValueError(f"WARP {key} must decode to 32 bytes")
    try:
        address = ipaddress.ip_interface(config["ipv4"] if "/" in config["ipv4"] else config["ipv4"] + "/32")
    except ValueError as error:
        raise ValueError("WARP ipv4 must be a valid IPv4 interface address") from error
    if address.version != 4:
        raise ValueError("WARP ipv4 must be IPv4")
    endpoint = config.get("endpoint", "engage.cloudflareclient.com")
    port = int(config.get("port", 2408))
    mtu = int(config.get("mtu", 1280))
    keepalive = int(config.get("keepalive", 25))
    if not isinstance(endpoint, str) or not endpoint or any(ch.isspace() for ch in endpoint):
        raise ValueError("Invalid WARP endpoint")
    if not 1 <= port <= 65535 or not 576 <= mtu <= 9000 or not 0 <= keepalive <= 65535:
        raise ValueError("Invalid WARP port, MTU, or keepalive")
    reserved = config.get("reserved")
    if reserved is not None and (not isinstance(reserved, list) or len(reserved) != 3 or any(type(v) is not int or not 0 <= v <= 255 for v in reserved)):
        raise ValueError("WARP reserved must be a three-byte integer array")
    return {"private_key": config["private_key"], "peer_public_key": config["peer_public_key"],
            "ipv4": str(address.ip), "endpoint": endpoint, "port": port, "mtu": mtu,
            "keepalive": keepalive, "reserved": reserved}


def build_warp_proxy(config):
    peer = {"server": config["endpoint"], "port": config["port"],
            "public-key": config["peer_public_key"], "allowed-ips": ["0.0.0.0/0"],
            "persistent-keepalive": config["keepalive"]}
    if config.get("reserved") is not None:
        peer["reserved"] = config["reserved"]
    return {"name": "WARP", "type": "wireguard", "private-key": config["private_key"],
            "ip": config["ipv4"], "udp": True, "mtu": config["mtu"], "peers": [peer]}


def decode_config(value):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
    except Exception:
        return ""


def parse_profile(config, row):
    blocks, directives = {}, []
    block, buffer = None, []
    for raw in config.splitlines():
        line = raw.strip()
        if block:
            if line.lower() == f"</{block}>":
                blocks[block] = "\n".join(buffer).strip() + "\n"
                block, buffer = None, []
            else:
                buffer.append(raw)
            continue
        if not line or line.startswith(("#", ";")):
            continue
        match = re.fullmatch(r"<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)\s*>", line, re.I)
        if match:
            block = match.group(1).lower()
            continue
        parts = line.split()
        directives.append((parts[0].lower(), parts[1:]))

    if block:
        return None

    def occurrences(key):
        return [value for name, value in directives if name == key]

    def values(key):
        return [value for value in occurrences(key) if value]

    remotes = values("remote")
    if not remotes or len(remotes[0]) < 2 or not blocks.get("ca"):
        return None
    host = remotes[0][0]
    try:
        port = int(remotes[0][1])
    except ValueError:
        return None
    if not host or not 1 <= port <= 65535:
        return None

    proto_values = values("proto")
    proto = proto_values[0][0].lower() if proto_values else "udp"
    if proto in ("tcp", "tcp-client", "tcp4-client", "tcp6-client"):
        proto = "tcp"
    elif proto in ("udp", "udp4", "udp6"):
        proto = "udp"
    else:
        return None

    country = (row.get("CountryLong") or row.get("CountryShort") or "Unknown").strip()
    label = re.sub(r"[^A-Za-z0-9._ -]", "", f"VPNGate {country} {row.get('IP') or host}")[:80]
    node = {
        "name": label,
        "type": "openvpn",
        "server": host,
        "port": port,
        "proto": proto,
        "udp": proto == "udp",
        "username": "vpn",
        "password": "vpn",
        "ca": blocks["ca"],
    }
    for key in ("cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"):
        if blocks.get(key):
            node[key] = blocks[key]
    key_direction = values("key-direction")
    if key_direction:
        node["key-direction"] = key_direction[0][0]
    for key in ("cipher", "data-ciphers-fallback", "auth"):
        found = values(key)
        if found:
            node[key] = found[0][0].upper()
    data_ciphers = values("data-ciphers")
    if data_ciphers:
        node["data-ciphers"] = [
            item.upper()
            for item in re.split(r"[:,\s]+", " ".join(data_ciphers[0]))
            if item
        ]
    compression = occurrences("comp-lzo")
    if compression:
        # OpenVPN accepts both "comp-lzo" and "comp-lzo yes".
        node["comp-lzo"] = compression[0][0].lower() if compression[0] else "yes"
    elif values("compress"):
        node["comp-lzo"] = "yes"

    # Mihomo's OpenVPN outbound has no tls-cipher equivalent. Make this
    # compatibility limitation visible instead of silently dropping it.
    if values("tls-cipher"):
        print(f"兼容性警告 {label}: profile contains tls-cipher; Mihomo outbound cannot map it")

    return {"proxy": node, "country": country}


def parse_csv(text):
    lines = [line for line in text.splitlines() if line.strip()]
    header_index = next(
        (index for index, line in enumerate(lines) if line.lstrip("#").startswith("HostName,")),
        None,
    )
    if header_index is None:
        raise ValueError("VPN Gate CSV header not found")

    rows = csv.DictReader([lines[header_index].lstrip("#")] + lines[header_index + 1 :])
    output, seen = [], set()
    for row in rows:
        if not row.get("HostName") or row["HostName"].startswith("*"):
            continue
        encoded = row.get("OpenVPN_ConfigData_Base64") or row.get("OpenVPN_Config")
        item = parse_profile(decode_config(encoded), row)
        if item:
            proxy = item["proxy"]
            key = (proxy["server"], proxy["port"], proxy["proto"])
            if key not in seen:
                seen.add(key)
                output.append(item)
    return output


def fetch():
    response = requests.get(
        API,
        timeout=40,
        headers={"User-Agent": "cf001-vpngate/1.0", "Cache-Control": "no-cache"},
    )
    response.raise_for_status()
    response.encoding = "utf-8"
    return parse_csv(response.text)


def rank(items):
    """Return every valid node in the latest official VPN Gate directory order."""
    return list(items)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _log_tail(path, limit=5000):
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError:
        return "(Mihomo log unavailable)"


def start_node(node, binary, folder, warp_proxy):
    folder.mkdir(parents=True, exist_ok=True)
    port = free_port()
    config = {
        "mixed-port": port,
        "mode": "rule",
        "log-level": "debug",
        "proxies": [warp_proxy, {**node, "dialer-proxy": "WARP"}],
        "proxy-groups": [{"name": "TEST", "type": "select", "proxies": [node["name"]]}],
        "rules": ["MATCH,TEST"],
    }
    config_path = folder / "test.yaml"
    config_path.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")
    log_path = folder / "mihomo.log"
    log = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [binary, "-f", str(config_path)],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log.flush()
            log.close()
            raise RuntimeError(f"mihomo startup failed: {_log_tail(log_path)}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return process, log, port
        except OSError:
            time.sleep(0.1)
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    log.flush()
    log.close()
    raise RuntimeError(f"mihomo startup timeout: {_log_tail(log_path)}")


def stop_node(process, log):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    log.close()


def check_connectivity(proxy_url):
    """Confirm traffic passes through the selected VPN; do not measure speed or latency."""
    for attempt in range(3):
        for url in CONNECTIVITY_URLS:
            response = None
            try:
                response = requests.get(
                    url,
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=(5, 8),
                    allow_redirects=True,
                    stream=True,
                )
                if response.status_code in (200, 204, 301, 302):
                    return True
            except requests.RequestException:
                pass
            finally:
                if response is not None:
                    response.close()
        if attempt < 2:
            time.sleep(1)
    return False


def probe(item, binary, folder, warp_proxy):
    process = log = None
    error_message = None
    try:
        process, log, port = start_node(item["proxy"], binary, folder, warp_proxy)
        if not check_connectivity(f"http://127.0.0.1:{port}"):
            error_message = "HTTP connectivity probes failed for both configured endpoints"
            return False
        return True
    except Exception as error:
        error_message = f"{type(error).__name__}: {error}"
        return False
    finally:
        if process is not None:
            stop_node(process, log)
        if error_message:
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "failure.txt").write_text(
                f"node: {item['proxy']['name']}\n"
                f"server: {item['proxy']['server']}:{item['proxy']['port']}\n"
                f"reason: {error_message}\n",
                encoding="utf-8",
            )
            print(f"连通性检查失败 {item['proxy']['name']}: {error_message}")
        else:
            shutil.rmtree(folder, ignore_errors=True)


def _run_probes(items, binary, workers, diagnostic_root, warp_proxy):
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 5))) as pool:
        jobs = {
            pool.submit(probe, item, binary, diagnostic_root / str(index), warp_proxy): (index, item)
            for index, item in enumerate(items)
        }
        passed_by_index = {}
        for future in concurrent.futures.as_completed(jobs):
            index, item = jobs[future]
            try:
                if future.result():
                    passed_by_index[index] = item
                    print(f"连通性通过: {item['country']} | {item['proxy']['name']}")
            except Exception as error:
                print(f"probe error {item['proxy']['name']}: {type(error).__name__}: {error}")
    return [passed_by_index[index] for index in sorted(passed_by_index)]


def test_many(items, binary, workers, warp_proxy):
    configured_root = os.getenv("VPNGATE_DIAGNOSTICS_DIR")
    if configured_root:
        diagnostic_root = Path(configured_root)
        diagnostic_root.mkdir(parents=True, exist_ok=True)
        print(f"失败节点诊断日志目录: {diagnostic_root}")
        return _run_probes(items, binary, workers, diagnostic_root, warp_proxy)

    with tempfile.TemporaryDirectory(prefix="vpngate-") as temporary:
        return _run_probes(items, binary, workers, Path(temporary), warp_proxy)


def write_yaml(results, path, warp_proxy):
    nodes = [{**item["proxy"], "dialer-proxy": "WARP"} for item in results]
    if not nodes:
        raise RuntimeError("zero reachable nodes; refusing to publish empty subscription")
    document = {
        "proxies": [warp_proxy] + nodes,
        "proxy-groups": [
            {"name": "VPN Gate 优选", "type": "select", "proxies": [node["name"] for node in nodes]}
        ],
        "rules": ["MATCH,VPN Gate 优选"],
    }
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump(document, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return document


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="vpngate-clash-mi.yaml")
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("VPNGATE_PROBE_WORKERS", "3")),
    )
    parser.add_argument("--parse-only", action="store_true")
    args = parser.parse_args()

    try:
        latest_nodes = fetch()
        candidates = rank(latest_nodes)
        print(
            f"Latest VPN Gate snapshot: parsed={len(latest_nodes)}; "
            f"connectivity candidates={len(candidates)} (all valid nodes)"
        )
        if args.parse_only:
            print("Parse-only: no connectivity checks, YAML output, or publishing.")
            return 0

        warp_config = load_warp_config()
        warp_proxy = build_warp_proxy(warp_config)
        print("WARP WireGuard configuration validated; testing VPN Gate nodes through WARP.")

        binary = shutil.which(os.getenv("MIHOMO_PATH", "mihomo"))
        if not binary:
            raise RuntimeError("Mihomo binary not found")

        reachable = test_many(candidates, binary, args.workers, warp_proxy)
        document = write_yaml(reachable, args.output, warp_proxy)
        print(f"Connectivity passed={len(reachable)}; published nodes={len(document['proxies']) - 1}")
        print("No latency or download-speed tests were performed.")
        return 0
    except Exception as error:
        print(f"VPN Gate task failed: {type(error).__name__}: {str(error)[:160]}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
