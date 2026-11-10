#!/usr/bin/env python3
"""Fetch the latest VPN Gate directory, filter and rank reachable Mihomo OpenVPN nodes by latency, and publish a high-availability subscription."""
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
API_MIRRORS = (
    "https://www.vpngate.net/api/iphone/",
    "http://www.vpngate.net/api/iphone/",
)
CONNECTIVITY_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
)
# Reserved bytes decoded from the current wgcf registration client_id.
# Refresh this value if the WARP registration is replaced.
DEFAULT_WARP_RESERVED = [211, 165, 3]

# Curated Cloudflare WARP Anycast ingress IPs across distinct CIDR blocks
# to prevent single-endpoint UDP blocking in mainland China networks.
DEFAULT_WARP_OPTIMAL_ENDPOINTS = (
    "162.159.192.1",
    "162.159.193.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "188.114.98.1",
)

# AmneziaWG 1.0 pulse obfuscation parameters (can be enabled via VPNGATE_ENABLE_AWG=1 or Worker ?awg=1).
# Disabled by default during CI Mihomo v1.19.33 probes to avoid Mihomo WireGuard parser issue #3033.
DEFAULT_AMNEZIA_WG_OPTION = {
    "jc": 4,
    "jmin": 40,
    "jmax": 70,
    "s1": 0,
    "s2": 0,
    "h1": 1,
    "h2": 2,
    "h3": 3,
    "h4": 4,
}

# Preferred low-latency Asia-Pacific regions for domestic connectivity.
PREFERRED_COUNTRIES = {"JP", "KR", "HK", "TW", "SG", "MY", "TH", "VN"}


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
    # A workflow-level override tests Cloudflare's documented fallback WireGuard ports
    # without asking the user to edit or re-upload the private WARP secret.
    port_override = os.getenv("VPNGATE_WARP_PORT")
    port = int(port_override) if port_override else int(config.get("port", 2408))
    mtu = int(config.get("mtu", 1280))
    keepalive = int(config.get("keepalive", 25))
    if not isinstance(endpoint, str) or not endpoint or any(ch.isspace() for ch in endpoint):
        raise ValueError("Invalid WARP endpoint")
    if not 1 <= port <= 65535 or not 576 <= mtu <= 9000 or not 0 <= keepalive <= 65535:
        raise ValueError("Invalid WARP port, MTU, or keepalive")
    reserved = config["reserved"] if "reserved" in config else DEFAULT_WARP_RESERVED.copy()
    if reserved is not None and (not isinstance(reserved, list) or len(reserved) != 3 or any(type(v) is not int or not 0 <= v <= 255 for v in reserved)):
        raise ValueError("WARP reserved must be a three-byte integer array")

    enable_awg = os.getenv("VPNGATE_ENABLE_AWG", "0").strip().lower() in ("1", "true", "yes")
    awg_option = config.get("amnezia_wg_option")
    if awg_option is None and enable_awg:
        awg_option = DEFAULT_AMNEZIA_WG_OPTION.copy()

    return {
        "private_key": config["private_key"],
        "peer_public_key": config["peer_public_key"],
        "ipv4": str(address.ip),
        "endpoint": endpoint,
        "port": port,
        "mtu": mtu,
        "keepalive": keepalive,
        "reserved": reserved,
        "amnezia_wg_option": awg_option,
    }


def build_warp_proxy(config, name="WARP", endpoint_override=None, port_override=None):
    """Build a Mihomo WireGuard outbound dictionary with optional AmneziaWG obfuscation."""
    endpoint = endpoint_override or config["endpoint"]
    port = int(port_override if port_override is not None else config["port"])
    peer = {
        "server": endpoint,
        "port": port,
        "public-key": config["peer_public_key"],
        "allowed-ips": ["0.0.0.0/0"],
        "persistent-keepalive": config["keepalive"],
    }
    if config.get("reserved") is not None:
        peer["reserved"] = config["reserved"]
    proxy = {
        "name": name,
        "type": "wireguard",
        "private-key": config["private_key"],
        "ip": config["ipv4"],
        "udp": True,
        "mtu": config["mtu"],
        "persistent-keepalive": config["keepalive"],
        "remote-dns-resolve": True,
        "dns": ["1.1.1.1", "1.0.0.1"],
        "peers": [peer],
    }
    awg_option = config.get("amnezia_wg_option")
    if isinstance(awg_option, dict) and awg_option:
        proxy["amnezia-wg-option"] = awg_option.copy()
    return proxy


def build_warp_proxies(config, primary_proxy, verified_ports=None):
    """Build a resilient pool of WARP proxies across multiple Anycast IPs and verified UDP ports."""
    proxies = [primary_proxy]
    seen = {(primary_proxy["peers"][0]["server"], int(primary_proxy["peers"][0]["port"]))}

    raw_endpoints = os.getenv("VPNGATE_WARP_ENDPOINTS", "").strip()
    if raw_endpoints:
        endpoints = [ep.strip() for ep in raw_endpoints.split(",") if ep.strip()]
    else:
        endpoints = list(DEFAULT_WARP_OPTIMAL_ENDPOINTS)

    ports = list(verified_ports) if verified_ports else [int(primary_proxy["peers"][0]["port"]), 2408, 500, 1701, 4500]
    unique_ports = list(dict.fromkeys(p for p in ports if 1 <= int(p) <= 65535))

    # 1. Add alternate verified ports on the primary endpoint
    primary_server = primary_proxy["peers"][0]["server"]
    for alt_port in unique_ports:
        key = (primary_server, int(alt_port))
        if key not in seen:
            seen.add(key)
            proxies.append(
                build_warp_proxy(
                    config,
                    name=f"WARP-Port-{alt_port}",
                    endpoint_override=primary_server,
                    port_override=alt_port,
                )
            )

    # 2. Add curated Anycast IPs rotating across verified ports
    for idx, ep in enumerate(endpoints):
        chosen_port = unique_ports[idx % len(unique_ports)] if unique_ports else 2408
        key = (ep, int(chosen_port))
        if key not in seen:
            seen.add(key)
            proxies.append(
                build_warp_proxy(
                    config,
                    name=f"WARP-优选{idx + 1} ({ep}:{chosen_port})",
                    endpoint_override=ep,
                    port_override=chosen_port,
                )
            )
    return proxies


def warp_port_candidates(config):
    """Return only ports that passed the independent WireGuard handshake and HTTPS probe."""
    raw = os.getenv("VPNGATE_WARP_VERIFIED_PORTS", "").strip()
    if not raw:
        raise RuntimeError("Missing Go WARP probe verified_ports; refusing Mihomo tests or publication")
    try:
        ports = [int(value.strip()) for value in raw.split(",") if value.strip()]
    except ValueError as error:
        raise ValueError("Go WARP probe returned an invalid verified port list") from error
    if not ports or any(not 1 <= port <= 65535 for port in ports):
        raise ValueError("Go WARP probe returned an empty or out-of-range verified port list")
    return list(dict.fromkeys(ports))


def start_warp(warp_proxy, binary, folder):
    """Start a WARP-only Mihomo instance with no other outbound or fallback."""
    folder.mkdir(parents=True, exist_ok=True)
    port = free_port()
    config = {
        "mixed-port": port,
        "mode": "rule",
        "log-level": "debug",
        "proxies": [warp_proxy],
        "proxy-groups": [{"name": "WARP-ONLY", "type": "select", "proxies": ["WARP"]}],
        "rules": ["MATCH,WARP-ONLY"],
    }
    config_path = folder / "warp-only.yaml"
    config_path.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")
    log_path = folder / "mihomo.log"
    log = log_path.open("w", encoding="utf-8")
    process = None
    try:
        process = subprocess.Popen([binary, "-f", str(config_path)], stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"Mihomo WARP-only startup failed: {_log_tail(log_path)}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return process, log, port
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"Mihomo WARP-only startup timeout: {_log_tail(log_path)}")
    except Exception:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        log.flush()
        log.close()
        raise


def check_warp_connectivity(proxy_url):
    """Require successful HTTPS requests through the WARP-only local proxy."""
    for url in CONNECTIVITY_URLS:
        response = None
        try:
            response = requests.get(
                url,
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=(4, 6),
                allow_redirects=False,
                stream=True,
            )
            if response.status_code in (200, 204):
                return True
        except requests.RequestException:
            pass
        finally:
            if response is not None:
                response.close()
    return False


def probe_warp(binary, warp_config, diagnostic_root):
    """Run Mihomo's WARP-only data-plane check on Go-verified ports only."""
    failures = []
    for udp_port in warp_port_candidates(warp_config):
        proxy = build_warp_proxy({**warp_config, "port": udp_port})
        folder = diagnostic_root / "warp-only" / str(udp_port)
        process = log = None
        failure = None
        try:
            process, log, local_port = start_warp(proxy, binary, folder)
            if check_warp_connectivity(f"http://127.0.0.1:{local_port}"):
                stop_node(process, log)
                process = log = None
                shutil.rmtree(folder, ignore_errors=True)
                print(f"WARP-only HTTPS data-plane PASS: UDP port {udp_port}")
                return proxy
            failure = "HTTPS data-plane probes failed through WARP-only proxy"
        except Exception as error:
            failure = f"{type(error).__name__}: {error}"
        finally:
            if process is not None:
                stop_node(process, log)
        failures.append(f"{udp_port}: {failure}")
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "failure.txt").write_text(
            f"WARP UDP port: {udp_port}\nreason: {failure}\n", encoding="utf-8"
        )
        print(f"WARP-only HTTPS data-plane FAIL: UDP port {udp_port}: {failure}")
    raise RuntimeError(
        "WARP-only validation failed on all candidate UDP ports; refusing to test VPN Gate "
        "or publish a new subscription. " + " | ".join(failures)
    )


def decode_config(value):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
    except Exception:
        return ""


def _safe_int(value, default=0):
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


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
    country_short = (row.get("CountryShort") or "").strip().upper()
    ip_text = (row.get("IP") or host).strip()
    # Format node display name as "地区 + IP" (e.g. "Japan 106.168.67.207")
    label = re.sub(r"[^A-Za-z0-9._ -]", "", f"{country} {ip_text}")[:80].strip()
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
        # Explicit OpenVPN/VPNGate defaults so Mihomo does not fall back to unsupported cipher
        "cipher": "AES-128-CBC",
        "auth": "SHA1",
        # Inner OpenVPN MTU must be smaller than outer WARP MTU (1280) to avoid fragmentation blackholes
        "mtu": 1200,
        # Force DNS resolution inside the OpenVPN tunnel (requires non-empty dns list)
        "remote-dns-resolve": True,
        "dns": ["1.1.1.1", "8.8.8.8"],
        "handshake-timeout": 15,
        "ping": 10,
        "ping-restart": 60,
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
        parsed_ciphers = [
            item.upper()
            for item in re.split(r"[:,\s]+", " ".join(data_ciphers[0]))
            if item
        ]
        for fallback_cipher in (node["cipher"], "AES-256-GCM", "AES-128-GCM", "AES-128-CBC"):
            if fallback_cipher and fallback_cipher not in parsed_ciphers:
                parsed_ciphers.append(fallback_cipher)
        node["data-ciphers"] = parsed_ciphers
    node.setdefault("data-ciphers-fallback", node["cipher"])

    compression = occurrences("comp-lzo")
    if compression:
        node["comp-lzo"] = compression[0][0].lower() if compression[0] else "yes"
    elif values("compress"):
        node["comp-lzo"] = "yes"

    if values("tls-cipher"):
        print(f"兼容性警告 {label}: profile contains tls-cipher; Mihomo outbound cannot map it")

    result = {"proxy": node, "country": country}
    if country_short:
        result["country_short"] = country_short
    if row.get("Speed") is not None:
        result["speed_bps"] = _safe_int(row.get("Speed"), 0)
    if row.get("Ping") is not None:
        result["ping_ms"] = _safe_int(row.get("Ping"), 999)
    if row.get("Score") is not None:
        result["score"] = _safe_int(row.get("Score"), 0)
    return result


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
        encoded = row.get("OpenVPN_ConfigFileData_Base64") or row.get("OpenVPN_ConfigData_Base64")
        item = parse_profile(decode_config(encoded), row)
        if item:
            proxy = item["proxy"]
            key = (proxy["server"], proxy["port"], proxy["proto"])
            if key not in seen:
                seen.add(key)
                output.append(item)
    return output


def filter_candidates(items):
    """Pre-filter and prioritize candidates by region, bandwidth, UDP preference, and ping."""
    if not items:
        return []
    min_speed = int(os.getenv("VPNGATE_MIN_SPEED_BPS", "5000000"))    # Default 5 Mbps
    max_ping = int(os.getenv("VPNGATE_MAX_PING_MS", "250"))          # Default 250 ms
    max_candidates = int(os.getenv("VPNGATE_MAX_CANDIDATES", "60"))  # Probe top 60 candidates

    filtered = [
        item for item in items
        if item.get("speed_bps", min_speed) >= min_speed
        and (0 <= item.get("ping_ms", 50) <= max_ping or item.get("ping_ms", 0) == 0)
    ]
    # Fallback to all items if strict threshold filtered out too many nodes
    if len(filtered) < min(12, len(items)):
        filtered = list(items)

    def candidate_sort_key(item):
        is_preferred_region = 0 if item.get("country_short") in PREFERRED_COUNTRIES else 1
        is_udp = 0 if item["proxy"].get("proto") == "udp" else 1
        ping_val = item.get("ping_ms", 500)
        if ping_val <= 0:
            ping_val = 500
        speed_val = item.get("speed_bps", 0)
        score_val = item.get("score", 0)
        return (is_preferred_region, is_udp, ping_val, -speed_val, -score_val)

    enable_pre_sort = os.getenv("VPNGATE_PRE_SORT", "1").strip().lower() not in ("0", "false", "no")
    if enable_pre_sort:
        filtered.sort(key=candidate_sort_key)

    if max_candidates > 0:
        return filtered[:max_candidates]
    return filtered


def fetch():
    last_error = None
    for url in API_MIRRORS:
        try:
            response = requests.get(
                url,
                timeout=40,
                headers={"User-Agent": "cf001-vpngate/2.0", "Cache-Control": "no-cache"},
            )
            response.raise_for_status()
            response.encoding = "utf-8"
            return parse_csv(response.text)
        except Exception as error:
            last_error = error
            print(f"Fetch mirror {url} failed: {type(error).__name__}: {error}")
    raise last_error


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
    chained_node = {
        **node,
        "dialer-proxy": "WARP",
        "udp": True,
        "mtu": min(int(node.get("mtu", 1200)), int(warp_proxy.get("mtu", 1280)) - 80),
        "remote-dns-resolve": True,
        "dns": node.get("dns") or ["1.1.1.1", "8.8.8.8"],
    }
    config = {
        "mixed-port": port,
        "mode": "rule",
        "log-level": "debug",
        "ipv6": False,
        "dns": {
            "enable": True,
            "ipv6": False,
            "default-nameserver": ["1.1.1.1", "8.8.8.8"],
            "nameserver": [
                "https://1.1.1.1/dns-query#WARP",
                "https://8.8.8.8/dns-query#WARP",
            ],
            "proxy-server-nameserver": ["1.1.1.1", "8.8.8.8"],
        },
        "proxies": [warp_proxy, chained_node],
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


def measure_connectivity(proxy_url):
    """Confirm traffic passes through the selected VPN and measure warm tunnel RTT (ms)."""
    for attempt in range(2):
        for url in CONNECTIVITY_URLS:
            response = None
            start_ts = time.monotonic()
            try:
                response = requests.get(
                    url,
                    proxies={"http": proxy_url, "https": proxy_url},
                    timeout=(10, 10),
                    allow_redirects=True,
                    stream=True,
                )
                elapsed_ms = int((time.monotonic() - start_ts) * 1000)
                if response.status_code in (200, 204, 301, 302):
                    response.close()
                    response = None
                    # Perform one quick warm-tunnel ping to measure pure data-plane RTT without cold handshake overhead
                    warm_start = time.monotonic()
                    try:
                        warm_resp = requests.get(
                            url,
                            proxies={"http": proxy_url, "https": proxy_url},
                            timeout=(4, 4),
                            allow_redirects=False,
                            stream=True,
                        )
                        if warm_resp.status_code in (200, 204, 301, 302):
                            elapsed_ms = min(elapsed_ms, int((time.monotonic() - warm_start) * 1000))
                        warm_resp.close()
                    except requests.RequestException:
                        pass
                    return True, elapsed_ms
            except requests.RequestException:
                pass
            finally:
                if response is not None:
                    response.close()
        if attempt < 1:
            time.sleep(1)
    return False, None


def check_connectivity(proxy_url):
    """Backwards-compatible boolean connectivity check."""
    ok, _ = measure_connectivity(proxy_url)
    return ok


def probe(item, binary, folder, warp_proxy):
    process = log = None
    error_message = None
    try:
        process, log, port = start_node(item["proxy"], binary, folder, warp_proxy)
        proxy_url = f"http://127.0.0.1:{port}"
        ok, latency_ms = measure_connectivity(proxy_url)
        if not ok:
            error_message = "HTTP connectivity probes failed for both configured endpoints"
            return False
        if latency_ms is not None:
            item["latency_ms"] = latency_ms
        print(f"连通性通过: {item.get('country', 'Unknown')} | {item['proxy']['name']} ({item.get('latency_ms', 0)}ms)")
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
    max_pool = max(1, min(int(workers), 10))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_pool) as pool:
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
            except Exception as error:
                print(f"probe error {item['proxy']['name']}: {type(error).__name__}: {error}")

        ordered = [passed_by_index[index] for index in sorted(passed_by_index)]
        # Sort by measured latency_ms when present so fastest nodes appear first
        if any("latency_ms" in item for item in ordered):
            ordered.sort(
                key=lambda x: (
                    x.get("latency_ms", 99999),
                    0 if x.get("country_short") in PREFERRED_COUNTRIES else 1,
                    -x.get("speed_bps", 0),
                )
            )
        max_output = int(os.getenv("VPNGATE_MAX_OUTPUT_NODES", "30"))
        if max_output > 0 and len(ordered) > max_output:
            ordered = ordered[:max_output]
        return ordered


def test_many(items, binary, workers, warp_proxy):
    configured_root = os.getenv("VPNGATE_DIAGNOSTICS_DIR")
    if configured_root:
        diagnostic_root = Path(configured_root)
        diagnostic_root.mkdir(parents=True, exist_ok=True)
        print(f"失败节点诊断日志目录: {diagnostic_root}")
        return _run_probes(items, binary, workers, diagnostic_root, warp_proxy)

    with tempfile.TemporaryDirectory(prefix="vpngate-") as temporary:
        return _run_probes(items, binary, workers, Path(temporary), warp_proxy)


def write_yaml(results, path, warp_proxy, warp_config=None, verified_ports=None):
    if warp_config is not None:
        warp_proxies = build_warp_proxies(warp_config, warp_proxy, verified_ports=verified_ports)
    else:
        warp_proxies = [warp_proxy]

    warp_names = [p["name"] for p in warp_proxies]
    dialer_target = os.getenv("VPNGATE_DIALER_PROXY", "WARP").strip() or "WARP"

    nodes = []
    used_names = set(warp_names)
    warp_mtu = int(warp_proxy.get("mtu", 1280))
    for item in results:
        node = {
            **item["proxy"],
            "dialer-proxy": dialer_target,
            "udp": True,
            "mtu": min(int(item["proxy"].get("mtu", 1200)), warp_mtu - 80),
            "remote-dns-resolve": True,
            "dns": item["proxy"].get("dns") or ["1.1.1.1", "8.8.8.8"],
        }
        base_name = str(node.get("name") or "VPNGate node")
        unique_name = base_name
        suffix = 2
        while unique_name in used_names:
            unique_name = f"{base_name} ({suffix})"
            suffix += 1
        node["name"] = unique_name
        used_names.add(unique_name)
        nodes.append(node)
    if not nodes:
        raise RuntimeError("zero reachable nodes; refusing to publish empty subscription")

    openvpn_names = [node["name"] for node in nodes]
    proxy_groups = [
        {
            "name": "出站节点",
            "type": "select",
            "proxies": [
                "⚡ 自动优选 (最快)",
                "🛡️ 故障转移 (稳定)",
                "🌐 WARP 前置池",
                "WARP",
            ] + openvpn_names,
        },
        {
            "name": "⚡ 自动优选 (最快)",
            "type": "url-test",
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 180,
            "tolerance": 50,
            "lazy": False,
            "proxies": openvpn_names + ["WARP"],
        },
        {
            "name": "🛡️ 故障转移 (稳定)",
            "type": "fallback",
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 120,
            "lazy": False,
            "proxies": openvpn_names + warp_names,
        },
        {
            "name": "🌐 WARP 前置池",
            "type": "url-test",
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 180,
            "tolerance": 30,
            "lazy": False,
            "proxies": warp_names,
        },
    ]

    document = {
        "ipv6": False,
        "tun": {
            "route-exclude-address": [
                "10.0.0.0/8",
                "127.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
        },
        "dns": {
            "enable": True,
            "ipv6": False,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": [
                "*.lan",
                "*.local",
                "localhost.ptlogin2.qq.com",
                "ipv6.*",
                "*.ipv6.*",
            ],
            "default-nameserver": ["1.1.1.1", "8.8.8.8", "223.5.5.5"],
            "nameserver": [
                "https://1.1.1.1/dns-query#WARP",
                "https://8.8.8.8/dns-query#WARP",
            ],
            "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29", "1.1.1.1"],
        },
        "proxies": warp_proxies + nodes,
        "proxy-groups": proxy_groups,
        "rules": ["MATCH,出站节点"],
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
        default=int(os.getenv("VPNGATE_PROBE_WORKERS", "6")),
    )
    parser.add_argument("--parse-only", action="store_true")
    args = parser.parse_args()

    try:
        latest_nodes = fetch()
        candidates = filter_candidates(latest_nodes)
        print(
            f"Latest VPN Gate snapshot: parsed={len(latest_nodes)}; "
            f"filtered candidates={len(candidates)} (prioritized by region, speed & ping)"
        )
        if args.parse_only:
            print("Parse-only: no connectivity checks, YAML output, or publishing.")
            return 0

        warp_config = load_warp_config()
        verified_ports = warp_port_candidates(warp_config)

        binary = shutil.which(os.getenv("MIHOMO_PATH", "mihomo"))
        if not binary:
            raise RuntimeError("Mihomo binary not found")

        configured_root = os.getenv("VPNGATE_DIAGNOSTICS_DIR")
        if configured_root:
            diagnostic_root = Path(configured_root)
            diagnostic_root.mkdir(parents=True, exist_ok=True)
            warp_proxy = probe_warp(binary, warp_config, diagnostic_root)
            reachable = test_many(candidates, binary, args.workers, warp_proxy)
        else:
            with tempfile.TemporaryDirectory(prefix="cf001-diagnostics-") as temporary:
                diagnostic_root = Path(temporary)
                warp_proxy = probe_warp(binary, warp_config, diagnostic_root)
                reachable = test_many(candidates, binary, args.workers, warp_proxy)

        print(
            f"Go WireGuard handshake + HTTPS and Mihomo WARP-only validation passed on UDP port {warp_proxy['peers'][0]['port']}; "
            "tested and ranked VPN Gate nodes through WARP."
        )
        document = write_yaml(
            reachable,
            args.output,
            warp_proxy,
            warp_config=warp_config,
            verified_ports=verified_ports,
        )
        print(f"Connectivity passed={len(reachable)}; total published proxies={len(document['proxies'])}")
        return 0
    except Exception as error:
        print(f"VPN Gate task failed: {type(error).__name__}: {str(error)[:160]}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
