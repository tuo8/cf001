
#!/usr/bin/env bash
# Cloudflare 按地区筛选优选 IP
# 支持 OUTPUT_DIR 环境变量，并额外生成纯 IP 清单 alive.txt

set -euo pipefail
cd "$(dirname "$0")"

CFST_BIN="./cfst"
URL="https://speed.cloudflare.com/__down?bytes=100000"
COLOS="${1:-HKG,NRT,KHH,TPE,SIN,ICN,LAX,SJC,SEA,FRA}"
TOP_N="${2:-4}"
LABEL="${3:-电信优选}"
PORT=443
OUT_DIR="${OUTPUT_DIR:-${HOME}/Desktop/Cloudflare优选IP}"

ABUSEIPDB_KEY="${ABUSEIPDB_KEY:-}"
IPDATA_KEY="${IPDATA_KEY:-}"
RISK_MAX="${RISK_MAX:-60}"

mkdir -p "$OUT_DIR"

if [[ ! -x "$CFST_BIN" ]]; then
  echo "错误：找不到可执行的 CFST 程序：$CFST_BIN" >&2
  echo "请确认 cfst 与本脚本位于同一目录，并具有执行权限。" >&2
  exit 1
fi

echo "==> [1/3] 开始 CFST 测速：$COLOS"

if ! "$CFST_BIN" -httping -dd -url "$URL" \
  -cfcolo "$COLOS" -tl 300 -tlr 0.2 -n 100 -o result.csv; then
  echo "错误：CFST 测速失败。" >&2
  exit 1
fi

if [[ ! -s result.csv ]]; then
  echo "错误：result.csv 不存在或为空。" >&2
  exit 1
fi

echo "==> [2/3] 解析结果、补测下载速度和 IP 属性"

COLOS="$COLOS" TOP_N="$TOP_N" LABEL="$LABEL" PORT="$PORT" \
OUT_DIR="$OUT_DIR" ABUSEIPDB_KEY="$ABUSEIPDB_KEY" \
IPDATA_KEY="$IPDATA_KEY" RISK_MAX="$RISK_MAX" \
env -u PYTHONPATH python3 <<'PYEOF'
import csv
import os
import collections
import datetime
import subprocess
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor

colo_csv = os.environ["COLOS"]
top_n = int(os.environ["TOP_N"])
label = os.environ["LABEL"]
port = os.environ["PORT"]
out_dir = os.environ["OUT_DIR"]
abuse_key = os.environ.get("ABUSEIPDB_KEY", "")
ipdata_key = os.environ.get("IPDATA_KEY", "")
risk_max = int(os.environ.get("RISK_MAX", "60"))

if top_n < 1:
    raise SystemExit("TOP_N 必须大于 0")
if not 0 <= risk_max <= 100:
    raise SystemExit("RISK_MAX 必须在 0 到 100 之间")

DL_URL = "https://speed.cloudflare.com/__down?bytes=2000000"

REGION_NAMES = {
    "HKG": "香港", "NRT": "东京", "KHH": "高雄",
    "TPE": "台北", "SIN": "新加坡", "ICN": "首尔",
    "LAX": "洛杉矶", "SJC": "圣何塞", "SEA": "西雅图",
    "FRA": "法兰克福",
}
requested = [
    c.strip().upper()
    for c in colo_csv.split(",")
    if c.strip()
]

with open("result.csv", newline="", encoding="utf-8-sig") as f:
    rows = list(csv.DictReader(f))

if not rows:
    raise SystemExit("CFST 没有返回任何测速结果")

groups = collections.defaultdict(list)

for row in rows:
    colo = (row.get("地区码") or "N/A").strip()
    try:
        latency = float(row.get("平均延迟") or 9999)
    except (ValueError, TypeError):
        latency = 9999

    raw_ip = (row.get("IP 地址") or "").strip()
    try:
        ipaddress.ip_address(raw_ip)
    except ValueError:
        continue

    groups[colo].append((latency, row))


def curl_json(url, headers=None, timeout=12):
    cmd = ["curl", "-fsS", "--max-time", str(timeout)]
    for key, value in (headers or {}).items():
        cmd += ["-H", f"{key}: {value}"]
    cmd.append(url)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 3
        )
        if result.returncode != 0:
            return {}
        return json.loads(result.stdout or "{}")
    except Exception:
        return {}


def dl_mbps(ip):
    try:
        result = subprocess.run(
            [
                "curl", "-sS", "-o", "/dev/null",
                "-w", "%{speed_download}",
                "--max-time", "8",
                "--resolve", f"speed.cloudflare.com:{port}:{ip}",
                DL_URL
            ],
            capture_output=True, text=True, timeout=13
        )
        if result.returncode != 0:
            return 0.0
        return float(result.stdout or 0) * 8 / 1_000_000
    except Exception:
        return 0.0


def purity_check(ip):
    result = {
        "risk": None, "abuse": None, "idc": None,
        "native": None, "threats": [], "blocklists": 0
    }

    # ProxyCheck：机房/托管类型判断
    data = curl_json(
        f"https://proxycheck.io/v2/{ip}?key=free&vpn=1",
        timeout=10
    )
    info = data.get(ip, {}) if isinstance(data, dict) else {}
    if isinstance(info, dict) and "type" in info:
        result["idc"] = str(info["type"]).lower() in (
            "business", "hosting", "education"
        )

    # IPinfo：anycast 标记
    data = curl_json(f"https://ipinfo.io/{ip}/json", timeout=10)
    if isinstance(data, dict) and "anycast" in data:
        result["native"] = not bool(data["anycast"])

    # AbuseIPDB：举报置信度
    if abuse_key:
        data = curl_json(
            "https://api.abuseipdb.com/api/v2/check"
            f"?ipAddress={ip}&maxAgeInDays=90",
            headers={
                "Key": abuse_key,
                "Accept": "application/json"
            },
            timeout=12
        )
        details = data.get("data", {}) if isinstance(data, dict) else {}
        if "abuseConfidenceScore" in details:
            try:
                result["abuse"] = int(details["abuseConfidenceScore"])
            except (ValueError, TypeError):
                pass

    # ipdata：威胁标记
    if ipdata_key:
        data = curl_json(
            f"https://api.ipdata.co/{ip}/threat?api-key={ipdata_key}",
            timeout=10
        )
        if isinstance(data, dict):
            if "is_datacenter" in data:
                result["idc"] = bool(data["is_datacenter"])

            flags = (
                ("is_known_attacker", "攻击者"),
                ("is_known_abuser", "滥用者"),
                ("is_threat", "威胁"),
                ("is_proxy", "代理"),
                ("is_tor", "Tor"),
            )
            for key, title in flags:
                if data.get(key):
                    result["threats"].append(title)

            if isinstance(data.get("blocklists"), list):
                result["blocklists"] = len(data["blocklists"])

    # 本地合成风险分；它不是任何一家服务商的官方评分
    risk = 0
    if result["idc"] is True:
        risk += 25
    if result["native"] is False:
        risk += 10
    if "Tor" in result["threats"]:
        risk += 40
    if "攻击者" in result["threats"]:
        risk += 30
    if "滥用者" in result["threats"] or "威胁" in result["threats"]:
        risk += 20
    if "代理" in result["threats"]:
        risk += 10

    risk += min(15, result["blocklists"] * 5)
    if result["abuse"] is not None:
        risk += round(result["abuse"] * 0.5)

    result["risk"] = min(risk, 100)
    return result


def fmt_purity(data):
    parts = []
    if data.get("risk") is not None:
        parts.append(f"风控{data['risk']}%")
    if data.get("abuse") is not None and data["abuse"] > 0:
        parts.append(f"举报{data['abuse']}%")
    if data.get("threats"):
        parts.append("威胁:" + "/".join(data["threats"]))

    if data.get("idc") is True:
        parts.append("机房IP")
    elif data.get("idc") is False:
        parts.append("非机房IP")

    if data.get("native") is True:
        parts.append("原生IP")
    elif data.get("native") is False:
        parts.append("广播IP")

    return (" " + " ".join(parts)) if parts else ""


# 每个地区按延迟选取 Top N
picks = {}
jobs = []

for colo in requested:
    if colo not in groups:
        continue

    top = sorted(groups[colo], key=lambda item: item[0])[:top_n]
    picks[colo] = []

    for latency, row in top:
        ip = row["IP 地址"].strip()
        picks[colo].append((latency, ip, 0.0, None))
        jobs.append(ip)

# 并发补测下载速度与 IP 属性
unique_ips = list(dict.fromkeys(jobs))

with ThreadPoolExecutor(max_workers=10) as pool:
    speed_values = list(pool.map(dl_mbps, unique_ips))
    purity_values = list(pool.map(purity_check, unique_ips))

speeds = dict(zip(unique_ips, speed_values))
purities = dict(zip(unique_ips, purity_values))

for colo in picks:
    picks[colo] = [
        (latency, ip, speeds.get(ip, 0.0), purities.get(ip))
        for latency, ip, _, _ in picks[colo]
    ]

today = datetime.date.today().isoformat()
lines = [f"Cloudflare 优选 IP（{today}）", "=" * 60]
alive_ips = []

for colo in requested:
    name = REGION_NAMES.get(colo, colo)

    if colo not in picks:
        lines.append(f"# {colo}（{name}）：本轮未测到可用 IP")
        continue

    kept = []
    filtered = []

    for latency, ip, mbps, purity in picks[colo]:
        if purity and purity["risk"] > risk_max:
            filtered.append((latency, ip, mbps, purity))
        else:
            kept.append((latency, ip, mbps, purity))

    lines.append(f"# {colo}（{name}）：")

    region_path = os.path.join(out_dir, f"{colo}-{name}.txt")
    with open(region_path, "w", encoding="utf-8") as f:
        f.write(f"# {colo}（{name}）Top{len(kept)}（{today}）\n")

        for latency, ip, mbps, purity in kept:
            alive_ips.append(ip)
            line = (
                f"{ip}:{port}#{colo} {label}"
                f"[{latency:.0f}ms {mbps:.2f}Mbps]"
                f"{fmt_purity(purity or {})}"
            )
            lines.append(line)
            f.write(line + "\n")

    if filtered:
        detail = ", ".join(
            f"{ip}[风控{purity['risk']}%]"
            for _, ip, _, purity in filtered
        )
        lines.append(f"  风控>{risk_max}% 已过滤 {len(filtered)} 个：{detail}")

# 输出汇总文本
with open(
    os.path.join(out_dir, "最优IP-汇总.txt"),
    "w", encoding="utf-8"
) as f:
    f.write("\n".join(lines) + "\n")

# 输出 CFST 原始结果 CSV
with open(
    os.path.join(out_dir, "全部结果.csv"),
    "w", encoding="utf-8-sig", newline=""
) as f:
    writer = csv.writer(f)
    writer.writerow([
        "IP地址", "已发送", "已接收", "丢包率",
        "平均延迟(ms)", "下载速度(MB/s)", "地区码"
    ])
    for row in rows:
        writer.writerow([
            row.get("IP 地址", ""),
            row.get("已发送", ""),
            row.get("已接收", ""),
            row.get("丢包率", ""),
            row.get("平均延迟", ""),
            row.get("下载速度(MB/s)", ""),
            row.get("地区码", "")
        ])

# 独立 IP 清单：每行一个 IP，不带端口、地区或说明文字
with open(
    os.path.join(out_dir, "alive.txt"),
    "w", encoding="utf-8"
) as f:
    unique_alive = list(dict.fromkeys(alive_ips))
    if unique_alive:
        f.write("\n".join(unique_alive) + "\n")

print("\n".join(lines))
print(f"\n输出目录：{out_dir}")
print(f"独立 IP 清单：{os.path.join(out_dir, 'alive.txt')}")
print(f"本轮筛选出 {len(set(alive_ips))} 个 IP")
PYEOF

echo "==> [3/3] 完成"
