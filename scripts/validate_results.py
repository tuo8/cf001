
#!/usr/bin/env python3
import ipaddress
import os
import sys
from pathlib import Path

source = Path(
    os.environ.get("RESULT_FILE", "dist/alive.txt")
)

if not source.is_file():
    print(f"ERROR: result file missing: {source}")
    sys.exit(1)

valid = []
invalid = []

for raw in source.read_text(
    encoding="utf-8-sig"
).splitlines():
    line = raw.strip()

    if not line or line.startswith("#"):
        continue

    # 支持 IP:PORT 格式；不接受带注释的代理 URI
    address = line.split("#", 1)[0].strip()
    host = address

    if address.startswith("[") and "]" in address:
        host = address[1:address.index("]")]
    elif address.count(":") == 1:
        host = address.rsplit(":", 1)[0]

    try:
        ipaddress.ip_address(host)
        valid.append(line)
    except ValueError:
        invalid.append(line)

if not valid:
    print("ERROR: no valid IP entries; refusing publication.")
    sys.exit(1)

if invalid:
    print(f"WARNING: ignored {len(invalid)} invalid lines.")

print(f"Validated {len(valid)} IP entries.")
