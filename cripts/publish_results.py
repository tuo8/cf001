
#!/usr/bin/env python3
import os
import shutil
import sys
import tempfile
from pathlib import Path

source = Path(
    os.environ.get("RESULT_FILE", "dist/alive.txt")
)
destination = Path(
    os.environ.get("PUBLISH_FILE", "public/alive.txt")
)

if not source.is_file() or source.stat().st_size == 0:
    print("ERROR: source is missing or empty.")
    sys.exit(1)

destination.parent.mkdir(parents=True, exist_ok=True)

# 在目标目录中先写临时文件，再原子替换
fd, temporary = tempfile.mkstemp(
    prefix=".alive-",
    dir=str(destination.parent)
)
os.close(fd)

try:
    shutil.copyfile(source, temporary)
    os.replace(temporary, destination)
except Exception:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise

print(f"Published {destination}")
