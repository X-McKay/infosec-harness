"""Report the native mutation-admission ledger occupancy for this checkout's gateway, read-only.

Run as root inside the checkout-owned Linux guest. It resolves the running gateway's open
SQLite database through the verified gateway process, opens it in read-only query mode with the
live WAL, and prints aggregate counts only: no payloads, request ids or credentials. The quota
comes from the gateway's TOML (the patched key) or the pinned default of 1000.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import time
from pathlib import Path


def gateway_database(base: Path) -> Path:
    pid = int((base / "gateway.pid").read_text().strip())
    process = Path("/proc") / str(pid)
    exe = os.readlink(process / "exe")
    if not exe.startswith(str(base / "bin/openshell-gateway")):
        raise SystemExit("gateway.pid does not name this checkout's gateway binary")
    for descriptor in (process / "fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        if target.endswith("/openshell.db"):
            return Path(target)
    raise SystemExit("gateway has no open openshell.db descriptor")


def quota(base: Path) -> int:
    text = (base / "gateway-conf/gateway.toml").read_text()
    match = re.search(r"(?m)^max_mutation_admissions_per_caller\s*=\s*(\d+)", text)
    return int(match.group(1)) if match else 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout-id", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{10}", args.checkout_id) or os.geteuid() != 0:
        raise SystemExit("requires root in the guest and a valid checkout identity")
    base = Path("/var/lib/ih-openshell") / args.checkout_id
    database = gateway_database(base)
    connection = sqlite3.connect(f"file:{database}?mode=ro", uri=True)
    connection.execute("PRAGMA query_only=ON")
    retained = connection.execute(
        "select count(*) from objects where object_type = 'mutation_admission_v1'"
    ).fetchone()[0]
    print(json.dumps({"observed_at_ms": int(time.time() * 1000), "retained": retained,
                      "quota": quota(base), "read_only": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
