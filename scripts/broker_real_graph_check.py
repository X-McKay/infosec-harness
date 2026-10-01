#!/usr/bin/env python3
"""Freeze or execute one reviewed production Temporal graph qualification phase."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests/runtime"))
from broker_real_graph_fixture import execute, freeze  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "execute"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--pilot-manifest", type=Path)
    parser.add_argument("--phase", choices=("direct", "native"))
    parser.add_argument("--infrastructure-correction", choices=("guest-visible-tmpdir",))
    args = parser.parse_args()
    if args.mode == "freeze":
        if args.pilot_manifest is None or args.phase is None:
            parser.error("Freeze requires pilot manifest and phase")
        freeze(args.pilot_manifest, args.manifest, args.phase, infrastructure_correction=args.infrastructure_correction)
        print("FROZEN_PRODUCTION_GRAPH_MANIFEST_READY")
        return 0
    result = asyncio.run(execute(args.manifest))
    print(json.dumps(result, sort_keys=True))
    return 0 if all(result.get(key) == "passed" for key in ("graph", "replay", "workflow_cleanup", "worker_cleanup")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
