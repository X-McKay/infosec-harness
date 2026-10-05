#!/usr/bin/env python3
"""Freeze or execute one reviewed production Temporal graph qualification trial."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from infosec_harness.qualification.broker.graph import execute, freeze


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("freeze", "execute"))
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--pilot-manifest", type=Path)
    parser.add_argument("--phase", choices=("direct", "native"))
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    if args.mode == "freeze":
        if args.pilot_manifest is None or args.phase is None:
            parser.error("Freeze requires --pilot-manifest and --phase")
        freeze(args.pilot_manifest, args.manifest, args.phase)
        print("FROZEN_PRODUCTION_GRAPH_MANIFEST_READY")
        return 0
    if args.manifest_sha256 is None:
        parser.error("Execute requires the reviewed --manifest-sha256")
    result = asyncio.run(execute(args.manifest, args.manifest_sha256))
    print(json.dumps(result, sort_keys=True))
    return 0 if all(result.get(key) == "passed" for key in ("graph", "replay", "workflow_cleanup", "worker_cleanup")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
