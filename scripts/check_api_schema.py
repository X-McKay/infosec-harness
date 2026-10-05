"""Fail on OpenAPI contract drift without rewriting generated files."""
from __future__ import annotations

import json
from pathlib import Path

from infosec_harness.web import app


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "ui/openapi.json"
    if json.loads(path.read_text()) != app.openapi():
        print("OpenAPI schema drift: run `just regenerate` and review the generated changes.")
        return 1
    print("OpenAPI schema matches application contracts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
