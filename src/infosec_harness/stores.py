"""Local content-addressed artifacts, SQLite run metadata, and append-only audit JSONL."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .domain import RunSummary
from .policy import digest, redact


class RestrictedEvidenceError(ValueError):
    pass


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)

    def put_text(self, text: str, *, protected: bool = False) -> str:
        clean, fingerprints = redact(text)
        if fingerprints and not protected:
            raise RestrictedEvidenceError("restricted evidence must not enter ordinary artifact storage")
        artifact_hash = digest(text if protected else clean)
        directory = self.root / "protected" if protected else self.root
        directory.mkdir(exist_ok=True)
        path = directory / artifact_hash.removeprefix("sha256:")
        if not path.exists():
            path.write_text(text if protected else clean, encoding="utf-8")
        return artifact_hash

    def put_json(self, item: Any, *, protected: bool = False) -> str:
        return self.put_text(
            json.dumps(item, sort_keys=True, separators=(",", ":")), protected=protected
        )


class RunStore:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.root = root
        self.db_path = root / "runs.sqlite3"
        self.audit_path = root / "audit.jsonl"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, terminal_state TEXT NOT NULL, summary_json TEXT NOT NULL,
                summary_hash TEXT NOT NULL, created_at TEXT NOT NULL)"""
            )

    def event(self, event_type: str, run_id: str, **fields: Any) -> None:
        record = {"at": datetime.now(UTC).isoformat(), "event": event_type, "run_id": run_id, **fields}
        with self.audit_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    def save(self, summary: RunSummary) -> str:
        raw = summary.model_dump_json()
        summary_hash = digest(raw)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runs VALUES (?, ?, ?, ?, ?)",
                (summary.run_id, summary.terminal_state.value, raw, summary_hash, summary.created_at.isoformat()),
            )
        self.event("run_finished", summary.run_id, terminal_state=summary.terminal_state.value, summary_hash=summary_hash)
        return summary_hash

    def get(self, run_id: str) -> RunSummary:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT summary_json FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown run id: {run_id}")
        return RunSummary.model_validate_json(row[0])

    def save_report_files(self, summary: RunSummary, markdown: str, rendered_json: str, cost: str) -> None:
        reports = self.root / "reports"
        costs = self.root / "costs"
        reports.mkdir(exist_ok=True)
        costs.mkdir(exist_ok=True)
        (reports / f"{summary.run_id}.md").write_text(markdown, encoding="utf-8")
        (reports / f"{summary.run_id}.json").write_text(rendered_json, encoding="utf-8")
        (costs / f"{summary.run_id}.json").write_text(cost, encoding="utf-8")
        self.event("report_generated", summary.run_id, formats=["markdown", "json", "cost_json"])
