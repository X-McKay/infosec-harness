"""Bounded, controller-only review and operational helpers."""

from __future__ import annotations

import difflib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .domain import SecurityContextBundle, Usage
from .policy import PolicyError, canonical_path, digest, redact
from .stores import RunStore

MAX_DIFF_LINES = 240


def bounded_diff(repo: Path, before: str, after: str) -> dict[str, Any]:
    before_path = canonical_path(repo, before)
    after_path = canonical_path(repo, after)
    if not before_path.is_file() or not after_path.is_file():
        raise PolicyError("diff inputs must be regular in-scope files")
    before_text, before_secrets = redact(before_path.read_text(encoding="utf-8", errors="replace"))
    after_text, after_secrets = redact(after_path.read_text(encoding="utf-8", errors="replace"))
    if before_secrets or after_secrets:
        raise PolicyError("restricted evidence discovered")
    lines = list(
        difflib.unified_diff(
            before_text.splitlines(), after_text.splitlines(), fromfile=before, tofile=after, lineterm=""
        )
    )
    truncated = len(lines) > MAX_DIFF_LINES
    lines = lines[:MAX_DIFF_LINES]
    return {
        "before": before,
        "after": after,
        "diff": lines,
        "truncated": truncated,
        "diff_hash": digest("\n".join(lines)),
        "coverage": ["bounded unified diff"],
        "deferred_surfaces": ["callers/callees", "runtime configuration", "active validation"],
    }


def load_context(path: Path) -> SecurityContextBundle:
    return SecurityContextBundle.model_validate(json.loads(path.read_text(encoding="utf-8")))


def validate_context(bundle: SecurityContextBundle) -> None:
    if bundle.expires_at <= bundle.as_of:
        raise PolicyError("context bundle expiry must follow collection time")
    for fact in bundle.facts:
        required = {"fact_id", "source", "collected_at", "sensitivity", "evidence_class"}
        if not required.issubset(fact):
            raise PolicyError("context fact lacks provenance fields")


def compare_runs(store: RunStore, left_id: str, right_id: str) -> dict[str, Any]:
    left, right = store.get(left_id), store.get(right_id)
    return {
        "left_run": left_id,
        "right_run": right_id,
        "terminal_states": [left.terminal_state.value, right.terminal_state.value],
        "finding_delta": len(right.findings) - len(left.findings),
        "cost_delta_usd": round(right.estimated_cost_usd - left.estimated_cost_usd, 6),
        "policy_denial_delta": right.safety_summary["policy_denials"] - left.safety_summary["policy_denials"],
        "same_dependency_closure": left.dependency_closure_hash == right.dependency_closure_hash,
    }


def retention_audit(data_root: Path) -> dict[str, Any]:
    root = data_root.resolve()
    return {
        "at": datetime.now(UTC).isoformat(),
        "data_root": str(root),
        "artifact_count": sum(1 for path in (root / "artifacts").rglob("*") if path.is_file()),
        "protected_artifact_count": sum(
            1 for path in (root / "artifacts" / "protected").glob("*") if path.is_file()
        )
        if (root / "artifacts" / "protected").exists()
        else 0,
        "report_count": sum(1 for path in (root / "reports").glob("*.json")) if (root / "reports").exists() else 0,
        "action": "audit_only_no_deletion",
    }


def reconcile_cost(store: RunStore, run_id: str, provider_usage: dict[str, Any]) -> dict[str, Any]:
    """Compare imported provider usage to a sealed run; never rewrites original accounting."""
    run = store.get(run_id)
    reported = Usage.model_validate(provider_usage)
    recorded = run.usage
    return {
        "run_id": run_id,
        "recorded_usage": recorded.model_dump(),
        "provider_usage": reported.model_dump(),
        "matches": recorded == reported,
        "adjustment_required": recorded != reported,
        "original_cost_usd": run.estimated_cost_usd,
    }
