"""Accepted eval results, stored in the repository and tied to the commit that produced them.

Every run already lands in the experiment store, which is the right place for *all* of them:
queryable, incremental, and cheap to write. It is the wrong place for the handful that matter
later. That database is a local scratch file in practice, it is not reviewed, it does not
travel with a clone or a release, and the number you want six weeks from now -- "what did
`verdict` score on sonnet before we changed the prompt" -- is exactly the one that is gone.

So the two roles are split, the way agent-playbook 02 lays the directories out:

* **The experiment store** holds every run. Ephemeral, complete, queryable.
* **`evals/baselines/<agent>/<tier>.json`** holds the *accepted* result per agent per model.
  Committed, reviewed in a pull request like any other change, and readable without the
  database that produced it.

A baseline is a claim about a commit and an agent's whole dataset, so these rules are enforced
rather than documented:

* It must come from an experiment recorded as `complete`. A truncated run's metrics cover only
  the cases that happened to run, and a run with no recorded status proves nothing either way.
* It must cover the full dataset (`split == "full"`). A calibration or held-out split is a
  different denominator, and pinning one silently redefines what every later run is read
  against.
* It must have called a model. A stub run's numbers exercise the plumbing, not the agent.
* The working tree must be clean, and the run must carry a commit. A baseline recorded from a
  dirty tree names a commit that did not contain the code it measured.

All are refusals, not warnings. A baseline that quietly lies is worse than no baseline: it
becomes the thing every later comparison is measured against.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from infosec_harness._io import write_json
from infosec_harness.evals.provenance import code_version
from infosec_harness.resources import source_checkout

SCHEMA_VERSION = 1

# The metrics a baseline pins. Deliberately not "whatever the run produced": a baseline is a
# contract, and one that absorbs every new key silently changes what it promises.
BASELINE_METRICS = (
    "task_success_rate", "schema_validity_rate", "average_cost_usd",
    "p95_model_requests", "budget_exhausted_count", "n", "n_planned",
)


class BaselineRefused(ValueError):
    """The run cannot be recorded as a baseline, with the reason stated."""


def baselines_dir() -> Path:
    """`evals/baselines/` in the checkout. Baselines are project files: they are reviewed, not
    deployed, so they are deliberately absent from the wheel."""
    root = source_checkout()
    if root is None:
        raise BaselineRefused(
            "baselines live in the repository (`evals/baselines/`) and this is an installed "
            "copy with no checkout. Run from a source tree.")
    return root / "evals" / "baselines"


def baseline_path(agent: str, tier: str) -> Path:
    return baselines_dir() / agent / f"{tier}.json"


@dataclass(frozen=True)
class Baseline:
    agent: str
    model_tier: str
    model_name: str
    pricing: str
    git_commit: str
    harness_version: str
    config_hash: str
    dataset_version: str
    repetitions: int
    experiment_id: str
    recorded_at: str
    metrics: dict[str, Any]
    distributions: dict[str, Any]

    def as_dict(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, **self.__dict__}


def from_experiment(row: Any) -> Baseline:
    """Build a baseline from an experiment row, refusing every case that would make it lie."""
    metrics = row.metrics or {}
    status = metrics.get("status")
    if status is None:
        raise BaselineRefused(
            f"experiment {row.id} records no status, so nothing says every planned case ran. "
            f"Re-run it before recording a baseline.")
    if status != "complete":
        raise BaselineRefused(
            f"experiment {row.id} is {status}: it scored "
            f"{metrics.get('n', 0)}/{metrics.get('n_planned', '?')} "
            f"case runs, so its metrics describe a different dataset than the next run will. "
            f"Re-run it to completion before recording a baseline.")
    split = (metrics.get("comparison_identity") or {}).get("split")
    if split != "full":
        raise BaselineRefused(
            f"experiment {row.id} ran the {split or 'unrecorded'} split, not the full dataset, "
            f"so its numbers are over a different case set than a baseline promises. Run "
            f"`harness eval run {row.agent}` without a group filter.")
    if row.pricing == "stub" or str(row.model_name or "").startswith("stub:"):
        raise BaselineRefused(
            f"experiment {row.id} ran against the stub model, which exercises the eval "
            f"machinery and measures no agent. Record a baseline from a live model run.")
    if row.git_dirty:
        raise BaselineRefused(
            f"experiment {row.id} was run with a dirty working tree, so it does not describe "
            f"commit {row.git_sha[:12] or '(none)'}. Commit the change and re-run: a baseline "
            f"that names the wrong commit cannot be reproduced or bisected.")
    if not row.git_sha:
        raise BaselineRefused(
            f"experiment {row.id} carries no commit, so there is nothing to tie the result to.")
    return Baseline(
        agent=row.agent,
        model_tier=row.model_tier or "unknown",
        model_name=row.model_name,
        pricing=row.pricing,
        git_commit=row.git_sha,
        harness_version=row.harness_version,
        config_hash=row.config_hash,
        dataset_version=row.dataset_version,
        repetitions=row.repetitions,
        experiment_id=row.id,
        recorded_at=datetime.now(UTC).isoformat(),
        metrics={k: (row.metrics or {}).get(k) for k in BASELINE_METRICS},
        distributions=(row.metrics or {}).get("distributions", {}),
    )


def save(baseline: Baseline) -> Path:
    path = baseline_path(baseline.agent, baseline.model_tier)
    write_json(path, baseline.as_dict(), sort_keys=True)
    return path


def _read(path: Path) -> Baseline:
    data = json.loads(path.read_text())
    data.pop("schema_version", None)
    return Baseline(**data)


def load(agent: str, tier: str) -> Baseline | None:
    path = baseline_path(agent, tier)
    return _read(path) if path.is_file() else None


def load_all(agent: str | None = None) -> list[Baseline]:
    """Every stored baseline, newest-agent-first by name. Missing directory means none yet."""
    try:
        root = baselines_dir()
    except BaselineRefused:
        return []
    if not root.is_dir():
        return []
    return [_read(path) for path in sorted(root.glob("*/*.json"))
            if not agent or path.parent.name == agent]


def drift(baseline: Baseline, metrics: dict) -> list[tuple[str, Any, Any]]:
    """`(metric, was, now)` for every pinned metric that moved. Empty means no change."""
    moved = []
    for key, was in baseline.metrics.items():
        now = metrics.get(key)
        if was != now:
            moved.append((key, was, now))
    return moved


def staleness(baseline: Baseline) -> str | None:
    """A one-line note when the baseline no longer describes the current code, else None."""
    current = code_version()
    if not current.git_commit or baseline.git_commit == current.git_commit:
        return None
    return (f"recorded at {baseline.git_commit[:12]}, currently at {current.label()} -- "
            f"the code has moved since this number was measured")
