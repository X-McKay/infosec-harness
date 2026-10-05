"""Experiment overlay files: per-agent spec fragments, pinned to the spec they were written for.

An overlay records one variable against a committed spec. Applied to a later spec it measures
something else -- an overlay that replaces ``instructions`` silently reverts every instruction
change made since -- so each agent entry declares the ``base_version`` (the spec's
``metadata.version``) it was authored against, and a mismatch is refused rather than run.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml


class StaleOverlay(ValueError):
    """The overlay was written against a different version of the agent's spec."""


def load_overlay(path: Path) -> dict[str, dict[str, Any]]:
    """Read an overlay file and check every entry against the current spec version."""
    from infosec_harness.agents.registry import load_spec

    document = yaml.safe_load(Path(path).read_text())
    if not isinstance(document, Mapping) or not document:
        raise ValueError(f"{path}: an overlay maps agent names to spec fragments")
    overlay: dict[str, dict[str, Any]] = {}
    for agent, fragment in document.items():
        if not isinstance(fragment, Mapping):
            raise ValueError(f"{path}: the overlay for {agent!r} must be a mapping")
        fragment = dict(fragment)
        declared = fragment.pop("base_version", None)
        current = str((load_spec(str(agent)).metadata or {}).get("version"))
        if declared is None:
            raise StaleOverlay(
                f"{path}: the overlay for {agent!r} declares no base_version, so it cannot be "
                f"checked against the current spec ({current})")
        if str(declared) != current:
            raise StaleOverlay(
                f"{path}: the overlay for {agent!r} was written against spec version "
                f"{declared}, but the current spec is {current}. Re-derive the overlay from "
                "the current spec before running it; applied as-is it measures a different "
                "change than the one it records")
        overlay[str(agent)] = fragment
    return overlay
