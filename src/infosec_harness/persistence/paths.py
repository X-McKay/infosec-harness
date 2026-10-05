"""The worker's local workspace, shared by the run store, the recipe cache and snapshots."""

from __future__ import annotations

from pathlib import Path

from infosec_harness.settings import get_settings


def workspace_dir() -> Path:
    """The configured workspace, resolved and created on first use."""
    path = get_settings().workspace_dir.resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path
