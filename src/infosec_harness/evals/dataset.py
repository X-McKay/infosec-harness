"""The one loader for agent eval datasets, and the identity of the cases a run used.

An agent's dataset lives beside its spec, at ``<agents_dir>/<agent>/evals/dataset.yaml``, and is
resolved with the same rule the registry uses for the spec (``settings.agents_dir``). A caller
may name another file instead -- the sealed held-out datasets under ``evals/heldout/`` are run
this way -- and everything downstream (the runner, coverage, calibration, the release report)
reads the cases, version, identity and path from the :class:`Dataset` it was given rather than
re-deriving a path of its own.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from infosec_harness.domain.canonical import canonical_bytes, sha256_hex
from infosec_harness.resources import source_checkout
from infosec_harness.settings import get_settings

Case = dict[str, Any]


def case_group(case: Mapping[str, object]) -> str:
    """Stable group used to keep related variants on the same side of a holdout split."""
    if group := case.get("group"):
        return str(group)
    if repo := case.get("repo"):
        value = str(repo).rstrip("/")
        for suffix in ("/vulnerable", "/fixed"):
            if value.endswith(suffix):
                return value.removesuffix(suffix)
        return value
    name = str(case.get("name") or "")
    for suffix in ("-vulnerable", "-fixed"):
        if name.endswith(suffix):
            return name.removesuffix(suffix)
    return name


def case_set_identity(cases: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """What makes two runs measure the same thing: case names, groups and expectations.

    The digest covers the scoring contract of each case, so editing an expectation, regrouping a
    case, or adding one changes it even when the dataset's declared version does not.
    """
    cases = list(cases)
    contracts = [
        {"name": case.get("name"), "group": case_group(case), "expected": case.get("expected")}
        for case in cases
    ]
    return {
        # Persisted comparison identity: the ASCII-escaped encoding it has always used.
        "case_set_digest": sha256_hex(canonical_bytes(contracts, ascii_only=True)),
        "case_ids": [str(case.get("name")) for case in cases],
        "groups": sorted({case_group(case) for case in cases}),
    }


@dataclass(frozen=True)
class Dataset:
    agent: str
    path: Path
    version: str
    cases: tuple[Case, ...]

    @property
    def display_path(self) -> str:
        """The path a reader can follow: checkout-relative when inside the checkout."""
        resolved = self.path.resolve()
        root = source_checkout()
        if root is not None and resolved.is_relative_to(root.resolve()):
            return str(resolved.relative_to(root.resolve()))
        return str(resolved)

    def select(self, groups: set[str] | None) -> list[Case]:
        """The cases in ``groups`` (all of them for ``None``), in dataset order."""
        selected = [case for case in self.cases if groups is None or case_group(case) in groups]
        if not selected:
            raise ValueError(f"no cases selected for groups {sorted(groups or ())} in {self.path}")
        return selected


def load_dataset(agent: str, path: Path | None = None) -> Dataset:
    """Load ``agent``'s dataset, or the dataset at ``path`` when one is named."""
    path = (Path(path) if path is not None
            else get_settings().agents_dir / agent / "evals" / "dataset.yaml")
    document = yaml.safe_load(path.read_text())
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        raise ValueError(f"{path}: an eval dataset is a mapping with a `cases` list")
    cases = tuple(document["cases"])
    if not all(isinstance(case, dict) and case.get("name") for case in cases):
        raise ValueError(f"{path}: every case must be a mapping with a `name`")
    return Dataset(agent=agent, path=path, version=str(document.get("version", "1")), cases=cases)
