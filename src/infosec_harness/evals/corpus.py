"""Loader for the seeded ground-truth corpus (D7 starter set).

The corpus is paired: each CWE has a vulnerable and a fixed variant of the same tiny app,
so the expected verdicts differ only because the code differs. Ground truth (expected
verdict, reachability, sink line, target callable) is for scoring — it is never shown to
the agents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from infosec_harness.domain.models import FindingInput
from infosec_harness.settings import REPO_ROOT


@dataclass
class CorpusCase:
    name: str
    finding: FindingInput
    expected_verdict: str
    reachability: str
    sink_file: str
    sink_line: int
    target_callable: str
    early_exit: str | None = None

    @property
    def repo_path(self) -> Path:
        return (REPO_ROOT / self.finding.repo_url).resolve()


def corpus_path() -> Path:
    return REPO_ROOT / "eval-corpus" / "manifest.json"


def load_corpus(language: str = "python") -> list[CorpusCase]:
    manifest = json.loads(corpus_path().read_text())
    if manifest.get("language") != language:
        raise ValueError(f"corpus language {manifest.get('language')} != {language}")
    cases = []
    for c in manifest["cases"]:
        # Resolve the repo path relative to the manifest so findings carry an absolute path.
        finding = FindingInput.model_validate(c["finding"])
        finding = finding.model_copy(update={"repo_url": str((REPO_ROOT / finding.repo_url).resolve())})
        t = c["truth"]
        cases.append(CorpusCase(
            name=c["name"], finding=finding, expected_verdict=t["expected_verdict"],
            reachability=t["reachability"], sink_file=t["sink_file"], sink_line=t["sink_line"],
            target_callable=t["target_callable"], early_exit=t.get("early_exit")))
    return cases
