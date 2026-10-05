"""Loader for the seeded ground-truth corpus (D7 starter set).

The corpus is paired: each CWE has a vulnerable and a fixed variant of the same tiny app,
so the expected verdicts differ only because the code differs. Ground truth (expected
verdict, reachability, sink line, target callable) is for scoring — it is never shown to
the agents.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from infosec_harness.domain.models import FindingInput
from infosec_harness.settings import REPO_ROOT, get_settings


@dataclass
class CorpusCase:
    name: str
    language: str
    finding: FindingInput
    expected_verdict: str
    reachability: str
    sink_file: str
    sink_line: int
    target_callable: str
    early_exit: str | None = None
    # Harvested cases only. Repo-relative paths stripped from the checkout before the agent
    # reads it -- a benchmark's own proof-of-vulnerability test is in the tree of a `-fixed`
    # revision by construction, and an agent that copies it is not authoring a probe.
    mask_paths: list[str] = field(default_factory=list)
    # "covered" when one of our eight cwe-* skills handles this class. A harvested dataset
    # spans far more CWEs than we have skills for, and the dataset's own label is never
    # rewritten to suit our scorer -- relabelling would be inventing ground truth.
    cwe_coverage: str = "covered"
    # Where the case came from ("seed" for the hand-written corpus). Kept so a regression can
    # be traced to its dataset, and so external cases can be scored separately.
    dataset: str = "seed"

    @property
    def repo_path(self) -> Path:
        """Only meaningful for a vendored case; a harvested one is cloned at run time."""
        if is_remote(self.finding.repo_url):
            raise ValueError(
                f"{self.name} is a harvested case cloned from {self.finding.repo_url}; it has "
                "no path in this repository until checkout() runs."
            )
        return Path(self.finding.repo_url).resolve()


def corpus_path() -> Path:
    return REPO_ROOT / "eval-corpus" / "manifest.json"


def is_remote(repo_url: str) -> bool:
    """A harvested case names a git URL; a vendored one names a directory in this repo."""
    return repo_url.startswith(("http://", "https://", "git@"))


def approve_corpus_root(manifest_path: Path | None = None) -> Path:
    """Admit the directory a manifest lives in as a local repository root for this process.

    Local sources are refused unless an operator-approved root contains them. Running a corpus
    is that approval for the corpus the operator named, and only for it: the root is the
    manifest's own directory, and `load_corpus` refuses a vendored case that resolves outside
    it.
    """
    root = (manifest_path or corpus_path()).resolve().parent
    roots = get_settings().local_repo_roots
    if not any(root.is_relative_to(Path(r).resolve()) for r in roots):
        roots.append(root)
    return root


def load_corpus(language: str | None = None, *, manifest_path: Path | None = None,
                dataset: str = "seed") -> list[CorpusCase]:
    """Load corpus cases. ``language=None`` returns all; otherwise filters by language.

    ``manifest_path`` reads a harvested manifest (eval-corpus/external/*.json) instead of the
    seeded one. Only the ``cases`` array is read: a harvested manifest also carries
    ``quarantined`` entries, which exist precisely because they are NOT safe to run, and
    reading them by accident is the failure this argument is shaped to prevent.
    """
    manifest_file = (manifest_path or corpus_path()).resolve()
    manifest = json.loads(manifest_file.read_text())
    cases = []
    for c in manifest["cases"]:
        if language is not None and c.get("language") != language:
            continue
        finding = FindingInput.model_validate(c["finding"])
        # A vendored case names a directory in this repository and is resolved against the repo
        # root; a harvested one names a remote git URL, which checkout() clones as-is. Resolving
        # a URL against the root would produce `<repo>/https:/github.com/...`.
        if not is_remote(finding.repo_url):
            local = (REPO_ROOT / finding.repo_url).resolve()
            if not local.is_relative_to(manifest_file.parent):
                raise ValueError(
                    f"corpus case {c['name']!r} names {finding.repo_url!r}, outside the "
                    f"manifest's directory {manifest_file.parent}")
            finding = finding.model_copy(update={"repo_url": str(local)})
        t = c["truth"]
        cases.append(CorpusCase(
            name=c["name"], language=c.get("language", "python"), finding=finding,
            expected_verdict=t["expected_verdict"], reachability=t["reachability"],
            sink_file=t["sink_file"], sink_line=t["sink_line"],
            target_callable=t["target_callable"], early_exit=t.get("early_exit"),
            mask_paths=list((t.get("pov") or {}).get("mask_paths") or []),
            cwe_coverage=(c.get("cwe_coverage") or {}).get("status", "covered"),
            dataset=dataset))
    return cases


def languages() -> list[str]:
    manifest = json.loads(corpus_path().read_text())
    return sorted({c.get("language", "python") for c in manifest["cases"]})
