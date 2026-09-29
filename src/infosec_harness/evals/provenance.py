"""What produced a measurement: which commit, which build, and whether either can be trusted.

An eval number is only evidence if you can say what it measured. The playbook's Provenance
section asks for the commit, the agent version, the config hash, the model and the dataset
version, and the run already recorded most of that. Two things it did not record are the ones
that most often make a stored result misleading:

* **A dirty working tree.** ``git rev-parse HEAD`` answers the same SHA whether or not the
  files differ from it, so a run over uncommitted edits was filed against a commit that never
  contained the code it measured. Nothing downstream could tell the difference, which is worse
  than having no SHA at all.
* **The distribution's own version.** The commit identifies the source; it does not identify
  the artifact, and a wheel built from a tag is what a deployment actually runs.

Both are cheap to record and impossible to reconstruct afterwards, which is the test for
whether something belongs in provenance.
"""
from __future__ import annotations

import platform
import subprocess
from dataclasses import asdict, dataclass
from functools import cache

from infosec_harness.resources import source_checkout


@dataclass(frozen=True)
class CodeVersion:
    """The identity of the code under measurement."""

    git_commit: str
    """Full SHA, or empty off a source checkout (a wheel carries no repository)."""

    git_dirty: bool
    """True when tracked files differ from that commit, so the SHA does not describe the run."""

    harness_version: str
    """The installed distribution's version -- what a deployment would actually be running."""

    python: str

    def as_dict(self) -> dict:
        return asdict(self)

    @property
    def describes_a_commit(self) -> bool:
        """Whether this result can honestly be filed against a commit.

        A dirty tree cannot: the SHA names code that differs from what ran. Callers that store
        a result for later comparison should say so rather than quietly recording the SHA.
        """
        return bool(self.git_commit) and not self.git_dirty

    def label(self) -> str:
        """Short human form, with the dirty marker that a bare SHA would hide."""
        if not self.git_commit:
            return f"v{self.harness_version} (no checkout)"
        return f"{self.git_commit[:12]}{'-dirty' if self.git_dirty else ''}"


def _git(*args: str) -> str | None:
    """Run git inside the checkout, or None when there isn't one (or git fails)."""
    root = source_checkout()
    if root is None:
        return None
    try:
        return subprocess.check_output(["git", *args], cwd=root, text=True,
                                       stderr=subprocess.DEVNULL, timeout=10).strip()
    except Exception:
        return None


def _harness_version() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version("infosec-harness")
        except PackageNotFoundError:
            return "unknown"
    except Exception:
        return "unknown"


@cache
def code_version() -> CodeVersion:
    """The current code's identity. Cached: it cannot change inside one process."""
    commit = _git("rev-parse", "HEAD") or ""
    # `--porcelain` is empty exactly when tracked files match HEAD. Untracked files are
    # deliberately included (`--untracked-files=normal` is the default): a new, uncommitted
    # skill or dataset changes what an agent does just as much as an edited one.
    status = _git("status", "--porcelain")
    return CodeVersion(
        git_commit=commit,
        # `status` is None when there is no checkout at all, which is not dirtiness -- there is
        # simply nothing to compare against, and `git_commit` is already empty to say so.
        git_dirty=bool(status),
        harness_version=_harness_version(),
        python=platform.python_version(),
    )
