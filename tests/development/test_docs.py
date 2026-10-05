"""Living documentation must not point at files that do not exist.

Covers README.md and every Markdown file under docs/ except docs/evidence/, which holds dated,
point-in-time records that are deliberately left as written. Two kinds of reference are checked:

- every relative Markdown link resolves to a file or directory (and, for a link into a Markdown
  file with a ``#fragment``, to a heading of that file);
- every inline-code span that names a repository path (``src/...``, ``tests/...``,
  ``scripts/...``, ``docs/...``, ``deploy/...``, ``evals/...``, ``eval-corpus/...``, ``ui/...``,
  ``.claude/...``, ``.mise.toml``, ``justfile``, ``dev``) exists. Brace alternatives such as
  ``{a,b}`` are expanded; a placeholder (``<name>``) or glob (``*``) must match a path, or at
  least name an existing directory before its first variable segment.

Fenced code blocks are ignored: they hold commands and output, not references.
"""

from __future__ import annotations

import itertools
import re
from functools import cache
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs" / "evidence"

PATH_PREFIXES = ("src/", "tests/", "scripts/", "docs/", "deploy/", "evals/", "eval-corpus/",
                 "ui/", ".claude/")
EXACT_PATHS = {".mise.toml", "justfile", "dev"}

LINK = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
CODE_SPAN = re.compile(r"(`+)(.+?)\1")
FENCE = re.compile(r"^\s*(```|~~~)")


def _documents() -> list[Path]:
    docs = [p for p in sorted((ROOT / "docs").rglob("*.md"))
            if EVIDENCE not in p.parents]
    return [ROOT / "README.md", *docs]


def _prose_lines(path: Path) -> list[tuple[int, str]]:
    """Lines outside fenced code blocks, with their 1-based numbers."""
    lines, fenced = [], False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            lines.append((number, line))
    return lines


def _slug(heading: str) -> str:
    """GitHub's heading anchor: lowercase, punctuation dropped, spaces to hyphens."""
    text = re.sub(r"`|\*\*|__", "", heading.strip().lower())
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


@cache
def _anchors(path: Path) -> frozenset[str]:
    seen: dict[str, int] = {}
    anchors = set()
    for _, line in _prose_lines(path):
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not match:
            continue
        slug = _slug(match.group(1))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    return frozenset(anchors)


def _broken_links(path: Path) -> list[str]:
    problems = []
    for number, line in _prose_lines(path):
        for match in LINK.finditer(CODE_SPAN.sub("", line)):
            target = match.group(1)
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
                continue  # http:, https:, mailto: ...
            location, _, fragment = target.partition("#")
            resolved = (path.parent / location).resolve() if location else path
            where = f"{path.relative_to(ROOT)}:{number}: {target}"
            if not resolved.exists():
                problems.append(where + " (missing)")
            elif fragment and resolved.suffix == ".md" and fragment not in _anchors(resolved):
                problems.append(where + " (no such heading)")
    return problems


def _expand_braces(text: str) -> list[str]:
    match = re.search(r"\{([^{}]*)\}", text)
    if not match:
        return [text]
    head, tail = text[:match.start()], text[match.end():]
    return list(itertools.chain.from_iterable(
        _expand_braces(head + option + tail) for option in match.group(1).split(",")))


def _exists(reference: str) -> bool:
    """A literal path must exist; a pattern must match, or at least its fixed directory must.

    ``evals/baselines/<agent>/<tier>.json`` describes where files go, and is valid while no
    baseline is recorded yet, provided ``evals/baselines/`` itself exists.
    """
    reference = reference.rstrip("/")
    for candidate in _expand_braces(reference):
        if "<" in candidate or "*" in candidate:
            if next(iter(ROOT.glob(re.sub(r"<[^>]*>", "*", candidate))), None) is not None:
                return True
            fixed = re.split(r"[<*]", candidate, maxsplit=1)[0].rpartition("/")[0]
            if fixed and (ROOT / fixed).is_dir():
                return True
        elif (ROOT / candidate).exists():
            return True
    return False


def _repository_path(span: str) -> str | None:
    """The repository path an inline-code span names, or None if it names none."""
    token = span.strip().split()[0] if span.strip() else ""
    token = token.split("#", 1)[0].split("::", 1)[0]
    token = re.sub(r":\d+(-\d+)?$", "", token).rstrip(".,;:)")
    if "..." in token or "…" in token:
        return None
    if token in EXACT_PATHS or token.startswith(PATH_PREFIXES):
        return token
    return None


def _missing_paths(path: Path) -> list[str]:
    problems = []
    for number, line in _prose_lines(path):
        for match in CODE_SPAN.finditer(line):
            reference = _repository_path(match.group(2))
            if reference is not None and not _exists(reference):
                problems.append(f"{path.relative_to(ROOT)}:{number}: `{reference}`")
    return problems


@pytest.mark.parametrize("document", _documents(), ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(document):
    assert not _broken_links(document)


@pytest.mark.parametrize("document", _documents(), ids=lambda p: str(p.relative_to(ROOT)))
def test_backticked_repository_paths_exist(document):
    assert not _missing_paths(document)


def test_every_living_document_is_indexed():
    """docs/README.md links every living document, so none is reachable only by search."""
    index = ROOT / "docs" / "README.md"
    linked = {
        (index.parent / match.group(1).partition("#")[0]).resolve()
        for _, line in _prose_lines(index)
        for match in LINK.finditer(line)
        if not re.match(r"^[a-z][a-z0-9+.-]*:", match.group(1), re.IGNORECASE)
    }
    unindexed = [str(p.relative_to(ROOT)) for p in _documents()
                 if p != index and p.is_relative_to(ROOT / "docs") and p.resolve() not in linked]
    assert not unindexed
