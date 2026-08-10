"""Read-only, bounded repository tools. Repository data is always untrusted data."""

from __future__ import annotations

from pathlib import Path

from .domain import EvidenceSlice, Finding
from .policy import PolicyError, canonical_path, redact, tool_decision

MAX_FILE_BYTES = 32_000
MAX_LINES = 120


class ReadOnlyTools:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve(strict=True)

    def read(self, path: str, start_line: int, end_line: int) -> tuple[str, object]:
        try:
            target = canonical_path(self.root, path)
            if not target.is_file():
                raise PolicyError("not a regular file")
            if end_line < start_line or end_line - start_line + 1 > MAX_LINES:
                raise PolicyError("line range exceeds bound")
            raw = target.read_bytes()
            if len(raw) > MAX_FILE_BYTES:
                raise PolicyError("file exceeds bound")
            text, secret_fingerprints = redact(raw.decode("utf-8", errors="replace"))
            if secret_fingerprints:
                raise PolicyError("restricted evidence discovered")
            lines = text.splitlines()
            return "\n".join(lines[start_line - 1 : end_line]), tool_decision("read_file", path, True, "within scope")
        except (OSError, PolicyError) as exc:
            return "", tool_decision("read_file", path, False, str(exc))

    def list_tree(self, path: str = ".", depth: int = 2) -> tuple[list[str], object]:
        try:
            if depth < 0 or depth > 4:
                raise PolicyError("tree depth exceeds bound")
            target = canonical_path(self.root, path)
            entries = sorted(
                entry.relative_to(self.root).as_posix()
                for entry in target.rglob("*")
                if len(entry.relative_to(target).parts) <= depth and not entry.is_symlink()
            )[:200]
            return entries, tool_decision("list_tree", path, True, "within scope")
        except (OSError, PolicyError) as exc:
            return [], tool_decision("list_tree", path, False, str(exc))

    def search(self, pattern: str, path: str = ".") -> tuple[list[dict[str, object]], object]:
        try:
            if not pattern or len(pattern) > 120:
                raise PolicyError("invalid search pattern")
            target = canonical_path(self.root, path)
            matches: list[dict[str, object]] = []
            for entry in sorted(target.rglob("*")):
                if not entry.is_file() or entry.is_symlink() or len(matches) >= 50:
                    continue
                raw = entry.read_bytes()
                if len(raw) > MAX_FILE_BYTES:
                    continue
                text, secrets = redact(raw.decode("utf-8", errors="replace"))
                if secrets:
                    raise PolicyError("restricted evidence discovered")
                for line_no, line in enumerate(text.splitlines(), 1):
                    if pattern in line:
                        matches.append({"path": entry.relative_to(self.root).as_posix(), "line": line_no, "text": line})
                        if len(matches) >= 50:
                            break
            return matches, tool_decision("search", path, True, "within scope")
        except (OSError, PolicyError) as exc:
            return [], tool_decision("search", path, False, str(exc))


def build_evidence_slice(finding: Finding, repo: Path, revision: str) -> tuple[EvidenceSlice, list[object]]:
    tools = ReadOnlyTools(repo)
    locations = finding.code_flow or finding.locations
    excerpts: list[dict[str, object]] = []
    decisions: list[object] = []
    for location in locations[:8]:
        start = max(1, location.start_line - 2)
        end = min(location.end_line + 2, start + 12)
        text, decision = tools.read(location.path, start, end)
        decisions.append(decision)
        if getattr(decision, "allowed", False):
            excerpts.append({"path": location.path, "start_line": start, "end_line": end, "text": text})
    gaps = [] if excerpts else ["No in-scope source excerpt could be collected."]
    return (
        EvidenceSlice(
            finding_id=finding.finding_id,
            revision=revision,
            locations=locations,
            excerpts=excerpts,
            provenance={"scanner": finding.scanner["name"], "raw_finding": finding.raw_artifact},
            coverage=["SARIF primary location", "SARIF code flow", "bounded source excerpts"],
            deferred_surfaces=["runtime configuration", "deployment context", "active validation"],
            proof_gaps=gaps,
        ),
        decisions,
    )
