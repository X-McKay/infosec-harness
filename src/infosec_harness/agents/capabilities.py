"""The few capabilities we own (§6). Everything else comes from pydantic-ai / the harness.

Each is a ``@dataclass`` ``AbstractCapability`` so ``agent.yaml`` can reference it by
name, and each toolset carries a stable ``id`` so Temporal can route its tool calls to
activities on the worker.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass
from pathlib import Path

from pydantic_ai import FunctionToolset, ModelRetry, RunContext
from pydantic_ai.capabilities import AbstractCapability

from infosec_harness.agents.deps import AgentDeps

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "target", "build", "dist", ".idea"}
MAX_READ_LINES = 400
MAX_LIST = 300
MAX_MATCHES = 60


def _resolve(root: str, rel: str) -> Path:
    base = Path(root).resolve()
    target = (base / rel.lstrip("/")).resolve()
    if target != base and base not in target.parents:
        raise ModelRetry(f"Path {rel!r} is outside the repository.")
    return target


def list_files(ctx: RunContext[AgentDeps], directory: str = ".", pattern: str = "*") -> str:
    """List repository files under `directory` (recursive) whose name matches the glob `pattern`.

    Returns repo-relative paths, one per line, truncated to 300 entries.
    """
    root = Path(ctx.deps.repo_path).resolve()
    start = _resolve(ctx.deps.repo_path, directory)
    if not start.is_dir():
        raise ModelRetry(f"{directory!r} is not a directory.")
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(start):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if fnmatch.fnmatch(name, pattern):
                out.append(str((Path(dirpath) / name).relative_to(root)))
                if len(out) >= MAX_LIST:
                    return "\n".join(out) + f"\n... truncated at {MAX_LIST} entries"
    return "\n".join(out) or "(no matches)"


def read_file(ctx: RunContext[AgentDeps], path: str, start_line: int = 1, end_line: int = 200) -> str:
    """Read lines `start_line`..`end_line` (1-based, inclusive) of a repository file.

    Output lines are prefixed with their line numbers. At most 400 lines per call.
    """
    target = _resolve(ctx.deps.repo_path, path)
    if not target.is_file():
        raise ModelRetry(f"{path!r} does not exist.")
    start_line = max(1, start_line)
    end_line = min(max(start_line, end_line), start_line + MAX_READ_LINES - 1)
    lines = target.read_text(errors="replace").splitlines()
    chunk = lines[start_line - 1 : end_line]
    body = "\n".join(f"{i:>5}  {line}" for i, line in enumerate(chunk, start=start_line))
    return f"{path} (lines {start_line}-{start_line + len(chunk) - 1} of {len(lines)})\n{body}"


def search_code(ctx: RunContext[AgentDeps], regex: str, file_glob: str = "*") -> str:
    """Search repository files matching `file_glob` for the Python regular expression `regex`.

    Returns `path:line: text` for up to 60 matches.
    """
    try:
        pattern = re.compile(regex)
    except re.error as e:
        raise ModelRetry(f"Invalid regex: {e}") from e
    root = Path(ctx.deps.repo_path).resolve()
    hits: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not fnmatch.fnmatch(name, file_glob):
                continue
            fp = Path(dirpath) / name
            try:
                if fp.stat().st_size > 2_000_000:
                    continue
                text = fp.read_text(errors="strict")
            except (UnicodeDecodeError, OSError):
                continue
            for lineno, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    hits.append(f"{fp.relative_to(root)}:{lineno}: {line.strip()[:200]}")
                    if len(hits) >= MAX_MATCHES:
                        return "\n".join(hits) + f"\n... truncated at {MAX_MATCHES} matches"
    return "\n".join(hits) or "(no matches)"


@dataclass
class RepoReadOnly(AbstractCapability[AgentDeps]):
    """Read-only, path-confined access to the repository snapshot."""

    def get_toolset(self):
        return FunctionToolset([list_files, read_file, search_code], id="repo_ro")


async def run_in_sandbox(ctx: RunContext[AgentDeps], command: str) -> str:
    """Run a shell command in a fresh sandbox container of the candidate base image, with the
    repository NOT mounted. Use it to check package names, tool versions, or install commands.
    Returns exit code, stdout and stderr tails."""
    from infosec_harness.sandbox import docker

    if not ctx.deps.sandbox_image:
        raise ModelRetry("No sandbox image is configured for this run.")
    res = await docker.run_shell(ctx.deps.sandbox_image, command, network=True, timeout=180)
    return (
        f"[exit code: {res.exit_code}{' (timed out)' if res.timed_out else ''}]\n"
        f"[stdout]\n{docker.tail(res.stdout, 3000)}\n[stderr]\n{docker.tail(res.stderr, 3000)}"
    )


@dataclass
class SandboxShell(AbstractCapability[AgentDeps]):
    """Command execution routed into a gVisor container, never on the worker host."""

    def get_toolset(self):
        return FunctionToolset([run_in_sandbox], id="sandbox_shell")


CUSTOM_CAPABILITIES: tuple[type[AbstractCapability], ...] = (RepoReadOnly, SandboxShell)
