"""The read, search and write tools: confined repository file access inside the workspace."""

import json
from typing import Literal

from pydantic_ai import RunContext
from pydantic_ai.toolsets import FunctionToolset

from infosec_harness.agents.deps import InvestigationDeps
from infosec_harness.sandbox import OpenShell

from .execute import bounded, operation_id

# The worker keeps this many bytes of a file tool's output. The script never prints more
# than one byte past it, so no repository content can reach the native output bound.
EXCERPT_BYTES = 8192
# Longer lines are cut inside the sandbox (a minified file is one long line).
MAX_LINE_CHARS = 2000
# Larger files are refused by read and skipped by search.
MAX_FILE_BYTES = 2_000_000

# This script executes only inside OpenShell. It handles model-authored paths as data.
# Path confinement has worker-side twins (workflows/snapshot.py, sandbox/transfer.py); this
# copy cannot import worker code, so a fix to one must reach the others by hand.
_FILE_TOOL = (
    f"OUTPUT_BYTES, LINE_CHARS, FILE_BYTES = {EXCERPT_BYTES}, {MAX_LINE_CHARS}, {MAX_FILE_BYTES}\n"
    + r"""
import json, pathlib, sys
root = pathlib.Path('/workspace/repo').resolve()
budget = OUTPUT_BYTES + 1  # one byte past the excerpt tells the worker the output was cut
def emit(text):
    global budget
    data = (text + '\n').encode('utf-8', 'replace')[:budget]
    sys.stdout.buffer.write(data)
    budget -= len(data)
    if budget <= 0:
        sys.stdout.buffer.flush()
        sys.exit(0)
def cut(line):
    return line if len(line) <= LINE_CHARS else line[:LINE_CHARS] + ' [line cut]'
def confined(raw):
    rel = pathlib.PurePosixPath(raw)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('Expected a relative repository path')
    path = (root / raw).resolve()
    if not path.is_relative_to(root):
        raise ValueError('Path leaves repository')
    return path
def main(p):
    if p['action'] == 'read':
        path = confined(p['path'])
        if path.stat().st_size > FILE_BYTES:
            raise ValueError('File exceeds read limit')
        start, end = p['start_line'], p['end_line']
        if start < 1 or end < start or end - start > 500:
            raise ValueError('Expected at most 501 source lines')
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        for i in range(start - 1, min(end, len(lines))):
            emit(f'{i+1}: {cut(lines[i])}')
    elif p['action'] == 'write':
        path = confined(p['path'])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(p['content'])
        emit('Written ' + p['path'])
    elif p['action'] == 'search':
        count = 0
        for path in sorted(confined(p['path']).rglob('*')):
            if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                continue
            if path.stat().st_size > FILE_BYTES:
                continue
            try:
                lines = path.read_text(encoding='utf-8').splitlines()
            except (UnicodeError, OSError):
                continue
            for i, line in enumerate(lines):
                if p['text'] in line:
                    emit(f'{path.relative_to(root)}:{i+1}: {cut(line)}')
                    count += 1
                    if count >= 100:
                        return
    else:
        raise ValueError('Unknown file tool')
try:
    main(json.load(sys.stdin))
except Exception as error:
    # One bounded line, not a traceback: it is agent feedback and durable history.
    sys.stderr.write(f'{type(error).__name__}: {error}'[:OUTPUT_BYTES] + '\n')
    sys.exit(1)
"""
)


def excerpt(text: str) -> str:
    """At most ``EXCERPT_BYTES`` of ``text``, marked when cut; tool returns enter history."""
    data = text.encode()
    if len(data) <= EXCERPT_BYTES:
        return text
    return data[:EXCERPT_BYTES].decode(errors="ignore") + "\n[Output excerpted]"


async def file_tool(
    openshell: OpenShell,
    ctx: RunContext[InvestigationDeps],
    action: Literal["read", "search", "write"],
    **values: str | int,
) -> str:
    timeout = ctx.deps.request.limits.command_timeout_seconds
    result = await openshell.execute(
        ctx.deps.sandbox,
        bounded(["python", "-I", "-c", _FILE_TOOL], timeout),
        operation_id=operation_id(ctx, action),
        timeout=timeout,
        stdin=json.dumps({"action": action, **values}).encode(),
    )
    if result.exit_code:
        return f"File tool failed ({result.exit_code}): {excerpt(result.stderr)}"
    return excerpt(result.stdout)


def register(tools: FunctionToolset[InvestigationDeps], openshell: OpenShell) -> None:
    @tools.tool
    async def read(
        ctx: RunContext[InvestigationDeps], path: str, start_line: int = 1, end_line: int = 200
    ) -> str:
        """Read numbered source lines at a relative repository path."""
        return await file_tool(
            openshell, ctx, "read", path=path, start_line=start_line, end_line=end_line
        )

    @tools.tool
    async def search(ctx: RunContext[InvestigationDeps], text: str, path: str = ".") -> str:
        """Search literal text under a repository directory; return up to 100 matching lines."""
        return await file_tool(openshell, ctx, "search", text=text, path=path)

    @tools.tool
    async def write(ctx: RunContext[InvestigationDeps], path: str, content: str) -> str:
        """Write a fixture, regression test, or probe inside the sandbox repository."""
        # Content is bounded before this body runs: DurablePayloadLimit.before_tool_execute
        # rejects any tool call whose arguments exceed the 1 MB durable payload budget.
        return await file_tool(openshell, ctx, "write", path=path, content=content)
