"""The read, search and write tools: confined repository file access inside the workspace."""

import json

from pydantic_ai import RunContext
from pydantic_ai.toolsets import FunctionToolset

from infosec_harness.agents.investigator import InvestigationDeps
from infosec_harness.sandbox import OpenShell

from .execute import bounded, operation_id

# This script executes only inside OpenShell. It handles model-authored paths as data.
_FILE_TOOL = r"""
import json, pathlib, sys
p = json.load(sys.stdin)
root = pathlib.Path('/workspace/repo').resolve()
def confined(raw):
    rel = pathlib.PurePosixPath(raw)
    if rel.is_absolute() or '..' in rel.parts:
        raise ValueError('Expected a relative repository path')
    path = (root / raw).resolve()
    if not path.is_relative_to(root):
        raise ValueError('Path leaves repository')
    return path
if p['action'] == 'read':
    path = confined(p['path'])
    if path.stat().st_size > 2_000_000:
        raise ValueError('File exceeds read limit')
    lines = path.read_text().splitlines()
    start, end = p['start_line'], p['end_line']
    if start < 1 or end < start or end-start > 500:
        raise ValueError('Expected at most 501 source lines')
    print('\n'.join(f'{i+1}: {lines[i]}' for i in range(start-1, min(end,len(lines)))))
elif p['action'] == 'write':
    path = confined(p['path'])
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(p['content'])
    print('Written '+p['path'])
elif p['action'] == 'search':
    count = 0
    for path in sorted(confined(p['path']).rglob('*')):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
            continue
        if path.stat().st_size > 2_000_000:
            continue
        try:
            lines = path.read_text().splitlines()
        except (UnicodeError,OSError):
            continue
        for i,line in enumerate(lines):
            if p['text'] in line:
                print(f'{path.relative_to(root)}:{i+1}: {line[:2000]}')
                count += 1
                if count >= 100:
                    sys.exit(0)
else:
    raise ValueError('Unknown file tool')
"""


async def file_tool(
    openshell: OpenShell, ctx: RunContext[InvestigationDeps], action: str, **values
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
        return f"File tool failed ({result.exit_code}): {result.stderr}"
    excerpt = result.stdout.encode()[:8192].decode(errors="ignore")
    return excerpt + ("\n[Output excerpted]" if len(result.stdout.encode()) > 8192 else "")


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
        if len(content.encode()) > 2_000_000:
            raise ValueError("Write exceeds two megabytes")
        return await file_tool(openshell, ctx, "write", path=path, content=content)
