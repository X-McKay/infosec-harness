"""Stable capability surfaces assembled from focused repository and sandbox tools."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

from pydantic_ai import FunctionToolset, ModelRetry, RunContext
from pydantic_ai.capabilities import AbstractCapability

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.repo_tools import (
    list_files,
    list_tree,
    read_file,
    read_files,
    repo_digest,
    search_code,
)
from infosec_harness.agents.symbol_inspection import describe_callables
from infosec_harness.agents.target_context import inspect_target

# The toolset's tools, in the order they are declared to the model. The order is part of the
# cacheable prompt prefix, so it is fixed here rather than derived from a set.
REPO_RO_TOOLS = {
    "repo_digest": repo_digest,
    "list_tree": list_tree,
    "list_files": list_files,
    "read_file": read_file,
    "read_files": read_files,
    "search_code": search_code,
    "describe_callables": describe_callables,
    "inspect_target": inspect_target,
}
DEFAULT_REPO_RO_TOOLS: tuple[str, ...] = tuple(
    name for name in REPO_RO_TOOLS if name != "inspect_target"
)


@cache
def repo_ro_toolset(tools: tuple[str, ...]) -> FunctionToolset:
    """The `repo_ro` toolset exposing exactly `tools`, memoised so its identity is stable.

    Stability is a hard requirement, not an optimisation: Skills is a dynamic capability, so
    pydantic-ai re-collects capability toolsets each run and compares them by identity to the
    construction-time set, and a fresh toolset per call is rejected as a runtime addition under
    Temporal. `lru_cache` keyed on the (canonically ordered) tool names gives one instance per
    distinct surface for the life of the process, which is what that comparison needs. The
    default surface is built at import below, exactly as the single toolset used to be.
    """
    unknown = [t for t in tools if t not in REPO_RO_TOOLS]
    if unknown:
        raise ValueError(f"Unknown repo-read-only tools: {unknown}. "
                         f"Available: {sorted(REPO_RO_TOOLS)}")
    return FunctionToolset([REPO_RO_TOOLS[t] for t in tools], id="repo_ro")


def _canonical(tools) -> tuple[str, ...]:
    """Requested tools in declaration order, so two orderings share one toolset instance."""
    wanted = set(tools)
    return tuple(name for name in REPO_RO_TOOLS if name in wanted)


_REPO_RO_TOOLSET = repo_ro_toolset(DEFAULT_REPO_RO_TOOLS)


@dataclass
class RepoReadOnly(AbstractCapability[AgentDeps]):
    """Read-only, path-confined access to the repository snapshot.

    `tools` narrows the surface to a named subset; omitted, the agent gets all of it. A
    narrower surface is both least privilege and a smaller cacheable prefix, and it is what
    lets the offline measurement in `scripts/exploration.py` attribute a change in round trips
    to one tool rather than to the whole toolset.
    """

    tools: tuple[str, ...] | list[str] | None = None

    def get_toolset(self):
        if self.tools is None:
            return _REPO_RO_TOOLSET
        canonical = _canonical(self.tools)
        if not canonical:
            raise ValueError(f"RepoReadOnly(tools={self.tools!r}) selects no known tool; "
                             f"available: {sorted(REPO_RO_TOOLS)}")
        return repo_ro_toolset(canonical)


async def run_in_sandbox(ctx: RunContext[AgentDeps], command: str) -> str:
    """Observe local facts in a fresh sandbox container of the candidate base image.

    It has no repository mount, external network, or state from earlier calls or builds.
    It cannot validate repository code or fetch dependencies. Use it only when a local image
    fact would change the plan, combining independent checks in one command. Dependency
    installation and repository validation belong to the controlled build phase.
    Returns exit code, stdout and stderr tails.
    """
    from infosec_harness.sandbox import docker
    from infosec_harness.sandbox.policy import SandboxUnavailable

    if not ctx.deps.sandbox_image:
        raise ModelRetry("No sandbox image is configured for this run.")
    # Executing a command is a write, so it carries a stable key rather than relying on a
    # retry being free (agent-playbook §6). run_id is stable across a retry of the same
    # logical call; tool_call_id distinguishes separate calls within one agent run.
    key = f"{ctx.run_id}:{getattr(ctx, 'tool_call_id', '') or ''}:v1"
    # Diagnostic commands get no external egress. A repository/model-authored command cannot
    # widen the build allowlist or bypass its proxy; dependency installation belongs to the
    # controlled build phase.
    try:
        res = await docker.run_shell(ctx.deps.sandbox_image, command, timeout=180,
                                     idempotency_key=key)
    except SandboxUnavailable as e:
        # Fail closed and say so: no command ran, so the model gets no fabricated fact and must
        # plan without one. The build phase re-checks the runtime and fails closed on its own.
        return f"[sandbox unavailable: {e}]\nNo command was executed."
    return (
        f"[exit code: {res.exit_code}{' (timed out)' if res.timed_out else ''}]\n"
        f"[stdout]\n{docker.tail(res.stdout, 3000)}\n[stderr]\n{docker.tail(res.stderr, 3000)}"
    )


_SANDBOX_SHELL_TOOLSET = FunctionToolset([run_in_sandbox], id="sandbox_shell")


@dataclass
class SandboxShell(AbstractCapability[AgentDeps]):
    """Command execution routed into a gVisor container, never on the worker host."""

    def get_toolset(self):
        return _SANDBOX_SHELL_TOOLSET


CUSTOM_CAPABILITIES: tuple[type[AbstractCapability], ...] = (RepoReadOnly, SandboxShell)
