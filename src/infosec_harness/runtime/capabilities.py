"""Stable capability surfaces assembled from focused repository and sandbox tools.

Each toolset enforces the bounds its policy (`tools/<id>/tool.yaml`) declares: the policy's
`timeout_seconds` and `max_output_bytes` are read here, not restated.
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Collection
from dataclasses import dataclass
from functools import cache

from pydantic_ai import FunctionToolset, ModelRetry, RunContext
from pydantic_ai.capabilities import AbstractCapability

from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.sandbox.output import tail
from infosec_harness.tools.policies import load_policies
from infosec_harness.tools.repository import (
    clip_bytes,
    list_files,
    list_tree,
    read_file,
    read_files,
    repo_digest,
    search_code,
)
from infosec_harness.tools.symbols import describe_callables
from infosec_harness.tools.target import inspect_target

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


def selected_repo_tools(tools: Collection[str] | None) -> tuple[str, ...]:
    """The repo tools a `RepoReadOnly(tools=...)` selection exposes, in declaration order.

    The one place a selection is validated: None is the default surface; an unknown name, or a
    selection naming no tool, fails rather than silently narrowing the agent's tools. Two
    orderings of the same names give the same tuple, so they share one toolset instance.
    """
    if tools is None:
        return DEFAULT_REPO_RO_TOOLS
    unknown = sorted(set(tools) - set(REPO_RO_TOOLS))
    if unknown:
        raise ValueError(f"Unknown repo-read-only tools: {unknown}. "
                         f"Available: {sorted(REPO_RO_TOOLS)}")
    if not tools:
        raise ValueError(f"RepoReadOnly(tools={list(tools)!r}) selects no tool; "
                         f"available: {sorted(REPO_RO_TOOLS)}")
    wanted = set(tools)
    return tuple(name for name in REPO_RO_TOOLS if name in wanted)


def _within(text: str, max_bytes: int) -> str:
    """``text`` held to ``max_bytes`` UTF-8 bytes in total, truncation marker included."""
    if len(text.encode()) <= max_bytes:
        return text
    suffix = f"\n... truncated at the toolset's {max_bytes}-byte output bound"
    return clip_bytes(text, max_bytes - len(suffix.encode()), suffix)


def _bounded(tool: Callable[..., str], max_bytes: int) -> Callable[..., str]:
    """``tool`` with its result held to the policy's ``max_output_bytes``.

    ``functools.wraps`` keeps the name, docstring and signature, so the tool definition the
    model sees is unchanged.
    """
    @functools.wraps(tool)
    def bounded(*args, **kwargs) -> str:
        return _within(tool(*args, **kwargs), max_bytes)

    return bounded


@cache
def repo_ro_toolset(tools: tuple[str, ...]) -> FunctionToolset:
    """The `repo_ro` toolset exposing exactly `tools`, memoised so its identity is stable.

    Stability is a hard requirement, not an optimisation: Skills is a dynamic capability, so
    pydantic-ai re-collects capability toolsets each run and compares them by identity to the
    construction-time set, and a fresh toolset per call is rejected as a runtime addition under
    Temporal. Call it with a `selected_repo_tools` result, which validates and orders the names.
    """
    policy = load_policies()["repo-read-only"]
    return FunctionToolset(
        [_bounded(REPO_RO_TOOLS[t], policy.max_output_bytes) for t in tools],
        id="repo_ro", timeout=policy.timeout_seconds,
    )


# Build the default surface at import, outside any workflow, as every spec without a `tools`
# selection uses it.
repo_ro_toolset(DEFAULT_REPO_RO_TOOLS)


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
        return repo_ro_toolset(selected_repo_tools(self.tools))


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
    policy = load_policies()["sandbox-shell"]
    # Executing a command is a write, so it carries a stable key rather than relying on a
    # retry being free (agent-playbook §6). run_id is stable across a retry of the same
    # logical call; tool_call_id distinguishes separate calls within one agent run.
    key = f"{ctx.run_id}:{getattr(ctx, 'tool_call_id', '') or ''}:v1"
    # Diagnostic commands get no external egress. A repository/model-authored command cannot
    # widen the build allowlist or bypass its proxy; dependency installation belongs to the
    # controlled build phase.
    try:
        res = await docker.run_shell(ctx.deps.sandbox_image, command,
                                     timeout=policy.timeout_seconds, idempotency_key=key)
    except SandboxUnavailable as e:
        # Fail closed and say so: no command ran, so the model gets no fabricated fact and must
        # plan without one. The build phase re-checks the runtime and fails closed on its own.
        return f"[sandbox unavailable: {e}]\nNo command was executed."
    return _within(
        f"[exit code: {res.exit_code}{' (timed out)' if res.timed_out else ''}]\n"
        f"[stdout]\n{tail(res.stdout, 3000)}\n[stderr]\n{tail(res.stderr, 3000)}",
        policy.max_output_bytes,
    )


_SANDBOX_SHELL_TOOLSET = FunctionToolset([run_in_sandbox], id="sandbox_shell")


@dataclass
class SandboxShell(AbstractCapability[AgentDeps]):
    """Command execution routed into a gVisor container, never on the worker host."""

    def get_toolset(self):
        return _SANDBOX_SHELL_TOOLSET


CUSTOM_CAPABILITIES: tuple[type[AbstractCapability], ...] = (RepoReadOnly, SandboxShell)
