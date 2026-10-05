"""Orchestration shared by the in-process path (``LocalOps``) and the durable path (Temporal).

Everything here is deterministic and free of I/O of its own: side effects go through the
``Ops`` the caller passes. Its imports are all module-level on purpose: code that runs inside a
workflow must not import lazily, or the sandbox re-executes the module instead of passing it
through. Workflow code imports this module through Temporal's passthrough,
so the two paths share one definition of how a batch is grouped and scheduled, how a finding is
triaged, what a failure records, and how an agent call is accounted -- instead of two copies
that drift. Where they used to differ, the durable behaviour is the canonical one.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic_ai import capture_run_messages
from pydantic_ai.messages import ModelResponse, UserContent
from pydantic_ai.usage import RunUsage

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.intake_contracts import render_intake_prompt
from infosec_harness.agents.models import estimate_cost
from infosec_harness.agents.trajectory import count_repeated_calls, inspect_messages
from infosec_harness.domain.models import (
    AgentOutcome,
    ComponentProfile,
    Finding,
    FindingInput,
    InconclusiveReason,
    PreparedEnvironment,
    Reachability,
    SourceMode,
    StackFingerprint,
    TriageResult,
    TriageRunOutput,
    inconclusive_verdict,
)
from infosec_harness.graph.failures import classify_pipeline_failure, describe_failure
from infosec_harness.graph.manifests import execution_manifest
from infosec_harness.graph.ops import Ops
from infosec_harness.graph.prepare import PrepareFailed, prepare_resolved_component
from infosec_harness.graph.scoring import priority
from infosec_harness.graph.triage import TRIAGE_GRAPH, PreFilter, TriageDeps, TriageState
from infosec_harness.inference.provenance import runtime_evidence
from infosec_harness.intake import adapters
from infosec_harness.repo.components import component_stack, owning_component, preparation_key

MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 32
INTAKE_TASK = "Extract the missing finding fields from the report text, with citations."

RepoKey = tuple[str, str, SourceMode | None]


def clamp_concurrency(value: int) -> int:
    """Per-repository finding concurrency, bounded to what one runner can sensibly hold."""
    return max(MIN_CONCURRENCY, min(MAX_CONCURRENCY, int(value)))


def dedupe_by_fingerprint(findings: Sequence[FindingInput]) -> list[FindingInput]:
    """One finding per fingerprint: a duplicate in a batch is the same finding reported twice."""
    return list({Finding.compute_fingerprint(f): f for f in findings}.values())


def group_by_repository(findings: Sequence[FindingInput]) -> dict[RepoKey, list[FindingInput]]:
    """Findings sharing a checkout, in first-seen order; each group is discovered once."""
    groups: dict[RepoKey, list[FindingInput]] = defaultdict(list)
    for f in findings:
        groups[(f.repo_url, f.revision, f.source_mode)].append(f)
    return dict(groups)


@dataclass
class ComponentGroup:
    """Findings that share one prepared environment: a component of one discovered stack."""

    component: ComponentProfile | None
    stack: StackFingerprint
    findings: list[FindingInput]

    @property
    def root(self) -> str:
        return self.component.root if self.component is not None else "."


def split_components(stack: StackFingerprint,
                     findings: Sequence[FindingInput]) -> list[ComponentGroup]:
    """Split one repository's findings by owning component, each in warm-first order.

    Incompatible components are prepared and accounted separately. Within a group, findings
    are ordered deterministically (CWE, then path) so both paths warm the same finding.
    """
    groups: dict[str, ComponentGroup] = {}
    for finding in findings:
        component = owning_component(stack, finding.file_path)
        key = preparation_key(component)
        if key not in groups:
            narrowed = component_stack(stack, component) if component is not None else stack
            groups[key] = ComponentGroup(component, narrowed, [])
        groups[key].findings.append(finding)
    for group in groups.values():
        group.findings.sort(key=lambda f: (f.cwe or "", f.file_path or ""))
    return list(groups.values())


async def warm_then_fan_out[T, R](items: Sequence[T], run: Callable[[T], Awaitable[R]],
                                  concurrency: int) -> list[R]:
    """Run the first item alone, then the rest concurrently under ``concurrency`` (§6.2).

    The first finding writes the shared prompt-cache prefix; the rest read it. Fanning out from
    the start would have every finding of the repository miss the cache and write it.
    """
    if not items:
        return []
    gate = asyncio.Semaphore(clamp_concurrency(concurrency))

    async def bounded(item: T) -> R:
        async with gate:
            return await run(item)

    first = await run(items[0])
    return [first, *await asyncio.gather(*(bounded(item) for item in items[1:]))]


def inconclusive_output(finding: Finding, reason: InconclusiveReason, rationale: str,
                        status: str, invocations: Sequence[AgentOutcome] | None = None,
                        manifest: dict | None = None, *, context=None,
                        executions=None) -> TriageRunOutput:
    """The recorded outcome of a finding that never reached a supported security judgment."""
    verdict = inconclusive_verdict(reason, rationale)
    score, band = priority(finding, verdict, Reachability.unknown)
    result = TriageResult(fingerprint=finding.fingerprint, verdict=verdict, priority_score=score,
                          priority=band, environment_scope="none", early_exit=reason.value)
    return TriageRunOutput(finding=finding, result=result, prepared_status=status,
                           manifest=manifest or {}, invocations=list(invocations or []),
                           context=context, executions=list(executions or []),
                           needs_info=(reason == InconclusiveReason.needs_info))


async def run_recorded(agent: Any, name: str, prompt: Sequence[UserContent], deps: AgentDeps,
                       config: Any, record: list[AgentOutcome], *, clock: Callable[[], float],
                       timeout: float | None = None) -> AgentOutcome:
    """Run one agent call and append its outcome to ``record`` before returning or raising.

    The one place both ``Ops`` implementations run an agent. A call that raises is recorded
    too, with the usage its completed requests reported, and the exception propagates
    unchanged: a failed call spent requests and tokens, so it is never recorded as free and
    never silently dropped. ``clock`` is the caller's time source (workflow time inside a
    workflow, a monotonic clock in process).
    """
    started = clock()
    with capture_run_messages() as messages:
        try:
            async with asyncio.timeout(timeout):
                result = await agent.run(list(prompt), deps=deps,
                                         usage_limits=config.budget.to_usage_limits())
        except Exception as exc:
            record.append(partial_outcome(name, messages, config, clock() - started, exc))
            raise
    outcome = agent_outcome(name, result, config, clock() - started)
    record.append(outcome)
    return outcome


def agent_outcome(name: str, result: Any, config: Any, latency_s: float) -> AgentOutcome:
    """Account one completed agent run from its own usage and messages.

    ``config`` is the effective ``ResolvedAgentConfig`` the run was invoked under. Tool calls
    come from the run's usage, never from a separate count of messages, so both paths record
    the same number that the budget enforced.
    """
    usage = result.usage
    model_name = config.model.resolved_model
    cost, estimated = estimate_cost(model_name, usage)
    messages = result.all_messages()
    tools_called, skills_loaded = inspect_messages(messages)
    recorded_config = config.model_dump(mode="json")
    if config.model.broker_contract is not None:
        recorded_config["inference_runtime"] = runtime_evidence(messages)
    return AgentOutcome(
        output=result.output,
        agent=name,
        model_name=model_name,
        config_hash=config.digest,
        effective_config=recorded_config,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        cache_read_tokens=usage.cache_read_tokens or 0,
        cache_write_tokens=usage.cache_write_tokens or 0,
        cost_usd=cost,
        cost_estimated=estimated,
        latency_s=latency_s,
        tools_called=tools_called,
        skills_loaded=skills_loaded,
        requests=usage.requests or 0,
        tool_calls=usage.tool_calls,
        repeated_tool_calls=count_repeated_calls(messages),
    )


def partial_outcome(name: str, messages: Sequence[Any], config: Any, latency_s: float,
                    error: BaseException) -> AgentOutcome:
    """Account an agent run that raised, from the messages it had exchanged before failing.

    Usage is summed over the model responses that completed; a request lost in transport is
    not visible here, so this is a lower bound and is marked as an estimate.
    """
    responses = [m for m in messages if isinstance(m, ModelResponse)]
    usage = RunUsage(requests=len(responses))
    for response in responses:
        usage.input_tokens += response.usage.input_tokens or 0
        usage.output_tokens += response.usage.output_tokens or 0
        usage.cache_read_tokens += response.usage.cache_read_tokens or 0
        usage.cache_write_tokens += response.usage.cache_write_tokens or 0
    model_name = config.model.resolved_model
    cost, _ = estimate_cost(model_name, usage)
    tools_called, skills_loaded = inspect_messages(messages)
    return AgentOutcome(
        output=None, agent=name, model_name=model_name, config_hash=config.digest,
        effective_config=config.model_dump(mode="json"),
        input_tokens=usage.input_tokens, output_tokens=usage.output_tokens,
        cache_read_tokens=usage.cache_read_tokens, cache_write_tokens=usage.cache_write_tokens,
        cost_usd=cost, cost_estimated=True, latency_s=latency_s, tools_called=tools_called,
        skills_loaded=skills_loaded, requests=usage.requests,
        repeated_tool_calls=count_repeated_calls(list(messages)),
        failure=type(error).__name__)


def _never_cancelled(_exc: BaseException) -> bool:
    return False


async def triage_finding(ops: Ops, inp: FindingInput, prepared: PreparedEnvironment, *,
                         is_cancelled: Callable[[BaseException], bool] = _never_cancelled,
                         ) -> TriageRunOutput:
    """F0-F9 for one finding against its repository's prepared environment.

    A failure after normalization is an outcome, not an exception: the finding is recorded as
    inconclusive with every agent call, the context and the executions it had already produced.
    Only a cancellation (as ``is_cancelled`` recognises it) propagates.
    """
    finding = Finding.from_input(inp)
    invocations: list[AgentOutcome] = []
    state: TriageState | None = None
    try:
        # F0: extract from prose if needed, then resolve the location.
        if adapters.needs_extraction(finding) and finding.description.strip():
            outcome = await ops.run_agent(
                "intake",
                render_intake_prompt(INTAKE_TASK, {"report": finding.description,
                                                   "known": finding}),
                AgentDeps(repo_path=prepared.snapshot.path, report_text=finding.description),
                record=invocations)
            finding = adapters.merge_extraction(finding, outcome.output)
        resolved = await ops.resolve_location(finding, prepared.snapshot.path)
        if resolved is None:
            return inconclusive_output(
                finding, InconclusiveReason.needs_info,
                "The finding's location could not be resolved in the repository.",
                prepared.status, invocations, execution_manifest(prepared))
        finding = resolved
        try:
            rebound = await prepare_resolved_component(ops, finding, prepared)
        except PrepareFailed as exc:
            if is_cancelled(exc.cause):
                raise exc.cause from exc
            return inconclusive_output(
                finding, classify_pipeline_failure(exc.cause),
                f"Preparing the resolved component failed: {describe_failure(exc.cause)}",
                "failed", invocations + exc.invocations, execution_manifest(prepared))
        if rebound is not None:
            prepared = rebound.prepared
            invocations.extend(rebound.invocations)
        if prepared.status != "ready":
            return inconclusive_output(
                finding, InconclusiveReason.environment_unbuildable,
                f"The environment could not be prepared: {prepared.reason}.",
                prepared.status, invocations, execution_manifest(prepared))
        state = TriageState(finding=finding, prepared=prepared)
        result = await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=PreFilter())
        return TriageRunOutput(finding=finding, result=result, prepared_status=prepared.status,
                               invocations=invocations + state.invocations,
                               context=state.context, executions=state.executions,
                               manifest=execution_manifest(prepared))
    except Exception as exc:
        if is_cancelled(exc):
            raise
        return inconclusive_output(
            finding, classify_pipeline_failure(exc),
            f"Finding assessment failed: {describe_failure(exc)}", "failed",
            invocations + (state.invocations if state else []), execution_manifest(prepared),
            context=state.context if state else None,
            executions=state.executions if state else None)
