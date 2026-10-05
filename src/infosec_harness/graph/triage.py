"""Finding-triage graph (F1-F9): the per-finding topology, built with pydantic-graph.

It runs unchanged standalone (LocalOps) or inside a Temporal workflow (TemporalOps). Nodes
touch side effects only through ``ctx.deps.ops``; all control flow (the execute->diagnose->
repair loop, early exits) is expressed as typed node transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_graph import BaseNode, End, GraphBuilder, GraphRunContext

from infosec_harness.domain.models import (
    AgentOutcome,
    CodeRef,
    DiagnosisKind,
    EnvironmentSpec,
    Finding,
    FindingContext,
    InconclusiveReason,
    PreparedEnvironment,
    ProbeDiagnosis,
    ProbeExecution,
    ProbePlan,
    ProbeSource,
    Reachability,
    RepoProfile,
    StackFingerprint,
    TriageResult,
    Verdict,
    VerdictFacts,
    VerdictLabel,
    inconclusive_verdict,
)
from infosec_harness.graph.ops import Ops
from infosec_harness.graph.prepare import revise_environment, smoke_test
from infosec_harness.graph.scoring import priority
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.runtime.render import render_prompt
from infosec_harness.sandbox.controls import parse_control_result
from infosec_harness.settings import get_settings


@dataclass
class TriageDeps:
    ops: Ops
    max_probe_repairs: int = field(default_factory=lambda: get_settings().max_probe_repairs)
    max_environment_repairs: int = field(
        default_factory=lambda: get_settings().max_environment_repairs)


@dataclass
class TriageState:
    finding: Finding
    prepared: PreparedEnvironment
    nonce: str = ""
    # Probe executions so far; numbers each ProbeExecution. Not a repair budget.
    attempt: int = 0
    context: FindingContext | None = None
    plan: ProbePlan | None = None
    probe: ProbeSource | None = None
    executions: list[ProbeExecution] = field(default_factory=list)
    last_diagnosis: ProbeDiagnosis | None = None
    invocations: list[AgentOutcome] = field(default_factory=list)
    early_exit: str | None = None
    # Probe repairs already spent (RepairProbe). Counted separately from environment repairs,
    # whose re-execution of an unchanged probe must not consume the probe-repair budget.
    probe_repairs: int = 0
    # Probe-time environment re-plans already spent (RepairEnvironment).
    environment_repairs: int = 0

    @property
    def image_tag(self) -> str:
        return self.prepared.build.image_tag or "" if self.prepared.build else ""

    @property
    def spec(self) -> EnvironmentSpec:
        if self.prepared.build is None:
            raise RuntimeError("Triage requires a built environment")
        return self.prepared.build.spec

    @property
    def stack(self) -> StackFingerprint:
        return self.prepared.stack

    @property
    def profile(self) -> RepoProfile | None:
        return self.prepared.profile

    @property
    def source_files(self) -> int | None:
        """How much repository the agents have to explore, for budget scaling."""
        return self.prepared.stack.source_files

    def deps(self, facts: VerdictFacts | None = None) -> AgentDeps:
        return AgentDeps(repo_path=self.prepared.snapshot.path, sandbox_image=self.image_tag,
                         facts=facts, source_files=self.source_files)


def _invalid_citations(references: list[CodeRef | None],
                       checked: list[CodeRef | None]) -> list[str]:
    return [f"{ref.file_path}:{ref.start_line}-{ref.end_line}"
            for ref, grounded in zip(references, checked, strict=True)
            if ref is not None and grounded is None]


async def _validate_context_citations(ops: Ops, state: TriageState,
                                      context: FindingContext) -> FindingContext:
    """Ground citations through Ops so workflow replay never reads snapshot files."""
    references = [context.source, context.sink, *context.path, *context.sanitizers]
    checked = await ops.validate_citations(state.prepared.snapshot.path, references)
    invalid = _invalid_citations(references, checked)
    boundary = 2 + len(context.path)
    update = {
        "source": checked[0], "sink": checked[1],
        "path": [ref for ref in checked[2:boundary] if ref is not None],
        "sanitizers": [ref for ref in checked[boundary:] if ref is not None],
    }
    if invalid:
        update.update({
            "reachability": Reachability.unknown,
            "reachability_rationale": (
                context.reachability_rationale
                + " Citation validation failed, so reachability remains unknown: "
                + "; ".join(invalid[:5])
            ),
        })
    return context.model_copy(update=update)


async def _validate_verdict_citations(ops: Ops, state: TriageState, verdict: Verdict) -> Verdict:
    checked = await ops.validate_citations(state.prepared.snapshot.path, verdict.evidence)
    invalid = _invalid_citations(verdict.evidence, checked)
    update = {"evidence": [ref for ref in checked if ref is not None]}
    if invalid:
        update["rationale"] = (verdict.rationale + " Invalid code references were discarded: "
                               + "; ".join(invalid[:5]))
    return verdict.model_copy(update=update)


def _finalize(state: TriageState, verdict: Verdict, reachability: Reachability) -> TriageResult:
    score, band = priority(state.finding, verdict, reachability)
    return TriageResult(
        fingerprint=state.finding.fingerprint,
        verdict=verdict,
        priority_score=score,
        priority=band,
        environment_scope=state.spec.scope if state.prepared.status == "ready" else "none",
        early_exit=state.early_exit,
    )


@dataclass
class GatherContext(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> PlanProbe:
        s = ctx.state
        prompt = render_prompt(
            "Gather the code slice for this finding: source, sink, data path, sanitizers, "
            "reachability, and the target callable a unit test should drive.",
            {"finding": s.finding}, stack=s.stack, profile=s.profile,
        )
        outcome = await ctx.deps.ops.run_agent("context", prompt, s.deps(), record=s.invocations)
        s.context = await _validate_context_citations(ctx.deps.ops, s, outcome.output)
        return PlanProbe()


@dataclass
class PlanProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> AuthorProbe | End[TriageResult]:
        s = ctx.state
        # Context is a model assertion, even when its CodeRefs resolve. Initial policy therefore
        # does not turn `unreachable` into a safety verdict: continue to the bounded experiment.
        prompt = render_prompt(
            "Plan a targeted unit-test probe and define its deterministic oracle.",
            {"finding": s.finding, "finding_context": s.context}, stack=s.stack, profile=s.profile,
        )
        outcome = await ctx.deps.ops.run_agent("probe-planner", prompt, s.deps(),
                                               record=s.invocations)
        s.plan = outcome.output
        return AuthorProbe()


@dataclass
class AuthorProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> ExecuteProbe:
        s = ctx.state
        if not s.nonce:
            s.nonce = await ctx.deps.ops.new_nonce()
        prompt = render_prompt(
            "Write the probe as one unit test in the repository's own framework. Emit the "
            "precondition and oracle markers exactly as the probe-oracle-protocol skill defines.",
            {"finding": s.finding, "finding_context": s.context, "probe_plan": s.plan,
             "oracle_nonce": s.nonce}, stack=s.stack, profile=s.profile,
        )
        outcome = await ctx.deps.ops.run_agent("probe-author", prompt, s.deps(),
                                               record=s.invocations)
        s.probe = outcome.output
        return ExecuteProbe()


@dataclass
class ExecuteProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> DiagnoseProbe:
        s = ctx.state
        s.attempt += 1
        execution = await ctx.deps.ops.execute_probe(s.image_tag, s.probe, s.spec, s.nonce, s.attempt)
        s.executions.append(execution)
        return DiagnoseProbe()


def _correct_unsupported_negative(diagnosis: ProbeDiagnosis,
                                  execution: ProbeExecution) -> ProbeDiagnosis:
    """A clean negative requires the sink call to have returned.

    "The code resisted the payload" is only sayable if the payload reached the code and the
    call completed. The precondition marker is printed *before* the call, so on its own it
    cannot tell a resisted payload from a probe that threw on the way — and a probe can swallow
    its own error and still exit 0, which is exactly what happened on
    javascript-cmdi-vulnerable: a named export imported as a default, a call that threw inside a
    promise that resolved anyway, jest exiting 0, and a false negative on a genuinely
    exploitable finding.

    Deterministic rather than a retry, because it is arithmetic on recorded facts and the model
    reading them was not being unreasonable — the evidence it saw did look like a negative.
    """
    if diagnosis.kind is not DiagnosisKind.valid_negative or execution.sink_returned:
        return diagnosis
    return diagnosis.model_copy(update={
        "kind": DiagnosisKind.probe_defect,
        "explanation": (
            "Recorded as a probe defect rather than a negative: the probe never printed the "
            "sink-returned marker, so the call it was meant to exercise cannot be shown to "
            "have completed. A payload that never reached the sink says nothing about whether "
            "the code resists it. Original reading: " + diagnosis.explanation
        ),
        "fix_hint": diagnosis.fix_hint or (
            "Print HARNESS_SINK_RETURNED::<nonce> immediately after the sink call returns, and "
            "do not swallow an exception raised by that call."
        ),
    })


def _ground_zero_test_diagnosis(diagnosis: ProbeDiagnosis,
                                execution: ProbeExecution) -> ProbeDiagnosis:
    """Reject unsupported positive/negative readings without choosing the repair cause.

    Zero tests can result from a defective probe or an environment failure. Diagnosis owns
    that distinction and its repair hint; recorded runner evidence remains in the prompt.
    A fired oracle is stronger evidence than a runner's test-count summary.
    """
    if (not execution.runner_reported_no_tests or execution.oracle_fired
            or diagnosis.kind in {DiagnosisKind.probe_defect, DiagnosisKind.environment_issue}):
        return diagnosis
    return diagnosis.model_copy(update={
        "kind": DiagnosisKind.probe_defect,
        "explanation": (
            f"The test runner reported that it executed no tests: "
            f"{execution.runner_reported_no_tests} Original reading: {diagnosis.explanation}"
        ),
    })


@dataclass
class DiagnoseProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]
                  ) -> RepairProbe | RepairEnvironment | Decide:
        s = ctx.state
        execution = s.executions[-1]
        prompt = render_prompt(
            "Classify this probe execution: probe_defect, valid_negative, valid_positive, or "
            "environment_issue. Treat runner-reported zero tests as evidence of failed "
            "execution; identify whether the cause belongs to the probe or its environment.",
            {"probe_plan": s.plan, "probe_source": s.probe, "probe_execution": execution},
            stack=s.stack, profile=s.profile,
        )
        outcome = await ctx.deps.ops.run_agent("probe-diagnosis", prompt, s.deps(),
                                               record=s.invocations)
        s.last_diagnosis = _ground_zero_test_diagnosis(
            _correct_unsupported_negative(outcome.output, execution), execution)
        if (s.last_diagnosis.kind == DiagnosisKind.probe_defect
                and s.probe_repairs < ctx.deps.max_probe_repairs):
            return RepairProbe()
        # An environment problem found at probe time used to end the finding: the diagnosis was
        # recorded, nothing acted on it, and the run reported `inconclusive`. The probe was
        # usually fine -- measured on java-sqli, where `No suitable driver found` meant a
        # missing test dependency, and probe-repair, the only agent downstream, could see the
        # cause but had no power to install anything. Hand it back to the stage that does.
        if (s.last_diagnosis.kind == DiagnosisKind.environment_issue
                and s.environment_repairs < ctx.deps.max_environment_repairs):
            return RepairEnvironment()
        return Decide()


@dataclass
class RepairProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> ExecuteProbe:
        s = ctx.state
        s.probe_repairs += 1
        prompt = render_prompt(
            "Fix this probe so it runs honestly and still checks the same exploit condition. "
            "Keep the markers and the same oracle_nonce.",
            {"finding": s.finding, "probe_plan": s.plan, "probe_source": s.probe,
             "probe_execution": s.executions[-1], "diagnosis": s.last_diagnosis,
             "oracle_nonce": s.nonce}, stack=s.stack, profile=s.profile,
        )
        outcome = await ctx.deps.ops.run_agent("probe-repair", prompt, s.deps(),
                                               record=s.invocations)
        s.probe = outcome.output
        return ExecuteProbe()


@dataclass
class RepairEnvironment(BaseNode[TriageState, TriageDeps, TriageResult]):
    """Re-plan and rebuild the environment from what the probe run revealed, then retry.

    The image built and smoke-tested clean, so preparation had no way to know anything was
    missing: the gap only appears when the probe actually exercises the code. `build-repair` is
    the agent that owns environment specs, so it is the one asked, but the evidence it gets is
    the probe's output rather than a build log -- and the prompt says so, because "the build
    failed, here is the log" would be a lie and invites it to fix a build that worked.

    The probe source is deliberately NOT changed here. It is being re-run unmodified, because
    the whole premise of this edge is that the probe was correct and its environment was not.
    """

    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> ExecuteProbe | Decide:
        s = ctx.state
        s.environment_repairs += 1
        execution = s.executions[-1]
        revised = await revise_environment(
            ctx.deps.ops, "build-repair", _PROBE_ENVIRONMENT_REPAIR,
            {"build_error": execution.stderr_tail or execution.stdout_tail,
             "probe_source": s.probe, "diagnosis": s.last_diagnosis},
            failed_spec=s.spec, tried=[s.spec], snapshot=s.prepared.snapshot, stack=s.stack,
            profile=s.profile, record=s.invocations)
        if revised is None:
            s.early_exit = "environment_repair_no_progress"
            return Decide()
        build = await ctx.deps.ops.build_environment(s.prepared.snapshot, revised)
        if not build.ok:
            # Nothing is retried from here. The prepared environment stays as it was, so the
            # recorded spec still describes the image the probe actually ran in.
            s.early_exit = "environment_repair_failed"
            return Decide()
        # The runner is re-verified because a revised spec may change the base image, and a
        # missing runner at probe time reads as exit 127 -- a probe defect that is not one.
        smoke = await smoke_test(ctx.deps.ops, build, s.stack)
        if not smoke.ok:
            s.early_exit = "environment_repair_failed"
            return Decide()
        s.prepared = s.prepared.model_copy(update={"build": build, "smoke": smoke})
        return ExecuteProbe()


_PROBE_ENVIRONMENT_REPAIR = (
    "The image built and smoke-tested clean, but running the probe showed the environment is "
    "missing something the test needs. Return a revised EnvironmentSpec that installs it. Keep "
    "the test command's selector, flags and paths as they are: the probe is not at fault and "
    "will be re-run unchanged.")


@dataclass
class Decide(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> End[TriageResult]:
        s = ctx.state
        last_exec = s.executions[-1] if s.executions else None
        diagnosis = s.last_diagnosis
        reachability = s.context.reachability if s.context else Reachability.unknown
        facts = VerdictFacts(
            environment_ready=s.prepared.status == "ready",
            oracle_fired=bool(last_exec and last_exec.oracle_fired),
            precondition_reached=bool(last_exec and last_exec.precondition_reached),
            sink_returned=bool(last_exec and last_exec.sink_returned),
            last_diagnosis=diagnosis.kind if diagnosis else None,
            reachability=reachability,
            probe_repairs_exhausted=s.probe_repairs >= ctx.deps.max_probe_repairs,
        )
        # Deterministic inconclusive when the probe never ran honestly within budget.
        if diagnosis and diagnosis.kind == DiagnosisKind.probe_defect:
            verdict = inconclusive_verdict(
                InconclusiveReason.probe_unrepairable,
                "The probe could not be made to run honestly within the repair budget: "
                + diagnosis.explanation, confidence=0.3)
            s.early_exit = "probe_unrepairable"
            return End(_finalize(s, verdict, reachability))
        prompt = render_prompt(
            "Decide the three-way exploitability verdict from the evidence. Stay faithful to the "
            "recorded facts.",
            {"finding": s.finding, "finding_context": s.context, "probe_plan": s.plan,
             "probe_execution": last_exec, "diagnosis": diagnosis},
            stack=s.stack, profile=s.profile,
        )
        try:
            outcome = await ctx.deps.ops.run_agent("verdict", prompt, s.deps(facts=facts),
                                                   record=s.invocations)
        except UnexpectedModelBehavior as e:
            # The judge could not produce a verdict the evidence contract accepts within its
            # retry budget. `inconclusive` is precisely the answer the three-way contract
            # reserves for "the evidence does not support a call", so return it rather than
            # failing the finding — and, in a batch, every finding behind it. The failed call
            # is already in the record, with whatever usage it had.
            verdict = inconclusive_verdict(
                InconclusiveReason.error,
                f"The verdict agent could not satisfy the evidence contract: {e}")
            s.early_exit = "verdict_contract_unsatisfied"
            return End(_finalize(s, verdict, reachability))
        verdict = await _validate_verdict_citations(ctx.deps.ops, s, outcome.output)
        # Fail closed: a missing or unparseable control record is not a passed control.
        controls = parse_control_result(s.prepared.smoke.output_excerpt) if s.prepared.smoke else None
        controls_passed = controls is not None and controls.passed
        if (verdict.label is VerdictLabel.likely_not_exploitable
                and (diagnosis is None or diagnosis.kind is not DiagnosisKind.valid_negative
                     or not last_exec or not last_exec.sink_returned
                     or not controls_passed)):
            verdict = inconclusive_verdict(
                InconclusiveReason.conflicting_evidence,
                "A negative security judgment was rejected because the run did not have both a "
                "valid negative execution that completed the sink call and passing versioned "
                "positive/negative adapter controls.", evidence=verdict.evidence)
            s.early_exit = "unsupported_negative"
        return End(_finalize(s, verdict, reachability))


def build_triage_graph():
    g = GraphBuilder(state_type=TriageState, deps_type=TriageDeps, output_type=TriageResult)
    g.add(
        g.edge_from(g.start_node).to(GatherContext),
        g.node(GatherContext),
        g.node(PlanProbe),
        g.node(AuthorProbe),
        g.node(ExecuteProbe),
        g.node(DiagnoseProbe),
        g.node(RepairProbe),
        g.node(RepairEnvironment),
        g.node(Decide),
    )
    return g.build()


TRIAGE_GRAPH = build_triage_graph()
