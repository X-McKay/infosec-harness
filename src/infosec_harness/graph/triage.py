"""Finding-triage graph (F1-F9): the per-finding topology, built with pydantic-graph.

It runs unchanged standalone (LocalOps) or inside a Temporal workflow (TemporalOps). Nodes
touch side effects only through ``ctx.deps.ops``; all control flow (the execute->diagnose->
repair loop, early exits) is expressed as typed node transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic_ai.exceptions import UnexpectedModelBehavior
from pydantic_graph import BaseNode, End, GraphBuilder, GraphRunContext

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import (
    DiagnosisKind,
    Finding,
    FindingContext,
    InconclusiveReason,
    PreparedEnvironment,
    ProbeDiagnosis,
    ProbeExecution,
    ProbePlan,
    ProbeSource,
    Reachability,
    TriageResult,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)
from infosec_harness.graph.ops import AgentOutcome, Ops
from infosec_harness.graph.scoring import PreFilterResult, pre_filter, priority_band, priority_score
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
    attempt: int = 0
    context: FindingContext | None = None
    plan: ProbePlan | None = None
    probe: ProbeSource | None = None
    executions: list[ProbeExecution] = field(default_factory=list)
    last_diagnosis: ProbeDiagnosis | None = None
    invocations: list[AgentOutcome] = field(default_factory=list)
    early_exit: str | None = None
    # Probe-time environment re-plans already spent (RepairEnvironment).
    environment_repairs: int = 0

    @property
    def image_tag(self) -> str:
        return self.prepared.build.image_tag if self.prepared.build else ""

    @property
    def spec(self):
        return self.prepared.build.spec

    def deps(self, facts: VerdictFacts | None = None) -> AgentDeps:
        return AgentDeps(repo_path=self.prepared.snapshot.path, sandbox_image=self.image_tag,
                         facts=facts, source_files=self.source_files)

    @property
    def source_files(self) -> int | None:
        """How much repository the agents have to explore, for budget scaling."""
        return sum((self.prepared.stack.languages or {}).values()) or None

    def stack(self):
        return self.prepared.stack

    def profile(self):
        return self.prepared.profile


def _finalize(state: TriageState, verdict: Verdict, reachability: Reachability) -> TriageResult:
    score = priority_score(state.finding, verdict, reachability)
    return TriageResult(
        fingerprint=state.finding.fingerprint,
        verdict=verdict,
        priority_score=score,
        priority=priority_band(score),
        environment_scope=state.spec.scope if state.prepared.status == "ready" else "none",
        early_exit=state.early_exit,
    )


@dataclass
class PreFilter(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> GatherContext | End[TriageResult]:
        result: PreFilterResult = pre_filter(ctx.state.finding, ctx.state.prepared.snapshot)
        if not result.continue_triage:
            ctx.state.early_exit = result.note
            return End(_finalize(ctx.state, result.verdict, Reachability.unknown))
        return GatherContext()


@dataclass
class GatherContext(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> PlanProbe:
        s = ctx.state
        prompt = render_prompt(
            "Gather the code slice for this finding: source, sink, data path, sanitizers, "
            "reachability, and the target callable a unit test should drive.",
            {"finding": s.finding}, stack=s.stack(), profile=s.profile(),
        )
        outcome = await ctx.deps.ops.run_agent("context", prompt, s.deps())
        s.invocations.append(outcome)
        s.context = outcome.output
        return PlanProbe()


@dataclass
class PlanProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> AuthorProbe | End[TriageResult]:
        s = ctx.state
        # Only `unreachable` skips the probe. `neutralized` does NOT: it says untrusted input
        # reaches the sink and a named control stops it, and whether that control actually
        # holds is a claim about behaviour -- exactly what the probe is for. Measured: both
        # Java `fixed` cases took this exit with no build, probe or oracle behind them, and the
        # same reasoning on a vulnerable case is a false negative, the costliest error here.
        if s.context and s.context.reachability == Reachability.unreachable and (
            s.context.source or s.context.sink or s.context.path
        ):
            evidence = [r for r in (s.context.sink, s.context.source) if r] + s.context.path
            verdict = Verdict(
                label=VerdictLabel.likely_not_exploitable, confidence=0.7,
                rationale="Context analysis shows the sink is not reachable from untrusted input: "
                + s.context.reachability_rationale,
                evidence=evidence[:5],
            )
            s.early_exit = "unreachable_by_context"
            return End(_finalize(s, verdict, Reachability.unreachable))
        prompt = render_prompt(
            "Plan a targeted unit-test probe and define its deterministic oracle.",
            {"finding": s.finding, "finding_context": s.context}, stack=s.stack(), profile=s.profile(),
        )
        outcome = await ctx.deps.ops.run_agent("probe-planner", prompt, s.deps())
        s.invocations.append(outcome)
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
             "oracle_nonce": s.nonce}, stack=s.stack(), profile=s.profile(),
        )
        outcome = await ctx.deps.ops.run_agent("probe-author", prompt, s.deps())
        s.invocations.append(outcome)
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
    """When the runner said it ran no tests, make that the recorded cause.

    `_correct_unsupported_negative` above already stops a zero-test run being called a negative,
    because nothing printed the sink-returned marker. What it cannot fix is a diagnosis that
    reaches the right *kind* for the wrong *reason* — and the reason is what the repair agent
    acts on. Measured on perl-cmdi-vulnerable: prove printed `skipped: (no reason given)` with
    exit 255 and an empty stderr, the diagnosis correctly said probe_defect but explained it as
    "the file was either not written correctly, or crashed without producing output", the repair
    rewrote the file that was never the problem, and three attempts later a genuinely
    exploitable finding was reported `inconclusive`.

    So the runner's own words are promoted ahead of the model's reading, and the fix_hint is
    replaced rather than defaulted: an existing hint here is precisely the speculative one that
    sent the repair loop the wrong way. Deterministic for the same reason as above — it is a
    recorded fact, and the model was not being unreasonable about the evidence it could see.
    """
    if not execution.runner_reported_no_tests:
        return diagnosis
    return diagnosis.model_copy(update={
        "kind": DiagnosisKind.probe_defect,
        "explanation": (
            f"The test runner reported that it executed no tests: "
            f"{execution.runner_reported_no_tests} Repair what stopped the test from running, "
            f"not the probe's logic. Original reading: {diagnosis.explanation}"
        ),
        "fix_hint": (
            "A run that executed zero tests has a short list of causes; check them in order. "
            "(1) The file is not where the runner looks — confirm the path and that the runner "
            "was pointed at it. (2) The selector matches no test — a class/function name "
            "filter that does not match runs nothing and can still exit 0. (3) The plan or "
            "assertion count was emitted before the assertions ran. (4) The module under test "
            "failed to load, so the file aborted before its first assertion; if the runner "
            "buffers the child's stderr this leaves no message at all, so print a marker as "
            "the very first statement to distinguish 'never started' from 'started and died'."
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
            "environment_issue.",
            {"probe_plan": s.plan, "probe_source": s.probe, "probe_execution": execution},
            stack=s.stack(), profile=s.profile(),
        )
        outcome = await ctx.deps.ops.run_agent("probe-diagnosis", prompt, s.deps())
        s.invocations.append(outcome)
        s.last_diagnosis = _ground_zero_test_diagnosis(
            _correct_unsupported_negative(outcome.output, execution), execution)
        if s.last_diagnosis.kind == DiagnosisKind.probe_defect and s.attempt <= ctx.deps.max_probe_repairs:
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
        prompt = render_prompt(
            "Fix this probe so it runs honestly and still checks the same exploit condition. "
            "Keep the markers and the same oracle_nonce.",
            {"finding": s.finding, "probe_plan": s.plan, "probe_source": s.probe,
             "probe_execution": s.executions[-1], "diagnosis": s.last_diagnosis,
             "oracle_nonce": s.nonce}, stack=s.stack(), profile=s.profile(),
        )
        outcome = await ctx.deps.ops.run_agent("probe-repair", prompt, s.deps())
        s.invocations.append(outcome)
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
        outcome = await ctx.deps.ops.run_agent(
            "build-repair",
            render_prompt(
                "The image built and smoke-tested clean, but running the probe showed the "
                "environment is missing something the test needs. Return a revised "
                "EnvironmentSpec that installs it. Keep the test command's selector, flags and "
                "paths as they are: the probe is not at fault and will be re-run unchanged.",
                {"failed_spec": s.spec, "build_error": execution.stderr_tail or execution.stdout_tail,
                 "probe_source": s.probe, "diagnosis": s.last_diagnosis,
                 "previous_attempts": [s.spec.model_dump()]},
                stack=s.stack(), profile=s.profile(),
            ),
            AgentDeps(repo_path=s.prepared.snapshot.path, sandbox_image=s.spec.base_image,
                      source_files=s.source_files),
        )
        s.invocations.append(outcome)
        build = await ctx.deps.ops.build_environment(s.prepared.snapshot, outcome.output)
        if not build.ok:
            # Nothing is retried from here. The prepared environment stays as it was, so the
            # recorded spec still describes the image the probe actually ran in.
            s.early_exit = "environment_repair_failed"
            return Decide()
        # The runner is re-verified because a revised spec may change the base image, and a
        # missing runner at probe time reads as exit 127 -- a probe defect that is not one.
        smoke = await ctx.deps.ops.smoke_test(build.image_tag, build.spec.test_command)
        if not smoke.ok:
            s.early_exit = "environment_repair_failed"
            return Decide()
        s.prepared = s.prepared.model_copy(update={"build": build, "smoke": smoke})
        return ExecuteProbe()


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
            last_diagnosis=diagnosis.kind if diagnosis else None,
            reachability=reachability,
            probe_repairs_exhausted=s.attempt > ctx.deps.max_probe_repairs,
        )
        # Deterministic inconclusive when the probe never ran honestly within budget.
        if diagnosis and diagnosis.kind == DiagnosisKind.probe_defect:
            verdict = Verdict(
                label=VerdictLabel.inconclusive, confidence=0.3,
                rationale="The probe could not be made to run honestly within the repair budget: "
                + diagnosis.explanation,
                inconclusive_reason=InconclusiveReason.probe_unrepairable,
            )
            s.early_exit = "probe_unrepairable"
            return End(_finalize(s, verdict, reachability))
        prompt = render_prompt(
            "Decide the three-way exploitability verdict from the evidence. Stay faithful to the "
            "recorded facts.",
            {"finding": s.finding, "finding_context": s.context, "probe_plan": s.plan,
             "probe_execution": last_exec, "diagnosis": diagnosis},
            stack=s.stack(), profile=s.profile(),
        )
        try:
            outcome = await ctx.deps.ops.run_agent("verdict", prompt, s.deps(facts=facts))
        except UnexpectedModelBehavior as e:
            # The judge could not produce a verdict the evidence contract accepts within its
            # retry budget. `inconclusive` is precisely the answer the three-way contract
            # reserves for "the evidence does not support a call", so return it rather than
            # failing the finding — and, in a batch, every finding behind it.
            verdict = Verdict(
                label=VerdictLabel.inconclusive, confidence=0.0,
                rationale=f"The verdict agent could not satisfy the evidence contract: {e}",
                inconclusive_reason=InconclusiveReason.error,
            )
            s.early_exit = "verdict_contract_unsatisfied"
            return End(_finalize(s, verdict, reachability))
        s.invocations.append(outcome)
        return End(_finalize(s, outcome.output, reachability))


def build_triage_graph():
    g = GraphBuilder(state_type=TriageState, deps_type=TriageDeps, output_type=TriageResult)
    g.add(
        g.edge_from(g.start_node).to(PreFilter),
        g.node(PreFilter),
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
