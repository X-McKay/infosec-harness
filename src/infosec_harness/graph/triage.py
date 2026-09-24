"""Finding-triage graph (F1-F9): the per-finding topology, built with pydantic-graph.

It runs unchanged standalone (LocalOps) or inside a Temporal workflow (TemporalOps). Nodes
touch side effects only through ``ctx.deps.ops``; all control flow (the execute->diagnose->
repair loop, early exits) is expressed as typed node transitions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

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

    @property
    def image_tag(self) -> str:
        return self.prepared.build.image_tag if self.prepared.build else ""

    @property
    def spec(self):
        return self.prepared.build.spec

    def deps(self, facts: VerdictFacts | None = None) -> AgentDeps:
        return AgentDeps(repo_path=self.prepared.snapshot.path, sandbox_image=self.image_tag, facts=facts)

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
        outcome = await ctx.deps.ops.run_agent("probe_planner", prompt, s.deps())
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
        outcome = await ctx.deps.ops.run_agent("probe_author", prompt, s.deps())
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


@dataclass
class DiagnoseProbe(BaseNode[TriageState, TriageDeps, TriageResult]):
    async def run(self, ctx: GraphRunContext[TriageState, TriageDeps]) -> RepairProbe | Decide:
        s = ctx.state
        execution = s.executions[-1]
        prompt = render_prompt(
            "Classify this probe execution: probe_defect, valid_negative, valid_positive, or "
            "environment_issue.",
            {"probe_plan": s.plan, "probe_source": s.probe, "probe_execution": execution},
            stack=s.stack(), profile=s.profile(),
        )
        outcome = await ctx.deps.ops.run_agent("probe_diagnosis", prompt, s.deps())
        s.invocations.append(outcome)
        s.last_diagnosis = outcome.output
        if s.last_diagnosis.kind == DiagnosisKind.probe_defect and s.attempt <= ctx.deps.max_probe_repairs:
            return RepairProbe()
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
        outcome = await ctx.deps.ops.run_agent("probe_repair", prompt, s.deps())
        s.invocations.append(outcome)
        s.probe = outcome.output
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
        outcome = await ctx.deps.ops.run_agent("verdict", prompt, s.deps(facts=facts))
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
        g.node(Decide),
    )
    return g.build()


TRIAGE_GRAPH = build_triage_graph()
