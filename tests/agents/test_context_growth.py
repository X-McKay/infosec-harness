"""Nothing in a run's context may grow with the number of iterations or turns.

Two independent growth paths reach the same failure — `UsageLimitExceeded` on an input
ceiling — and only one of them is about the number:

1. *Across* repair-loop iterations. Each `execute -> diagnose -> repair` pass is a fresh
   agent run built from typed state, so the prompt carries the current probe, the last
   execution and the diagnosis, and never the transcript of earlier passes. That is a
   property of `graph/triage.py`, not an accident of the models, and the first test pins it:
   appending the prior probe and output to each repair prompt would grow the prompt linearly
   in the repair count and is exactly the shape a ~120k input ceiling cannot survive.

2. *Within* one agent run. Every request resends the whole conversation, so a retained tool
   result is paid for again on every later turn and per-request input grows with turn count.
   Measured on eval-corpus/java/sqli/vulnerable before compaction was enabled: 12.8 kB at
   turn 1, 116 kB at turn 19, on a repository whose entire source is 1.3 kB. The second test
   pins the plateau, and its companion shows the plateau is the capability's doing rather
   than a property of the fixture.

Both are shape tests. A number would have to be re-chosen the next time a prompt or a skill
changes; the shape must hold whatever those are.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from pydantic_ai.messages import ModelMessage, ModelResponse, ToolCallPart
from pydantic_ai.models.function import AgentInfo, FunctionModel
from pydantic_ai_harness.compaction import estimate_token_count

from infosec_harness.domain.models import (
    AgentOutcome,
    DiagnosisKind,
    EnvironmentSpec,
    Finding,
    FindingContext,
    FindingSourceKind,
    OracleKind,
    PreparedEnvironment,
    ProbeDiagnosis,
    ProbeExecution,
    ProbePlan,
    ProbeSource,
    Reachability,
    RepoSnapshot,
    StackFingerprint,
)
from infosec_harness.graph.triage import TRIAGE_GRAPH, GatherContext, TriageDeps, TriageState
from infosec_harness.runtime.deps import AgentDeps
from infosec_harness.runtime.registry import DEFAULT_CLEAR_TOOL_TOKENS, build_agent
from infosec_harness.runtime.render import prompt_text, render_prompt

# --- 1. The repair loop does not carry earlier iterations forward -------------------------


class _RecordingOps:
    """An `Ops` whose agents are canned, so the only variable is what the graph puts in a prompt.

    Every repair returns a probe whose content names its own iteration, which is what lets the
    assertions below distinguish "the current probe" from "the transcript so far".
    """

    def __init__(self, repo: str):
        self.repo = repo
        self.prompts: list[tuple[str, str]] = []
        self.repairs = 0

    async def validate_citations(self, repo_path, references):
        from infosec_harness.repo.access import validate_citations

        return validate_citations(repo_path, references)

    async def run_agent(self, name: str, prompt, deps: AgentDeps, *,
                        record: list[AgentOutcome] | None = None) -> AgentOutcome:
        self.prompts.append((name, prompt_text(prompt)))
        outcome = AgentOutcome(output=self._output(name), agent=name)
        if record is not None:
            record.append(outcome)
        return outcome

    def _output(self, name: str):
        if name == "context":
            return FindingContext(summary="s", reachability=Reachability.reachable,
                                  reachability_rationale="r", target_callable="app.lookup")
        if name == "probe-planner":
            return ProbePlan(hypothesis="h", payload="p", oracle=OracleKind.marker_output,
                             oracle_condition="c", precondition_checkpoint="k",
                             test_file_path="tests/test_probe.py")
        if name == "probe-author":
            return self._probe(0)
        if name == "probe-diagnosis":
            return ProbeDiagnosis(kind=DiagnosisKind.probe_defect,
                                  explanation="the import never resolved", fix_hint="fix it")
        if name == "probe-repair":
            self.repairs += 1
            return self._probe(self.repairs)
        raise AssertionError(f"unexpected agent {name!r}")

    @staticmethod
    def _probe(iteration: int) -> ProbeSource:
        # Same length at every iteration, so a size comparison measures accumulation only.
        return ProbeSource(test_file_path="tests/test_probe.py",
                           content=f"# probe revision {iteration:04d}\ndef test_x(): pass\n")

    async def new_nonce(self) -> str:
        return "nonce"

    async def execute_probe(self, image_tag, probe, spec, nonce, attempt) -> ProbeExecution:
        return ProbeExecution(attempt=attempt, exit_code=1, oracle_fired=False,
                              precondition_reached=False, sink_returned=False,
                              stderr_tail="ModuleNotFoundError: app")

    async def build_environment(self, snapshot, spec):  # pragma: no cover - unused here
        raise AssertionError("triage does not build")

    async def smoke_test(self, image_tag, test_command=""):  # pragma: no cover - unused here
        raise AssertionError("triage does not smoke test")


def _prepared(repo: str) -> PreparedEnvironment:
    from infosec_harness.domain.models import BuildResult, RepoProfile

    stack = StackFingerprint(languages={"python": 1}, manifests=["requirements.txt"],
                             test_frameworks=["pytest"])
    snapshot = RepoSnapshot(repo_url=repo, revision="HEAD", path=repo, content_hash="h" * 8)
    spec = EnvironmentSpec(base_image="python:3.12-slim", test_command="pytest -s {test_file}")
    return PreparedEnvironment(
        snapshot=snapshot, stack=stack, status="ready",
        profile=RepoProfile(summary="s", primary_language="python", test_framework="pytest",
                            test_layout="tests"),
        build=BuildResult(ok=True, image_tag="img", spec=spec),
    )


async def _repair_prompts() -> list[str]:
    repo = tempfile.mkdtemp()
    Path(repo, "requirements.txt").write_text("")
    Path(repo, "app.py").write_text("def lookup(db, n):\n    return db.execute('SELECT ' + n)\n")
    ops = _RecordingOps(repo)
    finding = Finding(fingerprint="f" * 16, title="SQLi", repo_url=repo, revision="HEAD",
                      cwe="CWE-89", source_kind=FindingSourceKind.generic_json)
    state = TriageState(finding=finding, prepared=_prepared(repo))
    await TRIAGE_GRAPH.run(state=state, deps=TriageDeps(ops=ops), inputs=GatherContext())
    return [text for name, text in ops.prompts if name == "probe-repair"]


async def test_a_repair_iteration_does_not_carry_the_previous_iterations_forward():
    """The repair prompt is built from state, so it names the current probe and nothing older.

    Carrying the transcript would be invisible in a short run and fatal in a long one: with
    `max_probe_repairs = 3` the third repair would resend three probes and three executions,
    and the only symptom is an input ceiling firing on a legitimate repair.
    """
    prompts = await _repair_prompts()
    assert len(prompts) >= 3, "the fixture must exercise several repair iterations"
    for iteration, text in enumerate(prompts):
        assert f"# probe revision {iteration:04d}" in text, (
            f"repair {iteration} must be shown the probe it is repairing"
        )
        for older in range(iteration):
            assert f"# probe revision {older:04d}" not in text, (
                f"repair {iteration} carries revision {older} forward; the prompt is "
                "accumulating the transcript instead of the current state"
            )


async def test_the_repair_prompt_does_not_grow_with_the_iteration_count():
    """Size is the thing the budget sees, so assert on size too, not only on content.

    The iterations differ by an attempt number and a revision counter — a few bytes — so any
    growth that scales with the iteration index is accumulation.
    """
    prompts = await _repair_prompts()
    sizes = [len(text) for text in prompts]
    one_iteration = sizes[0]
    assert max(sizes) - min(sizes) < one_iteration // 10, (
        f"repair prompt sizes {sizes} spread by more than a tenth of one iteration "
        f"({one_iteration} chars), so something is accumulating across iterations"
    )


# --- 2. Within one run, per-request input plateaus instead of tracking turn count ---------

_VALID_PROBE = {
    "test_file_path": "tests/test_probe.py",
    "content": ("def test_probe():\n"
                "    print('HARNESS_PRECONDITION::n')\n"
                "    print('HARNESS_SINK_RETURNED::n')\n"
                "    print('HARNESS_ORACLE::n')\n"),
    "explanation": "drives the sink",
}
_READ_TURNS = 12
# The production trigger is DEFAULT_CLEAR_TOOL_TOKENS; reaching it here would need a fixture
# several times larger for no extra signal, since what is under test is whether per-request
# input plateaus at *a* trigger, not which one. tests/agents/test_budgets.py pins the production
# value's relationship to the per-request ceiling.
_TEST_TRIGGER = 5_000
assert _TEST_TRIGGER < DEFAULT_CLEAR_TOOL_TOKENS, "the test trigger must be the easier one"


def _repo_of_readable_modules() -> str:
    repo = tempfile.mkdtemp()
    Path(repo, "requirements.txt").write_text("")
    Path(repo, "tests").mkdir()
    for n in range(_READ_TURNS):
        # 400 lines is MAX_READ_LINES, so one read returns a whole file in a single result.
        body = "\n".join(f"def helper_{n}_{i}(db, name):  # {'x' * 40}" for i in range(400))
        Path(repo, f"mod_{n}.py").write_text(body + "\n")
    return repo


async def _history_tokens_per_request(*, compact: bool) -> list[int]:
    """Estimated history size the model was handed on each request of one probe-author run.

    One read per turn, each a different file, so nothing here is a re-read: this is the cost
    of ordinary exploration, not of a loop.
    """
    repo = _repo_of_readable_modules()
    overlay = ({"metadata": {"clear_tool_tokens": _TEST_TRIGGER}} if compact
               else {"metadata": {"clear_tool_results": False}})
    agent = build_agent("probe-author", overlay, durable=False)
    seen: list[int] = []
    reads = iter(range(_READ_TURNS))

    def fn(messages: list[ModelMessage], info: AgentInfo) -> ModelResponse:
        seen.append(estimate_token_count(messages))
        try:
            n = next(reads)
        except StopIteration:
            return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, _VALID_PROBE)])
        return ModelResponse(parts=[ToolCallPart("read_file", {
            "path": f"mod_{n}.py", "start_line": 1, "end_line": 400})])

    plan = ProbePlan(hypothesis="h", payload="p", oracle=OracleKind.marker_output,
                     oracle_condition="c", precondition_checkpoint="k",
                     test_file_path="tests/test_probe.py")
    prompt = render_prompt("Write the probe.", {"probe_plan": plan, "oracle_nonce": "n"})
    with agent.override(model=FunctionModel(fn)):
        await agent.run(prompt, deps=AgentDeps(repo_path=repo))
    return seen


def _one_tool_result(history: list[int]) -> int:
    """What a single retained read costs, taken from the run itself rather than assumed."""
    return history[2] - history[1]


async def test_per_request_input_plateaus_instead_of_tracking_the_turn_count():
    """Past the trigger, another turn must not make every later request bigger.

    This is the half of the fix a larger ceiling cannot buy. While per-request input tracks
    the turn count, *every* ceiling is reached eventually by an agent that merely keeps
    working — raising the number only moves the turn at which it happens.
    """
    history = await _history_tokens_per_request(compact=True)
    assert len(history) > _READ_TURNS // 2, "the fixture must make many turns"
    half = len(history) // 2
    growth = history[-1] - history[half]
    assert growth < _one_tool_result(history), (
        f"per-request input grew {growth} estimated tokens over the run's second half "
        f"({history}), more than the {_one_tool_result(history)} a single read costs, so it is "
        "still tracking the turn count"
    )


async def test_the_plateau_is_the_capabilitys_doing_and_not_the_fixtures():
    """The companion: the same run without compaction must grow linearly instead.

    Without this, the test above would keep passing if the capability were dropped and the
    fixture simply stopped being large enough — which is how the original ceiling came to look
    safe: it was compared against a single call while the run was allowed sixteen.
    """
    uncompacted = await _history_tokens_per_request(compact=False)
    compacted = await _history_tokens_per_request(compact=True)
    half = len(uncompacted) // 2
    growth = uncompacted[-1] - uncompacted[half]
    assert growth > _one_tool_result(uncompacted) * 3, (
        f"without compaction the fixture only grew {growth} estimated tokens over its second "
        f"half ({uncompacted}), so it cannot show that compaction is what bounds the history"
    )
    assert max(uncompacted) > max(compacted) * 2, (
        f"uncompacted {max(uncompacted)} vs compacted {max(compacted)}: compaction is not "
        "measurably bounding the history"
    )
