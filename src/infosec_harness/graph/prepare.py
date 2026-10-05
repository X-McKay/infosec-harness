"""Repository preparation (P2-P6): profile, plan, build with a bounded repair loop, then a
partial-build fallback, then a smoke test. Runs once per repo@revision and is cached.

Expressed as an orchestrator over the same Ops interface as the triage graph, so it runs
standalone or durably. The build-repair and partial-build loops are aggressive within hard
caps (D6).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.agents.render import render_prompt
from infosec_harness.domain.models import (
    BuildResult,
    EnvironmentSpec,
    Finding,
    PreparedEnvironment,
    RepoProfile,
    RepoSnapshot,
    SmokeResult,
    StackFingerprint,
)
from infosec_harness.graph.ops import AgentOutcome, Ops
from infosec_harness.repo.components import component_stack, owning_component
from infosec_harness.settings import get_settings


@dataclass
class PrepareOutcome:
    prepared: PreparedEnvironment
    invocations: list[AgentOutcome] = field(default_factory=list)


class PrepareFailed(Exception):
    """A preparation that raised, carrying the agent calls it had already completed.

    Preparation makes up to a dozen agent calls, and until this existed the list of them was a
    local variable that died with the exception. Measured: a live run over harvested
    repositories failed all six cases in the prepare phase and its metrics contained
    ``"trajectory": {}`` and ``"budget": {}`` -- nothing at all about what recon and env-planner
    had done, on precisely the failures that most needed explaining. The two instruments built
    to diagnose this (the per-agent request/loop report and the stage funnel) were blind
    exactly where they were needed.

    The partial list *is* the evidence, so it travels with the failure. ``cause`` is the
    original exception: callers classify on its type, and wrapping must not hide it.
    """

    def __init__(self, cause: BaseException, invocations: list[AgentOutcome]) -> None:
        self.cause = cause
        self.invocations = invocations
        super().__init__(f"{type(cause).__name__}: {cause}")


async def run_prepare(ops: Ops, snapshot: RepoSnapshot, stack: StackFingerprint, *,
                      component_root: str = ".") -> PrepareOutcome:
    """Prepare one repository, or raise :class:`PrepareFailed` with the calls that did run.

    Every exception from the body is wrapped, because the caller's decision (which
    ``InconclusiveReason`` this deserves) is made on the type of the *cause*, not on this
    wrapper. ``BaseException`` deliberately passes through unwrapped: a cancellation or a
    Ctrl-C is not a statement about the repository and must keep its own semantics.
    """
    invocations: list[AgentOutcome] = []
    try:
        return await _run_prepare(ops, snapshot, stack, invocations, component_root=component_root)
    except Exception as e:
        raise PrepareFailed(e, invocations) from e


_BUILD_FAILED = "The build failed; diagnose the log and return a revised EnvironmentSpec."
_PARTIAL_BUILD = ("The full build failed; plan the smallest buildable unit containing the code and "
                  "return a partial EnvironmentSpec.")
_READINESS_FAILED = ("The image built, but its offline readiness check failed. Repair the "
                     "environment or test-runner setup and return a revised EnvironmentSpec.")


async def revise_environment(ops: Ops, agent: str, instruction: str, evidence: dict, *,
                             failed_spec: EnvironmentSpec, tried: list[EnvironmentSpec],
                             snapshot: RepoSnapshot, stack: StackFingerprint,
                             profile: RepoProfile | None, record: list[AgentOutcome],
                             bind: Callable[[EnvironmentSpec], EnvironmentSpec] = lambda s: s,
                             ) -> EnvironmentSpec | None:
    """Ask ``agent`` for a revised spec from one failure's evidence.

    Returns the revision, appended to ``tried``, or None when it repeats a plan already tried:
    rebuilding an equivalent plan cannot change the result and only spends the budget. Shared
    by preparation's repair loops and the probe-time environment repair, so every revision is
    asked the same way: the failed spec, the evidence, every attempt so far, and the failed
    image to inspect.
    """
    outcome = await ops.run_agent(
        agent,
        render_prompt(instruction, {"failed_spec": failed_spec, **evidence,
                                    "previous_attempts": [t.model_dump() for t in tried]},
                      stack=stack, profile=profile),
        AgentDeps(repo_path=snapshot.path, sandbox_image=failed_spec.base_image,
                  source_files=stack.source_files),
        record=record,
    )
    revised = bind(outcome.output)
    if revised in tried:
        return None
    tried.append(revised)
    return revised


async def _run_prepare(ops: Ops, snapshot: RepoSnapshot, stack: StackFingerprint,
                       invocations: list[AgentOutcome], *, component_root: str) -> PrepareOutcome:
    """The preparation itself. ``invocations`` is owned by :func:`run_prepare` so that the
    calls completed before a failure survive it."""
    s = get_settings()
    whole_repository = component_root in ("", ".")
    # How much repository the agents have to explore, which is what their budgets scale on.
    deps = AgentDeps(repo_path=snapshot.path, source_files=stack.source_files)
    component_context = {} if whole_repository else {"component_root": component_root}

    def bind_component(spec: EnvironmentSpec) -> EnvironmentSpec:
        """Confine every plan and repair to the selected component's working directory."""
        if whole_repository:
            return spec
        return spec.model_copy(update={"scope": "partial", "module_path": component_root})

    def prepared(status, *, profile=None, build=None, smoke=None, attempts=0, reason=""):
        return PreparedEnvironment(
            snapshot=snapshot, stack=stack, profile=profile, build=build, smoke=smoke,
            status=status, attempts=attempts, reason=reason,
        )

    # P2 recon
    recon = await ops.run_agent(
        "recon",
        render_prompt("Profile this repository." if whole_repository
                      else "Profile this repository component.", component_context, stack=stack),
        deps, record=invocations)
    profile: RepoProfile = recon.output
    tried: list[EnvironmentSpec] = []

    async def revise(agent: str, instruction: str, failed: BuildResult,
                     evidence: dict) -> EnvironmentSpec | None:
        return await revise_environment(
            ops, agent, instruction, evidence, failed_spec=failed.spec, tried=tried,
            snapshot=snapshot, stack=stack, profile=profile, record=invocations,
            bind=bind_component)

    # P3a a recipe that already built for this shape of repository, if there is one. The
    # expensive parts of a spec -- the surefire warm-up, cpanm's --local-lib and its matching
    # PERL5LIB, -Dmaven.repo.local on both sides of the two-path layout -- are properties of the
    # stack, not the project, so re-deriving them per repo is both slow and a chance to get them
    # wrong. A miss costs nothing; a bad hit costs one build and is then evicted.
    build: BuildResult | None = None
    from_recipe = False
    cached = await ops.lookup_recipe(stack)
    if cached is not None:
        cached = bind_component(cached)
        build = await ops.build_environment(snapshot, cached)
        if build.ok:
            tried.append(cached)
            from_recipe = True
        else:
            # Evict before falling back, so the next repo of this shape does not pay for it too.
            await ops.record_recipe(stack, cached, worked=False)
            build = None

    # P3b env planner, unless the recipe already produced a working image.
    if build is None:
        planned = await ops.run_agent(
            "env-planner",
            render_prompt(
                "Design a container environment that can run one unit test of this repo."
                if whole_repository else
                "Design a container environment that can run one unit test of this repository "
                "component.", component_context, stack=stack, profile=profile),
            deps, record=invocations)
        spec = bind_component(planned.output)
        tried.append(spec)
        build = await ops.build_environment(snapshot, spec)

    # P5 full-build repair, then P5b the partial-build fallback: each revises until a build
    # succeeds, its cap is reached, or it repeats a plan already tried.
    attempts = partial_attempts = 0
    while not build.ok and attempts < s.max_build_repairs:
        attempts += 1
        spec = await revise("build-repair", _BUILD_FAILED, build,
                            {"build_error": build.error_excerpt})
        if spec is None:
            break
        build = await ops.build_environment(snapshot, spec)
    while not build.ok and partial_attempts < s.max_partial_build_attempts:
        partial_attempts += 1
        spec = await revise("partial-build", _PARTIAL_BUILD, build,
                            {"build_error": build.error_excerpt})
        if spec is None:
            break
        build = await ops.build_environment(snapshot, spec)
    if not build.ok:
        return PrepareOutcome(
            prepared(status="unbuildable", profile=profile, build=build,
                     attempts=attempts + partial_attempts, reason="environment_unbuildable"),
            invocations,
        )

    # P6 smoke test. The spec's own test command is passed so the runner it names is verified
    # here, where build repair can still act, rather than at probe time as exit 127.
    smoke = await smoke_test(ops, build, stack)
    readiness_reason = ""
    while not smoke.ok and attempts < s.max_build_repairs:
        attempts += 1
        revised = await revise("build-repair", _READINESS_FAILED, build,
                               {"readiness_error": smoke.output_excerpt})
        if revised is None:
            readiness_reason = "readiness_repair_no_progress"
            break
        build = await ops.build_environment(snapshot, revised)
        if not build.ok:
            readiness_reason = "readiness_repair_build_failed"
            break
        smoke = await smoke_test(ops, build, stack)
    # Recorded only after the smoke test, because a built image whose runner is missing is not
    # a working recipe -- that is the exact failure the smoke test was added to catch. The one
    # case that needs nothing written is a cached spec that worked again: re-recording it would
    # say nothing new. A cached spec that *failed* the smoke test still has to be evicted, so
    # this cannot simply skip everything that came from the cache.
    if not (from_recipe and smoke.ok):
        await ops.record_recipe(stack, build.spec, worked=smoke.ok)
    return PrepareOutcome(
        prepared(status="ready" if smoke.ok else "failed", profile=profile, build=build,
                 smoke=smoke, attempts=attempts + partial_attempts,
                 reason="" if smoke.ok else (readiness_reason or "smoke_test_failed")),
        invocations,
    )


async def smoke_test(ops: Ops, build: BuildResult, stack: StackFingerprint) -> SmokeResult:
    """Smoke-test a built image: the canary needs the language to write and, for a partial
    build, the module to run in."""
    return await ops.smoke_test(build.image_tag, build.spec.test_command,
                                language=stack.top_language,
                                module_path=build.spec.module_path or "")


async def prepare_resolved_component(ops: Ops, finding: Finding,
                                     prepared: PreparedEnvironment) -> PrepareOutcome | None:
    """Rebind a description-only finding when intake discovers a nested component."""
    path = finding.location.file_path if finding.location else None
    component = owning_component(prepared.stack, path)
    current_root = prepared.build.spec.module_path if prepared.build else None
    if component is None:
        return None
    narrowed = component_stack(prepared.stack, component)
    # A planner can choose a partial path while still operating on the whole repository.
    # Module-path equality alone does not establish component-local preparation. Test
    # directories are already relative in a narrowed view, so exclude them from this check.
    same_stack = prepared.stack.model_dump(exclude={"test_dirs"}) == narrowed.model_dump(
        exclude={"test_dirs"})
    if component.root == (current_root or ".") and same_stack:
        return None
    return await run_prepare(ops, prepared.snapshot, narrowed, component_root=component.root)
