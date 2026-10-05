"""Repository preparation (P2-P6): profile, plan, build with a bounded repair loop, then a
partial-build fallback, then a smoke test. Runs once per repo@revision and is cached.

Expressed as an orchestrator over the same Ops interface as the triage graph, so it runs
standalone or durably. The build-repair and partial-build loops are aggressive within hard
caps (D6).
"""

from __future__ import annotations

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


async def _run_prepare(ops: Ops, snapshot: RepoSnapshot, stack: StackFingerprint,
                       invocations: list[AgentOutcome], *, component_root: str) -> PrepareOutcome:
    """The preparation itself. ``invocations`` is owned by :func:`run_prepare` so that the
    calls completed before a failure survive it."""
    s = get_settings()
    # How much repository the agents have to explore, which is what their budgets scale on.
    source_files = stack.source_files
    deps = AgentDeps(repo_path=snapshot.path, source_files=source_files)
    component_context = ({"component_root": component_root}
                         if component_root not in ("", ".") else {})

    def bind_component(spec: EnvironmentSpec) -> EnvironmentSpec:
        """Confine every plan and repair to the selected component's working directory."""
        if component_root in ("", "."):
            return spec
        return spec.model_copy(update={"scope": "partial", "module_path": component_root})

    def prepared(status, *, profile=None, build=None, smoke=None, attempts=0, reason=""):
        return PreparedEnvironment(
            snapshot=snapshot, stack=stack, profile=profile, build=build, smoke=smoke,
            status=status, attempts=attempts, reason=reason,
        )

    # P2 recon
    recon_instruction = ("Profile this repository." if component_root in ("", ".")
                         else "Profile this repository component.")
    recon = await ops.run_agent(
        "recon", render_prompt(recon_instruction, component_context, stack=stack), deps
    )
    invocations.append(recon)
    profile: RepoProfile = recon.output

    # P3a a recipe that already built for this shape of repository, if there is one. The
    # expensive parts of a spec -- the surefire warm-up, cpanm's --local-lib and its matching
    # PERL5LIB, -Dmaven.repo.local on both sides of the two-path layout -- are properties of the
    # stack, not the project, so re-deriving them per repo is both slow and a chance to get them
    # wrong. A miss costs nothing; a bad hit costs one build and is then evicted.
    spec: EnvironmentSpec | None = None
    build: BuildResult | None = None
    from_recipe = False
    cached = await ops.lookup_recipe(stack)
    if cached is not None:
        cached = bind_component(cached)
        build = await ops.build_environment(snapshot, cached)
        if build.ok:
            spec, from_recipe = cached, True
        else:
            # Evict before falling back, so the next repo of this shape does not pay for it too.
            await ops.record_recipe(stack, cached, worked=False)
            build = None

    # P3b env planner, unless the recipe already produced a working image.
    if spec is None:
        planner_instruction = (
            "Design a container environment that can run one unit test of this repo."
            if component_root in ("", ".") else
            "Design a container environment that can run one unit test of this repository component."
        )
        planned = await ops.run_agent(
            "env-planner",
            render_prompt(planner_instruction, component_context, stack=stack, profile=profile),
            deps,
        )
        invocations.append(planned)
        spec = bind_component(planned.output)

    attempts = 0
    if build is None:
        build = await ops.build_environment(snapshot, spec)

    # P5 full-build repair loop
    tried_specs = [spec]
    while not build.ok and attempts < s.max_build_repairs:
        attempts += 1
        repair = await ops.run_agent(
            "build-repair",
            render_prompt(
                "The build failed; diagnose the log and return a revised EnvironmentSpec.",
                {"failed_spec": build.spec, "build_error": build.error_excerpt,
                 "previous_attempts": [t.model_dump() for t in tried_specs]},
                stack=stack, profile=profile,
            ),
            AgentDeps(repo_path=snapshot.path, sandbox_image=build.spec.base_image,
                      source_files=source_files),
        )
        invocations.append(repair)
        spec = bind_component(repair.output)
        if spec in tried_specs:
            # Rebuilding an equivalent plan cannot change the result and only spends the shared
            # preparation budget. Fall through to the distinct partial-build strategy.
            break
        tried_specs.append(spec)
        build = await ops.build_environment(snapshot, spec)

    # P5b partial-build fallback
    partial_attempts = 0
    while not build.ok and partial_attempts < s.max_partial_build_attempts:
        partial_attempts += 1
        partial = await ops.run_agent(
            "partial-build",
            render_prompt(
                "The full build failed; plan the smallest buildable unit containing the code and "
                "return a partial EnvironmentSpec.",
                {"failed_spec": build.spec, "build_error": build.error_excerpt,
                 "previous_attempts": [t.model_dump() for t in tried_specs]},
                stack=stack, profile=profile,
            ),
            AgentDeps(repo_path=snapshot.path, sandbox_image=build.spec.base_image,
                      source_files=source_files),
        )
        invocations.append(partial)
        spec = bind_component(partial.output)
        if spec in tried_specs:
            break
        tried_specs.append(spec)
        build = await ops.build_environment(snapshot, spec)

    total_attempts = attempts + partial_attempts
    if not build.ok:
        return PrepareOutcome(
            prepared(status="unbuildable", profile=profile, build=build, attempts=total_attempts,
                     reason="environment_unbuildable"),
            invocations,
        )

    # P6 smoke test. The spec's own test command is passed so the runner it names is verified
    # here, where build repair can still act, rather than at probe time as exit 127.
    # The canary inside the smoke test needs to know which language to write, and which
    # module to run in for a partial build.
    top_language = stack.top_language
    smoke = await ops.smoke_test(build.image_tag, build.spec.test_command,
                                 language=top_language,
                                 module_path=build.spec.module_path or "")
    readiness_reason = ""
    while not smoke.ok and attempts < s.max_build_repairs:
        attempts += 1
        repair = await ops.run_agent(
            "build-repair",
            render_prompt(
                "The image built, but its offline readiness check failed. Repair the environment "
                "or test-runner setup and return a revised EnvironmentSpec.",
                {"failed_spec": build.spec, "readiness_error": smoke.output_excerpt,
                 "previous_attempts": [t.model_dump() for t in tried_specs]},
                stack=stack, profile=profile,
            ),
            AgentDeps(repo_path=snapshot.path, sandbox_image=build.spec.base_image,
                      source_files=source_files),
        )
        invocations.append(repair)
        revised = bind_component(repair.output)
        if revised in tried_specs:
            readiness_reason = "readiness_repair_no_progress"
            break
        tried_specs.append(revised)
        build = await ops.build_environment(snapshot, revised)
        if not build.ok:
            readiness_reason = "readiness_repair_build_failed"
            break
        smoke = await ops.smoke_test(build.image_tag, build.spec.test_command,
                                     language=top_language,
                                     module_path=build.spec.module_path or "")
    total_attempts = attempts + partial_attempts
    status = "ready" if smoke.ok else "failed"
    # Recorded only after the smoke test, because a built image whose runner is missing is not
    # a working recipe -- that is the exact failure the smoke test was added to catch. The one
    # case that needs nothing written is a cached spec that worked again: re-recording it would
    # say nothing new. A cached spec that *failed* the smoke test still has to be evicted, so
    # this cannot simply skip everything that came from the cache.
    if not (from_recipe and smoke.ok):
        await ops.record_recipe(stack, build.spec, worked=smoke.ok)
    return PrepareOutcome(
        prepared(status=status, profile=profile, build=build, smoke=smoke, attempts=total_attempts,
                 reason="" if smoke.ok else (readiness_reason or "smoke_test_failed")),
        invocations,
    )


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
