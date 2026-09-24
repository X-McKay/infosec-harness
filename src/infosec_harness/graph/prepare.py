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
    PreparedEnvironment,
    RepoProfile,
    RepoSnapshot,
    StackFingerprint,
)
from infosec_harness.graph.ops import AgentOutcome, Ops
from infosec_harness.settings import get_settings


@dataclass
class PrepareOutcome:
    prepared: PreparedEnvironment
    invocations: list[AgentOutcome] = field(default_factory=list)


async def run_prepare(ops: Ops, snapshot: RepoSnapshot, stack: StackFingerprint) -> PrepareOutcome:
    s = get_settings()
    invocations: list[AgentOutcome] = []
    deps = AgentDeps(repo_path=snapshot.path)

    def prepared(status, *, profile=None, build=None, smoke=None, attempts=0, reason=""):
        return PreparedEnvironment(
            snapshot=snapshot, stack=stack, profile=profile, build=build, smoke=smoke,
            status=status, attempts=attempts, reason=reason,
        )

    # P2 recon
    recon = await ops.run_agent(
        "recon", render_prompt("Profile this repository.", {}, stack=stack), deps
    )
    invocations.append(recon)
    profile: RepoProfile = recon.output

    # P3 env planner
    planned = await ops.run_agent(
        "env_planner",
        render_prompt("Design a container environment that can run one unit test of this repo.",
                      {}, stack=stack, profile=profile),
        deps,
    )
    invocations.append(planned)
    spec: EnvironmentSpec = planned.output

    attempts = 0
    build: BuildResult = await ops.build_environment(snapshot, spec)

    # P5 full-build repair loop
    tried_specs = [spec]
    while not build.ok and attempts < s.max_build_repairs:
        attempts += 1
        repair = await ops.run_agent(
            "build_repair",
            render_prompt(
                "The build failed; diagnose the log and return a revised EnvironmentSpec.",
                {"failed_spec": build.spec, "build_error": build.error_excerpt,
                 "previous_attempts": [t.model_dump() for t in tried_specs]},
                stack=stack, profile=profile,
            ),
            AgentDeps(repo_path=snapshot.path, sandbox_image=build.spec.base_image),
        )
        invocations.append(repair)
        spec = repair.output
        tried_specs.append(spec)
        build = await ops.build_environment(snapshot, spec)

    # P5b partial-build fallback
    partial_attempts = 0
    while not build.ok and partial_attempts < s.max_partial_build_attempts:
        partial_attempts += 1
        partial = await ops.run_agent(
            "partial_build",
            render_prompt(
                "The full build failed; plan the smallest buildable unit containing the code and "
                "return a partial EnvironmentSpec.",
                {"failed_spec": build.spec, "build_error": build.error_excerpt,
                 "previous_attempts": [t.model_dump() for t in tried_specs]},
                stack=stack, profile=profile,
            ),
            AgentDeps(repo_path=snapshot.path, sandbox_image=build.spec.base_image),
        )
        invocations.append(partial)
        spec = partial.output
        tried_specs.append(spec)
        build = await ops.build_environment(snapshot, spec)

    total_attempts = attempts + partial_attempts
    if not build.ok:
        return PrepareOutcome(
            prepared(status="unbuildable", profile=profile, build=build, attempts=total_attempts,
                     reason="environment_unbuildable"),
            invocations,
        )

    # P6 smoke test
    smoke = await ops.smoke_test(build.image_tag)
    status = "ready" if smoke.ok else "failed"
    return PrepareOutcome(
        prepared(status=status, profile=profile, build=build, smoke=smoke, attempts=total_attempts,
                 reason="" if smoke.ok else "smoke_test_failed"),
        invocations,
    )
