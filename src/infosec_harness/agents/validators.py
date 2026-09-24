"""Output validators: deterministic contracts an agent's output must satisfy (§5.3).

A violated contract raises ``ModelRetry`` with the reason, so the model gets a chance to
correct itself within its ``retries.output`` budget.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic_ai import ModelRetry, RunContext

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import (
    DiagnosisKind,
    InconclusiveReason,
    ProbeSource,
    Reachability,
    Verdict,
    VerdictFacts,
    VerdictLabel,
)


def verdict_violations(verdict: Verdict, facts: VerdictFacts) -> list[str]:
    """Pure function so evals and tests can check the contract without a model."""
    problems: list[str] = []
    if verdict.label == VerdictLabel.potentially_exploitable:
        if not facts.oracle_fired:
            problems.append("potentially_exploitable requires the oracle to have fired; it did not.")
        if facts.last_diagnosis not in (None, DiagnosisKind.valid_positive):
            problems.append(f"potentially_exploitable requires a valid positive execution, "
                            f"but the diagnosis was {facts.last_diagnosis}.")
    elif verdict.label == VerdictLabel.likely_not_exploitable:
        valid_negative = (facts.last_diagnosis == DiagnosisKind.valid_negative
                          and facts.precondition_reached and not facts.oracle_fired)
        unreachable = facts.reachability == Reachability.unreachable and bool(verdict.evidence)
        if not (valid_negative or unreachable):
            problems.append("likely_not_exploitable requires either a valid negative execution that "
                            "reached the precondition checkpoint, or an unreachable sink with cited evidence.")
    else:
        if verdict.inconclusive_reason is None:
            problems.append("inconclusive verdicts must set inconclusive_reason.")
    if not facts.environment_ready and verdict.label != VerdictLabel.inconclusive and not (
        verdict.label == VerdictLabel.likely_not_exploitable and facts.reachability == Reachability.unreachable
    ):
        problems.append("The environment could not be built; only inconclusive (or an evidenced "
                        "unreachable finding) is allowed.")
    if not facts.environment_ready and verdict.label == VerdictLabel.inconclusive and (
        verdict.inconclusive_reason not in (InconclusiveReason.environment_unbuildable, None)
    ):
        problems.append("With no environment the inconclusive_reason must be environment_unbuildable.")
    return problems


def validate_verdict(ctx: RunContext[AgentDeps], output: Verdict) -> Verdict:
    facts = ctx.deps.facts
    if facts is None:
        return output
    problems = verdict_violations(output, facts)
    if problems:
        raise ModelRetry("Verdict violates the evidence contract:\n- " + "\n- ".join(problems))
    return output


def validate_probe(ctx: RunContext[AgentDeps], output: ProbeSource) -> ProbeSource:
    if ".." in output.test_file_path.split("/") or output.test_file_path.startswith("/"):
        raise ModelRetry("test_file_path must be a repo-relative path without '..'.")
    if "HARNESS_" not in output.content:
        raise ModelRetry("The probe must print the precondition marker and the oracle marker "
                         "(see the probe-oracle-protocol skill).")
    return output


OUTPUT_VALIDATORS: dict[str, tuple[Callable[[RunContext[AgentDeps], Any], Any], ...]] = {
    "verdict": (validate_verdict,),
    "probe_author": (validate_probe,),
    "probe_repair": (validate_probe,),
}
