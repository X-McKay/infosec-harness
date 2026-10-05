"""Per-agent eval adapters: how one dataset case becomes a scored agent run.

An adapter turns a YAML case into an :class:`AdaptedCase` (task text, payload, deps, predict).
`predict` reduces the agent's typed output to one comparable label, which is scored against the
case's own ``expected`` -- so scoring stays deterministic, and no judge model decides whether an
agent passed.

Two rules shape the labels below:

- Score the decision the graph actually routes on. `context`'s reachability call can
  early-exit a finding; `probe_planner`'s oracle choice determines whether the probe can
  observe anything at all. Scoring prose would measure nothing.
- Ground the expectation in the seeded corpus, whose vulnerable/fixed pairs are verified by
  tests/evals/test_corpus_oracle.py. An expectation is then traceable to code that demonstrably
  is or is not exploitable, rather than to an opinion recorded in a fixture.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import EnvironmentSpec, VerdictFacts
from infosec_harness.evals.messages import MAX_NAME_CHARS
from infosec_harness.repo.detect import detect_stack
from infosec_harness.sandbox.markers import (
    FILE_ORACLE_NAME_PREFIX,
    FILE_ORACLE_PREFIX,
    ORACLE_PREFIX,
    PRECONDITION_PREFIX,
)
from infosec_harness.settings import REPO_ROOT


@dataclass(frozen=True)
class AdaptedCase:
    """One dataset case, ready to run: what the agent is told, and how its answer is read."""

    task: str
    payload: dict
    deps: AgentDeps
    predict: Callable[[Any], str]


Adapter = Callable[[dict], AdaptedCase]


def _repo(case: dict) -> str:
    """Resolve a case's repo to an absolute path under the seeded corpus."""
    path = case.get("repo")
    if not path:
        return "/nonexistent"
    return str((REPO_ROOT / path).resolve())


def _deps(case: dict, **kw: Any) -> AgentDeps:
    repo_path = _repo(case)
    if "source_files" not in kw and case.get("repo"):
        kw["source_files"] = detect_stack(repo_path).source_files
    return AgentDeps(repo_path=repo_path, **kw)


def _with_detected_stack(case: dict) -> dict:
    """Fill in the stack fingerprint from the repo rather than hand-writing it in YAML.

    `StackFingerprint.languages` is a weight map, and transcribing one into a fixture is both
    tedious and a way to drift from what detection actually produces. The graph derives it
    with `detect_stack`; so does the eval.
    """
    payload = dict(case.get("payload") or {})
    if "stack_fingerprint" not in payload:
        payload["stack_fingerprint"] = detect_stack(_repo(case)).model_dump(mode="json")
    return payload


def _build_deps(case: dict) -> AgentDeps:
    """Bind the failed build's image exactly as the production graph does."""
    payload = case.get("payload")
    if not isinstance(payload, dict):
        raise ValueError(f"{case.get('name', '<unnamed>')}: payload must be an object")
    try:
        failed_spec = EnvironmentSpec.model_validate(payload.get("failed_spec"))
    except ValidationError as exc:
        raise ValueError(
            f"{case.get('name', '<unnamed>')}: payload.failed_spec must be a valid EnvironmentSpec"
        ) from exc
    if not failed_spec.base_image.strip():
        raise ValueError(f"{case.get('name', '<unnamed>')}: failed_spec.base_image must not be blank")
    return _deps(case, sandbox_image=failed_spec.base_image)


# --- Reasoning-only agents (no repository access) ---------------------------------------


def verdict_adapter(case: dict) -> AdaptedCase:
    facts = VerdictFacts.model_validate(case.get("facts", {}))
    return AdaptedCase("Decide the three-way exploitability verdict from the evidence.",
                       case["payload"], AgentDeps(repo_path="/nonexistent", facts=facts),
                       lambda o: o.label.value)


def diagnosis_adapter(case: dict) -> AdaptedCase:
    return AdaptedCase("Classify this probe execution.", case["payload"],
                       AgentDeps(repo_path="/nonexistent"), lambda o: o.kind.value)


def intake_adapter(case: dict) -> AdaptedCase:
    """Scored on the weakness class it extracts: that is what routes the CWE skill."""
    return AdaptedCase("Extract the missing finding fields from the report text, with citations.",
                       case["payload"], AgentDeps(repo_path="/nonexistent", report_text=case["payload"]["report"]),
                       lambda o: (o.cwe or "none"))


_FRAMEWORK_LABELS = (
    ("junit5", re.compile(
        r"(?:junit\s*5(?:\.\d+)*(?:\s*\(\s*(?:junit[\s-]+)?jupiter"
        r"(?:\s+5(?:\.\d+)*)?\s*\))?"
        r"|junit[\s-]+jupiter(?:\s+5(?:\.\d+)*)?)", re.IGNORECASE)),
    ("junit4", re.compile(
        r"junit\s*4(?:\.\d+)*(?:\s+4(?:\.\d+)*)?", re.IGNORECASE)),
    ("pytest", re.compile(r"pytest(?:\s+v?\d+(?:\.\d+)*)?", re.IGNORECASE)),
    ("jest", re.compile(r"jest(?:\s+v?\d+(?:\.\d+)*)?", re.IGNORECASE)),
    ("test::more", re.compile(
        r"(?:perl\s+)?test::more(?:\s+v?\d+(?:\.\d+)*)?", re.IGNORECASE)),
)


def _canonical_framework_label(value: str) -> str:
    """Canonicalize one unambiguous framework name; never fish an alias from prose."""
    source = value or ""
    if len(source) > MAX_NAME_CHARS:
        return "unrecognized"
    raw = " ".join(source.split())
    matches = [label for label, pattern in _FRAMEWORK_LABELS if pattern.fullmatch(raw)]
    return matches[0] if len(matches) == 1 else raw.lower()


# --- Repository-reading agents ----------------------------------------------------------


def recon_adapter(case: dict) -> AdaptedCase:
    """Scored on language and test framework: everything downstream builds on those."""
    def predict(profile: Any) -> str:
        framework = _canonical_framework_label(profile.test_framework or "")
        return f"{(profile.primary_language or '').lower()}/{framework}"

    return AdaptedCase("Profile this repository for a triage run.", _with_detected_stack(case),
                       _deps(case), predict)


def _ecosystem_label(spec: Any) -> str:
    """Reduce an EnvironmentSpec to (base-image family, test runner)."""
    image = (spec.base_image or "").lower()
    command = (spec.test_command or "").lower()
    family = next((f for f in ("python", "maven", "eclipse-temurin", "openjdk", "node", "perl")
                   if f in image), "other")
    runner = next((r for r in ("pytest", "mvn", "gradle", "jest", "npm", "prove", "perl")
                   if r in command), "other")
    return f"{family}/{runner}"


def env_planner_adapter(case: dict) -> AdaptedCase:
    return AdaptedCase("Plan a build and test environment for this repository.",
                       _with_detected_stack(case), _deps(case), _ecosystem_label)


def build_repair_adapter(case: dict) -> AdaptedCase:
    """Scored on whether the repair addresses the failure the log reports."""
    if case.get("scorer") == "no_previous_attempt_repeat_v1":
        payload = case["payload"]
        attempted = [payload["failed_spec"], *(payload.get("previous_attempts") or [])]

        def normalize(spec: Any) -> dict[str, Any]:
            value = EnvironmentSpec.model_validate(spec).model_dump(
                mode="json", exclude={"rationale"}
            )
            value["system_packages"] = sorted(value["system_packages"])
            return value

        normalized_attempts = [normalize(spec) for spec in attempted]

        def predict_no_repeat(spec: Any) -> str:
            # This negative case retains its historical labels: "unaddressed" is the
            # expected label for avoiding the repeated failed attempt. Distinctness
            # alone does not establish that the new configuration builds.
            return "addressed" if normalize(spec) in normalized_attempts else "unaddressed"

        return AdaptedCase("Repair this environment spec so the build succeeds.", case["payload"],
                           _build_deps(case), predict_no_repeat)

    def predict(spec: Any) -> str:
        packages = " ".join(spec.system_packages or []).lower()
        installs = " ".join(spec.install_commands or []).lower()
        needle = case["expect_mentions"].lower()
        return "addressed" if needle in packages or needle in installs else "unaddressed"

    return AdaptedCase("Repair this environment spec so the build succeeds.", case["payload"],
                       _build_deps(case), predict)


def partial_build_adapter(case: dict) -> AdaptedCase:
    """Scored on whether it narrows scope rather than retrying the whole build."""
    return AdaptedCase("Narrow the build to the module the finding needs.", case["payload"],
                       _build_deps(case), lambda spec: (spec.scope or "full"))


def context_adapter(case: dict) -> AdaptedCase:
    """Scored on reachability — the call that can early-exit a finding entirely.

    The paired corpus makes this a real question rather than a guess: the fixed variants are
    neutralized by constructs the cwe-* skills name verbatim, and tests/evals/test_corpus_oracle.py
    proves the vulnerable ones are exploitable and the fixed ones are not.
    """
    return AdaptedCase("Collect the code evidence for this finding.", case["payload"], _deps(case),
                       lambda ctx: ctx.reachability.value)


def probe_planner_adapter(case: dict) -> AdaptedCase:
    """Scored on the oracle kind: a side effect needs a canary, a value needs a marker."""
    return AdaptedCase("Plan a probe that decides whether this finding is exploitable.", case["payload"],
                       _deps(case), lambda plan: plan.oracle.value)


def _probe_conformance(case: dict) -> Callable[[Any], str]:
    """Does the probe follow the marker protocol and exercise the named callable?

    Deterministic and structural on purpose: whether the probe *would* fire its oracle is a
    question for the sandbox, but a probe that never prints the precondition marker, or never
    calls the target, cannot answer anything regardless of how it runs.
    """
    callable_name = case.get("target_callable", "")

    def predict(probe: Any) -> str:
        content = probe.content or ""
        if PRECONDITION_PREFIX not in content:
            return "no_precondition_marker"
        if not any(m in content for m in (ORACLE_PREFIX, FILE_ORACLE_PREFIX,
                                          FILE_ORACLE_NAME_PREFIX)):
            return "no_oracle_signal"
        if callable_name and callable_name not in content:
            return "target_not_called"
        return "conformant"

    return predict


def probe_author_adapter(case: dict) -> AdaptedCase:
    return AdaptedCase("Write the probe for this plan.", case["payload"], _deps(case),
                       _probe_conformance(case))


def probe_repair_adapter(case: dict) -> AdaptedCase:
    return AdaptedCase("Fix this probe so it runs honestly and still checks the same exploit condition. "
                       "Keep the markers and the same oracle_nonce.", case["payload"], _deps(case),
                       _probe_conformance(case))


ADAPTERS: dict[str, Adapter] = {
    "intake": intake_adapter,
    "recon": recon_adapter,
    "env-planner": env_planner_adapter,
    "build-repair": build_repair_adapter,
    "partial-build": partial_build_adapter,
    "context": context_adapter,
    "probe-planner": probe_planner_adapter,
    "probe-author": probe_author_adapter,
    "probe-repair": probe_repair_adapter,
    "probe-diagnosis": diagnosis_adapter,
    "verdict": verdict_adapter,
}


# --- The unevidenced-safety predicate ---------------------------------------------------
#
# The costliest error this system can make is to call something safe on evidence that does
# not support it (RISK-SEC-003). For three agents that has a crisp, deterministic shape, so it
# is counted for them, and their release policies gate on it (`unevidenced_safe_verdicts`).
# Whether it is a gate is the policy's decision (evals/gates.py); which agents it is *defined*
# for is a property of their outputs, and lives here. It is deliberately not defined for the
# probe-writing agents: a probe with no oracle signal is already a failed case, not a safety
# claim.


def _complete_negative(evidence: dict) -> bool:
    """A valid negative needs the sink reached and returned with the oracle silent.

    The precondition marker is emitted before the call, so it cannot distinguish a clean
    negative from a sink that threw before the return marker.
    """
    return (evidence.get("precondition_reached") is True
            and evidence.get("sink_returned") is True
            and evidence.get("oracle_fired") is False)


def _verdict_unevidenced(case: dict, predicted: str) -> bool:
    # The deterministic validator should already make this impossible; counting it proves the
    # contract held rather than assuming it.
    facts = case.get("facts") or {}
    supported = facts.get("last_diagnosis") == "valid_negative" and _complete_negative(facts)
    return predicted == "likely_not_exploitable" and not supported


def _diagnosis_unevidenced(case: dict, predicted: str) -> bool:
    execution = (case.get("payload") or {}).get("probe_execution") or {}
    return predicted == "valid_negative" and not _complete_negative(execution)


def _context_unevidenced(case: dict, predicted: str) -> bool:
    # Calling a sink unreachable early-exits the finding, so doing it on a variant that is in
    # fact exploitable suppresses a real vulnerability.
    return predicted == "unreachable" and case.get("expected") == "reachable"


_UNEVIDENCED_SAFE: dict[str, Callable[[dict, str], bool]] = {
    "context": _context_unevidenced,
    "probe-diagnosis": _diagnosis_unevidenced,
    "verdict": _verdict_unevidenced,
}


def defines_unevidenced_safety(agent: str) -> bool:
    return agent in _UNEVIDENCED_SAFE


def is_unevidenced_safe(agent: str, case: dict, predicted: str) -> bool:
    """Did the agent assert safety on evidence that cannot support it?"""
    predicate = _UNEVIDENCED_SAFE.get(agent)
    return predicate is not None and predicate(case, predicted)
