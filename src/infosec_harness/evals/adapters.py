"""Per-agent eval adapters: how one dataset case becomes a scored agent run.

An adapter turns a YAML case into (task_text, payload, deps, predict, expected). `predict`
reduces the agent's typed output to one comparable label, so scoring stays deterministic —
no judge model decides whether an agent passed.

Two rules shape the labels below:

- Score the decision the graph actually routes on. `context`'s reachability call can
  early-exit a finding; `probe_planner`'s oracle choice determines whether the probe can
  observe anything at all. Scoring prose would measure nothing.
- Ground the expectation in the seeded corpus, whose vulnerable/fixed pairs are verified by
  tests/test_corpus_oracle.py. An expectation is then traceable to code that demonstrably
  is or is not exploitable, rather than to an opinion recorded in a fixture.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from infosec_harness.agents.deps import AgentDeps
from infosec_harness.domain.models import VerdictFacts
from infosec_harness.sandbox.docker import CANARY_PREFIX, ORACLE_PREFIX, PRECONDITION_PREFIX
from infosec_harness.settings import REPO_ROOT

Adapter = Callable[[dict], tuple[str, dict, AgentDeps, Callable[[Any], str], str]]


def _repo(case: dict) -> str:
    """Resolve a case's repo to an absolute path under the seeded corpus."""
    path = case.get("repo")
    if not path:
        return "/nonexistent"
    return str((REPO_ROOT / path).resolve())


def _deps(case: dict, **kw: Any) -> AgentDeps:
    return AgentDeps(repo_path=_repo(case), **kw)


def _with_detected_stack(case: dict) -> dict:
    """Fill in the stack fingerprint from the repo rather than hand-writing it in YAML.

    `StackFingerprint.languages` is a weight map, and transcribing one into a fixture is both
    tedious and a way to drift from what detection actually produces. The graph derives it
    with `detect_stack`; so does the eval.
    """
    from infosec_harness.repo.detect import detect_stack

    payload = dict(case.get("payload") or {})
    if "stack_fingerprint" not in payload:
        payload["stack_fingerprint"] = detect_stack(_repo(case)).model_dump(mode="json")
    return payload


# --- Reasoning-only agents (no repository access) ---------------------------------------


def verdict_adapter(case: dict):
    facts = VerdictFacts.model_validate(case.get("facts", {}))
    return ("Decide the three-way exploitability verdict from the evidence.",
            case["payload"], AgentDeps(repo_path="/nonexistent", facts=facts),
            lambda o: o.label.value, case["expected"])


def diagnosis_adapter(case: dict):
    return ("Classify this probe execution.", case["payload"],
            AgentDeps(repo_path="/nonexistent"), lambda o: o.kind.value, case["expected"])


def intake_adapter(case: dict):
    """Scored on the weakness class it extracts: that is what routes the CWE skill."""
    return ("Extract the missing finding fields from the report text, with citations.",
            case["payload"], AgentDeps(repo_path="/nonexistent"),
            lambda o: (o.cwe or "none"), case["expected"])


# --- Repository-reading agents ----------------------------------------------------------


def recon_adapter(case: dict):
    """Scored on language and test framework: everything downstream builds on those."""
    def predict(profile: Any) -> str:
        return f"{(profile.primary_language or '').lower()}/{(profile.test_framework or '').lower()}"

    return ("Profile this repository for a triage run.", _with_detected_stack(case),
            _deps(case), predict, case["expected"])


def _ecosystem_label(spec: Any) -> str:
    """Reduce an EnvironmentSpec to (base-image family, test runner)."""
    image = (spec.base_image or "").lower()
    command = (spec.test_command or "").lower()
    family = next((f for f in ("python", "maven", "eclipse-temurin", "openjdk", "node", "perl")
                   if f in image), "other")
    runner = next((r for r in ("pytest", "mvn", "gradle", "jest", "npm", "prove", "perl")
                   if r in command), "other")
    return f"{family}/{runner}"


def env_planner_adapter(case: dict):
    return ("Plan a build and test environment for this repository.",
            _with_detected_stack(case), _deps(case), _ecosystem_label, case["expected"])


def build_repair_adapter(case: dict):
    """Scored on whether the repair addresses the failure the log reports."""
    def predict(spec: Any) -> str:
        packages = " ".join(spec.system_packages or []).lower()
        installs = " ".join(spec.install_commands or []).lower()
        needle = case["expect_mentions"].lower()
        return "addressed" if needle in packages or needle in installs else "unaddressed"

    return ("Repair this environment spec so the build succeeds.", case["payload"],
            _deps(case), predict, case["expected"])


def partial_build_adapter(case: dict):
    """Scored on whether it narrows scope rather than retrying the whole build."""
    return ("Narrow the build to the module the finding needs.", case["payload"],
            _deps(case), lambda spec: (spec.scope or "full"), case["expected"])


def context_adapter(case: dict):
    """Scored on reachability — the call that can early-exit a finding entirely.

    The paired corpus makes this a real question rather than a guess: the fixed variants are
    neutralized by constructs the cwe-* skills name verbatim, and tests/test_corpus_oracle.py
    proves the vulnerable ones are exploitable and the fixed ones are not.
    """
    return ("Collect the code evidence for this finding.", case["payload"], _deps(case),
            lambda ctx: ctx.reachability.value, case["expected"])


def probe_planner_adapter(case: dict):
    """Scored on the oracle kind: a side effect needs a canary, a value needs a marker."""
    return ("Plan a probe that decides whether this finding is exploitable.", case["payload"],
            _deps(case), lambda plan: plan.oracle.value, case["expected"])


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
        if ORACLE_PREFIX not in content and CANARY_PREFIX not in content \
                and "harness_canary_" not in content:
            return "no_oracle_signal"
        if callable_name and callable_name not in content:
            return "target_not_called"
        return "conformant"

    return predict


def probe_author_adapter(case: dict):
    return ("Write the probe for this plan.", case["payload"], _deps(case),
            _probe_conformance(case), case["expected"])


def probe_repair_adapter(case: dict):
    return ("Fix this probe so it runs honestly and still checks the same exploit condition. "
            "Keep the markers and the same oracle_nonce.", case["payload"], _deps(case),
            _probe_conformance(case), case["expected"])


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


# --- The unevidenced-safety gate --------------------------------------------------------
#
# The costliest error this system can make is to call something safe on evidence that does
# not support it (RISK-SEC-003). For three agents that has a crisp, deterministic shape, so
# it is a hard gate rather than a quality metric. It is deliberately not defined for the
# probe-writing agents: a probe with no oracle signal is already a failed case, not a
# safety claim.
UNEVIDENCED_SAFETY_AGENTS = ("context", "probe-diagnosis", "verdict")


def is_unevidenced_safe(agent: str, case: dict, predicted: str) -> bool:
    """Did the agent assert safety on evidence that cannot support it?"""
    payload = case.get("payload") or {}
    if agent == "verdict":
        # The deterministic validator should already make this impossible; counting it proves
        # the contract held rather than assuming it.
        facts = case.get("facts") or {}
        # `unreachable` supports a safe verdict on its own: nothing arrives, so there is
        # nothing to probe. `neutralized` deliberately does NOT, and must not be added here --
        # it says input arrives and a control stops it, which is a claim about behaviour that
        # only a probe can support. Letting it through would restore the exact gap this value
        # was introduced to close.
        supported = (facts.get("last_diagnosis") == "valid_negative"
                     and facts.get("precondition_reached")
                     and not facts.get("oracle_fired")) or facts.get("reachability") == "unreachable"
        return predicted == "likely_not_exploitable" and not supported
    if agent == "probe-diagnosis":
        # "The code resisted the payload" is only sayable if the payload reached the sink.
        execution = payload.get("probe_execution") or {}
        return predicted == "valid_negative" and not execution.get("precondition_reached")
    if agent == "context":
        # Calling a sink unreachable early-exits the finding, so doing it on a variant that is
        # in fact exploitable suppresses a real vulnerability.
        return predicted == "unreachable" and case.get("expected") == "reachable"
    return False
