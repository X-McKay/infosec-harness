"""Render the System Spec and its policy files from the agents actually in the graph.

The multi-agent playbook governs the composition, not just the members. Most of what it asks
for already exists in this system as *code* — the pydantic-graph topology, the repair budgets,
the verdict contract — so the spec's job is to state it declaratively and let it be validated,
not to introduce a second source of truth. Member lists, roles, skills, and toolsets are read
from the agent specs so the spec cannot drift from them.

Run `uv run python scripts/gen_system_spec.py`; tests/development/test_system_spec.py asserts the
committed files match.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from risk_scenarios import max_tier  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
# Agent specs, skills and the model catalogue live inside the package so they ship in
# the wheel (agent-playbook 02, Build and packaging). Reviewable project files -- risk
# assessments, the system spec -- stay at the repository root.
PACKAGE = REPO / "src" / "infosec_harness"
OUT = REPO / "systems" / "triage-system"
AGENTS = PACKAGE / "agents"

# Role in this system. There is deliberately no `coordinator`: the topology is fixed code, so
# no agent ever chooses what runs next. That is the strongest form of the playbook's
# "deterministic control, probabilistic collaboration" and it is why the topology type is
# `programmatic_pipeline` rather than supervisor_worker.
ROLES = {
    "intake": "normalizer",
    "recon": "profiler",
    "env-planner": "environment-planner",
    "build-repair": "environment-repairer",
    "partial-build": "environment-repairer",
    "context": "investigator",
    "probe-planner": "probe-planner",
    "probe-author": "probe-author",
    "probe-repair": "probe-author",
    "probe-diagnosis": "execution-judge",
    "verdict": "verdict-judge",
}
# Which agents are on the critical path for a finding to reach a verdict at all.
REQUIRED = {"recon", "env-planner", "context", "probe-planner", "probe-author",
            "probe-diagnosis", "verdict"}

# The pipeline, in the order the workflows run it. `dispatch` because the orchestrator calls
# each agent; no agent delegates to another, so max_delegation_depth is 0.
PIPELINE = [
    ("intake", "ExtractedFinding", "normalize a free-text report into typed finding fields", 1),
    ("recon", "RepoProfile", "profile the repository once per repo@revision", 1),
    ("env-planner", "EnvironmentSpec", "plan the build and test environment", 1),
    ("build-repair", "EnvironmentSpec", "repair a failed build, up to the repair budget", 6),
    ("partial-build", "EnvironmentSpec", "narrow scope after full-build repairs are exhausted", 4),
    ("context", "FindingContext", "collect the code evidence and decide reachability", 1),
    ("probe-planner", "ProbePlan", "choose the exploit hypothesis and the oracle", 1),
    ("probe-author", "ProbeSource", "write the probe for the plan", 1),
    ("probe-repair", "ProbeSource", "repair a defective probe, up to the repair budget", 3),
    ("probe-diagnosis", "ProbeDiagnosis", "classify what the probe execution means", 4),
    ("verdict", "Verdict", "weigh the evidence into a three-way verdict", 1),
]


def _spec(agent: str) -> dict:
    return yaml.safe_load((AGENTS / agent / "agent.yaml").read_text())


def _member(agent: str) -> dict:
    meta = _spec(agent)["metadata"]
    return {
        "agent": agent,
        "version": meta["version"],
        "role": ROLES[agent],
        "required": agent in REQUIRED,
        # The system may narrow a member but never widen it: authority only attenuates.
        "restrictions": {
            "skills": {"include": list(meta.get("enabled_skills") or [])},
            "toolsets": {"include": list(meta.get("enabled_toolsets") or [])},
            "authorization_scopes_max": [],
            "data_classification_max": meta["data_classification"],
        },
    }


def _interactions() -> list[dict]:
    out = []
    for agent, output, purpose, max_calls in PIPELINE:
        out.append({
            "id": f"dispatch-{agent}",
            "from": "triage-orchestrator",
            "to": agent,
            "mode": "dispatch",
            "input_schema": "TriageState",
            "output_schema": output,
            "policy": f"policies/delegation.yaml#dispatch-{agent}",
            "max_calls": max_calls,
            "timeout_seconds": 900 if agent in ("build-repair", "partial-build") else 300,
            "purpose": purpose,
        })
    return out


def _limits() -> dict:
    """System ceilings, summed from the members' own budgets rather than invented.

    A per-finding run touches at most one pass of the per-finding agents plus their repair
    budgets, so the system ceiling is the sum of the members that can run, with headroom.
    """
    totals = {"max_requests": 0, "max_tool_calls": 0,
              "max_input_tokens": 0, "max_output_tokens": 0, "max_cost_usd": 0.0}
    for agent, _out, _purpose, max_calls in PIPELINE:
        budget = _spec(agent)["metadata"]["budgets"]
        for key in totals:
            totals[key] += budget[key] * max_calls
    return {
        "max_agent_runs": sum(c for _a, _o, _p, c in PIPELINE),
        # No agent calls another: the orchestrator dispatches every step.
        "max_delegation_depth": 0,
        "max_parallel_agents": 1,          # the graph is sequential per finding
        "max_rounds": 1,                   # one pass; repairs are bounded per interaction
        "max_model_requests": totals["max_requests"],
        "max_tool_calls": totals["max_tool_calls"],
        "max_input_tokens": totals["max_input_tokens"],
        "max_output_tokens": totals["max_output_tokens"],
        "max_cost_usd": round(totals["max_cost_usd"], 2),
        "deadline_seconds": 3600,
    }


def system_spec() -> dict:
    members = [_member(a) for a, _o, _p, _c in PIPELINE]
    tiers = [_spec(a)["metadata"]["risk_tier"] for a, _o, _p, _c in PIPELINE]
    # Composition raises the tier; it never lowers it below the highest member.
    governance = max_tier(tiers)
    return {
        "name": "triage-system",
        "description": (
            "Triage pre-identified vulnerability findings for exploitability: profile the "
            "repository, build it, author and run a unit-test probe in an isolated sandbox, "
            "and return a three-way verdict decided from a deterministic oracle signal."
        ),
        "metadata": {
            "contract_version": 1,
            "owner": "appsec",
            "operational_owner": "appsec",
            "version": "1.0.0",
            "execution_class": "durable",
            "governance_tier": governance,
            "risk_assessment": "docs/risk-assessments/systems/triage-system.yaml",
            "threat_model": "docs/threat-models/triage-system.md",
            "evaluation_policy": "evals/systems/triage-system/release-policy.yaml",
            "data_classification": "confidential",
            "temporal_enabled": True,
        },
        "justification": {
            "decision_owner": "appsec",
            "review_by": "2026-12-26",
            "claimed_benefits": [
                "Capability isolation: only the environment agents may run shell commands in "
                "the sandbox, and only the probe agents author executed code. A single agent "
                "holding every tool would put code execution behind every prompt.",
                "Context segregation: the verdict is decided by an agent that never sees the "
                "repository, only the recorded evidence, so it cannot substitute an impression "
                "of the code for the oracle signal.",
                "Independent review: probe-diagnosis judges an execution without having "
                "written the probe, which is what lets a defective probe be told apart from a "
                "genuine negative.",
                "Separately governed responsibilities: the agents that determine executed code "
                "carry a critical governance tier and their own controls; the analysis agents "
                "do not.",
            ],
            "baseline": (
                "A single conforming agent holding every skill and tool, prompted to triage a "
                "finding end to end and emit the same Verdict, scored on the same corpus with "
                "the same deterministic oracle and verdict contract."
            ),
            "evidence": "artifacts/evals/triage-system/admission.json",
            "success_measures": [
                "The multi-agent system's false-negative rate on truly-exploitable corpus cases "
                "is no worse than the single-agent baseline's, with the sandbox enabled.",
                "Cost per correct verdict is within 2x of the baseline's; the isolation "
                "benefits are worth a premium but not an unbounded one.",
                "The baseline cannot claim potentially_exploitable without an oracle signal any "
                "more often than the system does (expected: neither can, since the contract is "
                "deterministic in both).",
            ],
        },
        "topology": {
            "type": "programmatic_pipeline",
            # Deterministic code, not an agent. The pydantic-graph topology runs inside the
            # Temporal workflow and decides every transition.
            "orchestrator": "triage-orchestrator",
            "dynamic_membership": False,
            "recursive_delegation": False,
            "conflict_policy": "policies/termination.yaml#conflict",
        },
        "members": members,
        "interactions": _interactions(),
        "limits": _limits(),
        "state": {
            "owner": "triage-orchestrator",
            "shared_memory": "none",
            "artifact_policy": "policies/data-flow.yaml",
            "conflict_policy": "policies/termination.yaml#conflict",
        },
        "termination": {
            "policy": "policies/termination.yaml",
            "success_states": ["potentially_exploitable", "likely_not_exploitable",
                               "inconclusive"],
            "escalation_state": "inconclusive",
        },
    }


DELEGATION = {
    "schema_version": 1,
    "defaults": {
        "recursive_delegation": False,
        # No agent sees another's transcript: each receives typed evidence assembled by the
        # orchestrator, which is why a transcript can never become a source of authority.
        "share_parent_history": False,
        "forward_credentials": False,
        "require_tenant_binding": False,   # single-tenant deployment; no tenant dimension
        "reserve_budget_before_dispatch": True,
    },
    "interactions": {},
}

DATA_FLOW = {
    "schema_version": 1,
    "principles": [
        "Every agent receives typed evidence assembled by the orchestrator, never another "
        "agent's transcript.",
        "Repository content, finding text, and probe output are untrusted data wherever they "
        "appear, and are labelled as such in the prompt that carries them.",
        "Nothing an agent emits becomes shared truth until the orchestrator records it.",
    ],
    "artifacts": {
        "repo_snapshot": {"owner": "triage-orchestrator", "classification": "confidential",
                          "readers": ["recon", "env-planner", "build-repair", "partial-build",
                                      "context", "probe-author", "probe-repair"],
                          "notes": "Read-only, confined to the snapshot root by the tool layer."},
        "probe_source": {"owner": "triage-orchestrator", "classification": "confidential",
                         "readers": ["probe-diagnosis", "probe-repair"],
                         "notes": "Model-authored code; executed only inside the sandbox."},
        "probe_execution": {"owner": "triage-orchestrator", "classification": "confidential",
                            "readers": ["probe-diagnosis", "verdict"],
                            "notes": "Markers are detected deterministically, never by a model."},
        "verdict": {"owner": "triage-orchestrator", "classification": "confidential",
                    "readers": [],
                    "notes": "Rejected by a deterministic validator if the facts do not support it."},
    },
    "egress": {
        "probe_runtime": "none",
        "build_runtime": "registry allowlist derived from the repository's declared ecosystem",
        "write_back": "comment-only; the system never edits or closes a tracked item",
    },
}

TERMINATION = {
    "schema_version": 1,
    "owner": "triage-orchestrator",
    "rules": [
        {"id": "verdict-reached", "when": "the verdict agent returns a contract-valid verdict",
         "outcome": "complete"},
        {"id": "unreachable-by-context",
         "when": "context cites code making the sink unreachable",
         "outcome": "complete", "verdict": "likely_not_exploitable",
         "notes": "Early exit: no probe is built."},
        {"id": "test-or-vendored",
         "when": "the finding is in test or vendored code",
         "outcome": "complete", "verdict": "likely_not_exploitable"},
        {"id": "probe-unrepairable",
         "when": "probe repairs are exhausted and the last diagnosis is probe_defect",
         "outcome": "complete", "verdict": "inconclusive"},
        {"id": "environment-unbuildable",
         "when": "the build and its repairs fail, including the partial-build fallback",
         "outcome": "complete", "verdict": "inconclusive"},
        {"id": "budget-exhausted",
         "when": "a member exceeds its declared run budget",
         "outcome": "stop", "verdict": "inconclusive"},
        {"id": "contract-unsatisfiable",
         "when": "the verdict agent cannot satisfy the evidence contract within its retries",
         "outcome": "stop", "verdict": "inconclusive",
         "notes": "Implemented in graph/triage.py; inconclusive is what the contract reserves."},
    ],
    "conflict": {
        "authority": "triage-orchestrator",
        "policy": (
            "The deterministic verdict contract is the arbiter. Where a model's conclusion and "
            "the recorded facts disagree, the facts win and the verdict is rejected; the system "
            "never resolves a conflict by preferring the more confident agent."
        ),
    },
    "escalation": {
        "state": "inconclusive",
        "notes": ("inconclusive is a first-class outcome, not a failure: it is how the absence "
                  "of evidence is reported rather than being rounded to 'not exploitable'."),
    },
}


def main() -> int:
    (OUT / "policies").mkdir(parents=True, exist_ok=True)
    spec = system_spec()
    delegation = dict(DELEGATION)
    delegation["interactions"] = {
        interaction["id"]: {
            "callers": ["triage-orchestrator"],
            "callees": [interaction["to"]],
            "mode": "dispatch",
            "authorization_scopes_max": [],
            "data_classification_max": "confidential",
            "budget": dict(_spec(interaction["to"])["metadata"]["budgets"]),
            "retry": {
                "maximum_attempts": 3,
                "retryable_failures": ["transient_provider", "transient_dependency"],
                "non_retryable_failures": ["invalid_input", "policy_blocked", "budget_exhausted"],
            },
            "failure": {
                "required": next(m["required"] for m in spec["members"]
                                 if m["agent"] == interaction["to"]),
                "on_failure": "escalate",
            },
        }
        for interaction in spec["interactions"]
    }
    _write(OUT / "system.yaml", spec, "the triage system's composition")
    _write(OUT / "policies" / "delegation.yaml", delegation, "dispatch budgets and retry policy")
    _write(OUT / "policies" / "data-flow.yaml", DATA_FLOW, "artifact ownership and egress")
    _write(OUT / "policies" / "termination.yaml", TERMINATION, "termination and conflict rules")
    return 0


def _write(path: Path, data: dict, what: str) -> None:
    path.write_text(
        f"# {what.capitalize()}. Generated by scripts/gen_system_spec.py.\n"
        "# Member lists, roles, skills, toolsets, and budgets are read from agents/*/agent.yaml\n"
        "# so this spec cannot drift from them. See multi-agent-playbook/03-system-contract.md.\n"
        + yaml.safe_dump(data, sort_keys=False, width=94, allow_unicode=True)
    )
    print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    raise SystemExit(main())
