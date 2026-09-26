"""Render docs/risk-assessments/*.yaml from the shared scenario library.

Run `uv run python scripts/gen_risk_assessments.py`. tests/test_risk_assessments.py asserts
the committed files match, so `scripts/risk_scenarios.py` stays the single source of truth
and a control edited once moves every assessment that credits it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from risk_scenarios import (  # noqa: E402
    AGENT_SCENARIOS,
    OWNER,
    SCENARIOS,
    SYSTEM_SCENARIOS,
    max_tier,
)

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "docs" / "risk-assessments"
ASSESSED_AT = "2026-09-26"
# Review cadence from agent-playbook §13: 1 month critical, 3 high, 6 medium, 12 low.
REVIEW_BY = {"low": "2027-09-26", "medium": "2027-03-26", "high": "2026-12-26",
             "critical": "2026-10-26"}
AGENT_VERSION = "1.0.0"

INTENDED_USE = (
    "Triage pre-identified vulnerability findings for exploitability by building the target "
    "repository and running a targeted unit-test probe in an isolated sandbox, returning "
    "potentially_exploitable, likely_not_exploitable, or inconclusive with cited evidence."
)
PROHIBITED_USES = [
    "Scanning for previously unknown vulnerabilities.",
    "Running probes against production systems, live services, or any host outside the sandbox.",
    "Writing code changes, fixes, or any modification to the repository under triage.",
    "Treating a verdict as an authoritative security sign-off without human review.",
    "Processing a repository whose source may not be sent to the configured model backend.",
]
DIMENSION_REVIEW = {
    "financial": ("applicable",
        "Model spend scales with findings triaged, and an unbounded loop spends without result."),
    "operational": ("applicable",
        "A stalled or looping run occupies worker capacity and delays the triage queue."),
    "reputational": ("applicable",
        "A confident verdict that turns out wrong — in either direction — damages trust in the "
        "triage output and in the team that operates it."),
    "legal": ("applicable",
        "Source under triage is customer material subject to contractual handling terms, and a "
        "missed exploitable vulnerability may carry disclosure obligations."),
    "security": ("applicable",
        "The system executes untrusted code by design and reasons over attacker-influenced text; "
        "this is the dominant dimension."),
    "privacy": ("applicable",
        "Unfixed vulnerability detail and customer source are sent to a model provider."),
    "regulatory": ("not_applicable",
        "The system makes no decision about a person and is not used in a regulated "
        "decision-making context. Revisit if it is ever applied to findings whose disclosure "
        "carries statutory timelines."),
    "human_impact_safety": ("not_applicable",
        "No output affects an individual's rights, opportunities, or physical safety. Revisit if "
        "the harness is ever pointed at software with a safety function."),
}


def _scenario_list(ids: list[str]) -> list[dict]:
    return [{"id": sid, **SCENARIOS[sid]} for sid in ids]


# Scenarios whose presence means this subject can influence code the sandbox executes.
CODE_EXECUTION_SCENARIOS = {"RISK-SEC-001", "RISK-SEC-004"}
CODE_EXECUTION_FLOOR = "high"


def _governance_floors(ids: list[str]) -> list[dict]:
    if not CODE_EXECUTION_SCENARIOS & set(ids):
        return []
    return [{
        "source": "agent-playbook §13 capability floor",
        "tier": CODE_EXECUTION_FLOOR,
        "rationale": (
            "This subject performs or determines privileged code execution: untrusted "
            "repository code and model-authored probes run on its output."
        ),
    }]


def _classification(ids: list[str]) -> dict:
    inherent = max_tier([SCENARIOS[s]["inherent"]["tier"] for s in ids])
    residual = max_tier([SCENARIOS[s]["residual"]["tier"] for s in ids])
    # Governance tier is the highest of inherent risk and any applicable floor (§13).
    floors = [f["tier"] for f in _governance_floors(ids)]
    governance = max_tier([inherent, *floors])
    conditional = residual in ("high", "critical")
    if residual == "critical":
        decision, rationale = "no_go", (
            "A critical residual scenario cannot launch under agent-playbook §13.")
    elif conditional:
        decision, rationale = "conditional_go", (
            "Every control except the isolation boundary itself is verified. gVisor has never "
            "executed — no host available to this project provides runsc — so RISK-SEC-001 and "
            "RISK-SEC-004 retain a high residual tier on absent evidence rather than on a known "
            "weakness. Launch is conditional on that evidence."
        )
    else:
        decision, rationale = "go", (
            "Every scenario reaching this agent has a verified control set and a residual tier of "
            "medium or below. It does not influence what code the sandbox executes."
        )
    return {
        "governance_tier": governance,  # anchored to inherent risk and mandatory floors
        "maximum_inherent_tier": inherent,
        "maximum_residual_tier": residual,
        "decision": decision,
        "rationale": rationale,
    }


def _acceptance(ids: list[str], classification: dict) -> dict:
    conditions = []
    if classification["decision"] == "conditional_go":
        conditions.append({
            "id": "CONDITION-001",
            "requirement": (
                "Run `harness eval corpus` with the sandbox enabled on a host providing the runsc "
                "runtime, confirming vulnerable cases build and fire their oracle while fixed "
                "variants do not, and record the result as evidence for CTRL-SBX-001."
            ),
            "owner": OWNER,
            "due_by": "2026-12-19",
        })
        conditions.append({
            "id": "CONDITION-002",
            "requirement": (
                "Confirm HARNESS_ALLOW_INSECURE_RUNTIME is unset in every non-development "
                "environment and alert on it being enabled."
            ),
            "owner": OWNER,
            "due_by": "2026-10-24",
        })
    return {
        "accountable_role": "appsec-risk-owner",
        "accepted_scenarios": [],
        "conditions": conditions,
        "expires_at": REVIEW_BY[classification["governance_tier"]],
        "rationale": (
            "Not yet accepted. The assessment is complete and its controls are evidenced except "
            "where noted; acceptance is pending the listed conditions and a named risk owner."
            if conditions else
            "Not yet accepted. Awaiting sign-off by the named risk owner; no conditions "
            "outstanding."
        ),
    }


def _member_assessments() -> list[dict]:
    """Every member's governance tier and the artifact that establishes it.

    The system tier must be at least the highest member's: composition raises assurance, it
    never lowers it. Reading the members here rather than restating them keeps the two
    artifacts from drifting.
    """
    import yaml as _yaml

    members = []
    for agent in AGENT_SCENARIOS:
        spec = _yaml.safe_load((REPO / "agents" / agent / "agent.yaml").read_text())
        members.append({
            "agent": agent,
            "agent_version": spec["metadata"]["version"],
            "governance_tier": spec["metadata"]["risk_tier"],
            "assessment": f"docs/risk-assessments/{agent}.yaml",
        })
    return members


MONITORING = {
    "owner": OWNER,
    "indicators": [
        {"name": "false_negative_rate_on_exploitable",
         "source": "harness eval corpus with the sandbox enabled",
         "note": "The headline quality signal. Cannot be measured until CONDITION-001 is met."},
        {"name": "unevidenced_exploitable_verdicts",
         "source": "the verdict evidence contract",
         "note": "Must be zero; a non-zero value means the deterministic contract was bypassed."},
        {"name": "sandbox_runtime_missing_count",
         "source": "sandbox.policy.ensure_runtime_available",
         "note": "Non-zero outside development means probes are failing closed, as intended."},
        {"name": "insecure_runtime_override_enabled",
         "source": "settings.allow_insecure_runtime",
         "note": "Must be false outside development; this disables the isolation boundary."},
        {"name": "budget_exhausted_count", "source": "UsageLimits breaches recorded per run",
         "note": "A rise means runs are being stopped rather than answered."},
        {"name": "average_cost_per_finding", "source": "per-invocation cost accounting",
         "note": "Catches a repair loop regressing into a storm."},
    ],
    "alerts": [
        "any verdict of potentially_exploitable recorded without an oracle signal",
        "insecure_runtime_override_enabled true in a non-development environment",
        "false-negative rate above the release threshold on the corpus",
        "budget exhaustion on more than a small fraction of findings",
    ],
    "reviews": {
        "cadence": "monthly while the governance tier is critical",
        "owner": OWNER,
        "note": ("Reassess on any change to a model, skill, tool, or the sandbox runtime, and "
                 "whenever a hard gate fails."),
    },
    "runbooks": [
        "docs/runbooks/sandbox-isolation.md",
        "docs/runbooks/triage-quality.md",
        "docs/runbooks/cost-and-capacity.md",
        "docs/runbooks/data-handling.md",
    ],
}


def build(subject: str, ids: list[str], *, is_system: bool) -> dict:
    classification = _classification(ids)
    members = _member_assessments()
    if is_system:
        member_tier = max_tier([m["governance_tier"] for m in members])
        # Composition raises assurance: the system is at least its strongest member.
        classification["governance_tier"] = max_tier(
            [classification["governance_tier"], member_tier])
        classification["maximum_member_tier"] = member_tier
        extra = {"member_assessments": members, "monitoring": MONITORING}
        identity = {"system": subject, "system_version": AGENT_VERSION}
    else:
        extra = {}
        identity = {"agent": subject, "agent_version": AGENT_VERSION}
    return {
        "schema_version": 1,
        "assessment": {
            **identity,
            "assessment_version": "1.0.0",
            "status": "draft",
            "assessed_at": ASSESSED_AT,
            "review_by": REVIEW_BY[classification["governance_tier"]],
            "prepared_by": OWNER,
            "approved_by": [],
        },
        "scope": {
            "intended_use": (
                INTENDED_USE if is_system else
                f"{INTENDED_USE} This assessment covers the {subject} agent's contribution."
            ),
            "prohibited_uses": PROHIBITED_USES,
            "users": ["application-security-engineers", "vulnerability-management"],
            "affected_parties": [
                "the operating organization",
                "customers whose source is triaged",
                "application teams receiving verdicts",
            ],
            "environments": ["local", "production"],
            "jurisdictions": ["replace-with-applicable-jurisdictions"],
            "execution_class": "durable",
        },
        "dimension_review": {
            name: {"status": status, "rationale": rationale}
            for name, (status, rationale) in DIMENSION_REVIEW.items()
        },
        "regulatory_screen": {
            "prohibited_use": False,
            "applicable_regimes": [],
            "required_reviews": ["security", "privacy"],
            "governance_floors": _governance_floors(ids),
            "notes": (
                "Jurisdictions and contractual data-handling terms are deployment-specific and "
                "must be confirmed against the configured model backend before approval. This "
                "screen does not establish legal compliance."
            ),
        },
        "classification": classification,
        "scenarios": _scenario_list(ids),
        "acceptance": _acceptance(ids, classification),
        "assumptions": [
            "The repository under triage is untrusted; its build scripts and tests may be hostile.",
            "Probes run with no network egress and are confined to the sandbox workdir.",
            "config/models.yaml is controlled at deployment time and reviewed like code.",
            "No agent has a write tool: the capability allowlist exposes reads and skill loads.",
        ],
        "open_questions": [
            "Which jurisdictions and contractual terms apply to the configured model backend?",
            "What false-negative rate is acceptable once measured with the sandbox enabled?",
        ],
        **extra,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "systems").mkdir(exist_ok=True)
    written = []
    for agent, ids in AGENT_SCENARIOS.items():
        path = OUT / f"{agent}.yaml"
        path.write_text(_render(build(agent, ids, is_system=False)))
        written.append(path)
    path = OUT / "systems" / "triage-system.yaml"
    path.write_text(_render(build("triage-system", SYSTEM_SCENARIOS, is_system=True)))
    written.append(path)
    for p in written:
        print(f"wrote {p.relative_to(REPO)}")
    return 0


def _render(data: dict) -> str:
    header = (
        "# Generated by scripts/gen_risk_assessments.py from scripts/risk_scenarios.py.\n"
        "# Edit the scenario library, not this file; tests/test_risk_assessments.py asserts\n"
        "# they agree. See agent-playbook 13-risk-assessment.md for the method.\n"
    )
    return header + yaml.safe_dump(data, sort_keys=False, width=94, allow_unicode=True)


if __name__ == "__main__":
    raise SystemExit(main())
