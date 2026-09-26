"""The harm scenarios this system can cause, and which agents contribute to each.

One library rather than eleven hand-maintained documents, because the agents share their
harms: they all read untrusted repository content, they all send it to a model provider, and
five of them influence what code the sandbox executes. Keeping the scenarios here means a
control that changes is edited once, and every assessment that credits it moves together.

`scripts/gen_risk_assessments.py` renders this into the canonical per-agent artifacts under
`docs/risk-assessments/`, which are what `agentctl risk validate` reads. A test asserts the
rendered files match, so the library stays the single source of truth.

Scoring follows agent-playbook §13: impact at a credible worst case, inherent likelihood
assuming the controls are absent, residual likelihood counting only controls whose
effectiveness is `verified`. A control marked `implemented` earns no residual reduction.
"""

from __future__ import annotations

from typing import Any

MATRIX = {  # (impact, likelihood) -> tier, from agent-playbook §13
    (1, 1): "low", (1, 2): "low", (1, 3): "medium", (1, 4): "medium",
    (2, 1): "low", (2, 2): "medium", (2, 3): "medium", (2, 4): "high",
    (3, 1): "medium", (3, 2): "medium", (3, 3): "high", (3, 4): "critical",
    (4, 1): "high", (4, 2): "high", (4, 3): "critical", (4, 4): "critical",
}
TIER_ORDER = ("low", "medium", "high", "critical")
OWNER = "appsec"


def tier_for(impact: int, likelihood: int) -> str:
    return MATRIX[(impact, likelihood)]


def rating(impact: int, likelihood: int, confidence: str, rationale: str) -> dict[str, Any]:
    return {"impact": impact, "likelihood": likelihood, "tier": tier_for(impact, likelihood),
            "confidence": confidence, "rationale": rationale}


# --- Controls, named once so several scenarios can credit the same evidence -------------

GVISOR = {
    "id": "CTRL-SBX-001", "type": "preventive",
    "description": ("Build and probe containers run under gVisor (runsc), fail-closed: "
                    "ensure_runtime_available raises SandboxUnavailable when runsc is absent "
                    "unless HARNESS_ALLOW_INSECURE_RUNTIME is set for development."),
    "owner": OWNER,
    "evidence": ["tests/test_sandbox_policy.py", "src/infosec_harness/sandbox/policy.py"],
    # The fail-closed *check* is verified by tests; the isolation it selects has never run.
    # No host available to this project has runsc, so it earns no residual reduction.
    "effectiveness": "implemented",
}
CONTAINER_HARDENING = {
    "id": "CTRL-SBX-002", "type": "preventive",
    "description": ("Containers run non-root with all capabilities dropped, no-new-privileges, "
                    "a read-only root filesystem, a tmpfs workdir, and CPU/memory/pid caps."),
    "owner": OWNER,
    "evidence": ["tests/test_sandbox.py", "tests/test_sandbox_policy.py"],
    "effectiveness": "verified",
}
NO_PROBE_NETWORK = {
    "id": "CTRL-SBX-003", "type": "preventive",
    "description": "Probe containers run with --network=none, so a probe has no egress at all.",
    "owner": OWNER, "evidence": ["tests/test_sandbox.py"], "effectiveness": "verified",
}
IMAGE_AND_EGRESS_ALLOWLIST = {
    "id": "CTRL-SBX-004", "type": "preventive",
    "description": ("Base images are restricted to an allowlisted registry set and build-time "
                    "egress is pinned to the registries a repo's declared ecosystem needs."),
    "owner": OWNER, "evidence": ["tests/test_sandbox_policy.py"], "effectiveness": "verified",
}
UNTRUSTED_DATA_FRAMING = {
    "id": "CTRL-INJ-001", "type": "preventive",
    "description": ("Every prompt labels repository content, finding text, and probe output as "
                    "untrusted data and forbids following instructions found in it."),
    "owner": OWNER, "evidence": ["tests/test_render.py"],
    # Prompt-level defence against a capable adversary is not a control you can call verified.
    "effectiveness": "implemented",
}
READ_ONLY_TOOLS = {
    "id": "CTRL-INJ-002", "type": "preventive",
    "description": ("The capability allowlist exposes no write tool at all: injected text has no "
                    "consequential operation to reach, only file reads and skill loads."),
    "owner": OWNER, "evidence": ["tests/test_agents.py", "src/infosec_harness/agents/registry.py"],
    "effectiveness": "verified",
}
ORACLE_CONTRACT = {
    "id": "CTRL-FN-001", "type": "preventive",
    "description": ("Exploitability is decided by an explicit oracle marker carrying a run nonce, "
                    "detected deterministically in code — never from a test passing, and never "
                    "from the model asserting it."),
    "owner": OWNER,
    "evidence": ["tests/test_sandbox.py", "src/infosec_harness/sandbox/docker.py"],
    "effectiveness": "verified",
}
VERDICT_EVIDENCE_CONTRACT = {
    "id": "CTRL-FN-002", "type": "preventive",
    "description": ("A deterministic validator rejects any verdict the recorded facts do not "
                    "support: potentially_exploitable requires the oracle to have fired, and "
                    "likely_not_exploitable requires either a valid negative that reached the "
                    "precondition or an evidenced unreachable sink."),
    "owner": OWNER, "evidence": ["tests/test_validators.py", "tests/test_graph.py"],
    "effectiveness": "verified",
}
THREE_WAY_VERDICT = {
    "id": "CTRL-FN-003", "type": "recovery",
    "description": ("`inconclusive` is a first-class outcome, so the absence of evidence is "
                    "reported as such instead of being rounded to 'not exploitable'."),
    "owner": OWNER, "evidence": ["tests/test_graph.py", "docs/LIVE_VALIDATION.md"],
    "effectiveness": "verified",
}
CORPUS_GROUND_TRUTH = {
    "id": "CTRL-FN-004", "type": "detective",
    "description": ("A paired vulnerable/fixed corpus is scored end to end, and reference probes "
                    "assert each vulnerable variant really is exploitable and its fixed twin is "
                    "not — so a corpus whose ground truth has rotted fails rather than flatters."),
    "owner": OWNER,
    "evidence": ["tests/test_corpus_oracle.py", "tests/test_corpus.py"],
    "effectiveness": "verified",
}
SKILL_CONSISTENCY = {
    "id": "CTRL-FN-005", "type": "detective",
    "description": ("An invariant test prevents a per-CWE skill from recommending an oracle that "
                    "violates the probe protocol, which previously produced a probe whose "
                    "instrumentation was never used — a silent false negative."),
    "owner": OWNER, "evidence": ["tests/test_skills_consistency.py"],
    "effectiveness": "verified",
}
RUN_BUDGETS = {
    "id": "CTRL-OPS-001", "type": "preventive",
    "description": ("Each agent declares a per-run ceiling on model requests, tool calls, tokens, "
                    "and cost, enforced through UsageLimits in both the local and durable paths."),
    "owner": OWNER, "evidence": ["tests/test_budgets.py"], "effectiveness": "verified",
}
BOUNDED_RETRIES = {
    "id": "CTRL-OPS-002", "type": "preventive",
    "description": ("All four retry layers are bounded and their product is asserted, so a "
                    "deterministic failure cannot retry indefinitely."),
    "owner": OWNER, "evidence": ["tests/test_retry_bounds.py"], "effectiveness": "verified",
}
FAILURE_CONTAINMENT = {
    "id": "CTRL-OPS-003", "type": "recovery",
    "description": ("A failure on one finding is recorded as inconclusive/error and the batch "
                    "continues; in the durable path each finding is its own child workflow."),
    "owner": OWNER, "evidence": ["tests/test_graph.py"], "effectiveness": "verified",
}
REVIEWED_BACKEND_CONFIG = {
    "id": "CTRL-PRIV-001", "type": "preventive",
    "description": ("The model backend and endpoint are declarative config in config/models.yaml "
                    "with no secrets, reviewed like code; a self-hosted OpenAI-spec endpoint is "
                    "supported so source need not leave the deployment's trust boundary."),
    "owner": OWNER, "evidence": ["config/models.yaml", "tests/test_agents.py"],
    "effectiveness": "implemented",
}
COST_TELEMETRY = {
    "id": "CTRL-OPS-004", "type": "detective",
    "description": ("Tokens, cache hits, and estimated cost are recorded per agent invocation and "
                    "persisted with the run, and emitted as span attributes."),
    "owner": OWNER, "evidence": ["tests/test_telemetry.py", "tests/test_persistence.py"],
    "effectiveness": "verified",
}

# --- Scenarios -------------------------------------------------------------------------

SCENARIOS: dict[str, dict[str, Any]] = {
    "RISK-SEC-001": {
        "title": "Untrusted repository code escapes the build or probe sandbox",
        "status": "open",
        "statement": (
            "Because the harness builds and executes code from a repository it does not trust, "
            "the agent could cause that code to run outside its intended isolation boundary, "
            "causing host or cluster compromise and loss of confidentiality, integrity, and "
            "availability to the operator and to every tenant whose code the harness processes."
        ),
        "primary_dimension": "security",
        "secondary_dimensions": ["operational", "legal", "reputational"],
        "affected_parties": ["the operating organization", "customers whose code is triaged"],
        "affected_assets": ["build and probe hosts", "the cluster", "other tenants' source"],
        "causes": [
            "a repository's build script or test hook executes arbitrary code",
            "an environment plan selects a base image or install command that widens privilege",
            "the isolation runtime is missing and the insecure-runtime override is enabled",
        ],
        "preconditions": [
            "a build or probe container is started",
            "the container runtime does not provide kernel-level isolation",
        ],
        "consequences": [
            "arbitrary code execution on the host or cluster node",
            "cross-tenant exposure of source under triage",
        ],
        "inherent": rating(4, 3, "high",
            "Executing untrusted build scripts without kernel isolation is a direct host "
            "compromise path, and it happens on every prepared repository."),
        "controls": [GVISOR, CONTAINER_HARDENING, NO_PROBE_NETWORK, IMAGE_AND_EGRESS_ALLOWLIST],
        "residual": rating(4, 2, "low",
            "The hardening controls are verified, but the control that actually provides the "
            "isolation boundary — gVisor — has never executed: no host available to this "
            "project has runsc, so it earns no residual reduction. Impact is unchanged because "
            "the remaining controls narrow privilege inside the container without containing a "
            "kernel escape. Confidence is low precisely because the evidence is absent."),
        "treatment": "mitigate",
        "owner": OWNER,
        "eval_cases": ["corpus-sandbox-on"],
        "indicators": ["sandbox_runtime_missing_count", "insecure_runtime_override_enabled"],
        "alerts": ["any probe or build executed without runsc in a non-development environment"],
        "runbook": "docs/runbooks/sandbox-isolation.md",
    },
    "RISK-SEC-002": {
        "title": "Repository content is treated as instructions",
        "status": "open",
        "statement": (
            "Because repository content, finding text, and probe output all reach the model, the "
            "agent could follow instructions embedded in that content, causing a misdirected "
            "investigation and an unreliable triage conclusion for the operating organization."
        ),
        "primary_dimension": "security",
        "secondary_dimensions": ["operational", "reputational"],
        "affected_parties": ["the operating organization", "application teams receiving verdicts"],
        "affected_assets": ["triage conclusions", "engineering time"],
        "causes": [
            "a source file or README contains text addressed to an automated reviewer",
            "a finding description is attacker-influenced",
        ],
        "preconditions": ["untrusted text reaches the model context"],
        "consequences": [
            "the agent investigates the wrong location or reports a fabricated conclusion",
            "remediation effort is misdirected",
        ],
        "inherent": rating(2, 3, "medium",
            "Injected text is plausible in any real repository, but the blast radius is a wrong "
            "triage conclusion rather than an action, because the agents have no write tools."),
        "controls": [UNTRUSTED_DATA_FRAMING, READ_ONLY_TOOLS, ORACLE_CONTRACT,
                     VERDICT_EVIDENCE_CONTRACT],
        "residual": rating(2, 2, "medium",
            "The decisive control is structural rather than textual: there is no consequential "
            "tool for injected text to reach, and a claim of exploitability is rejected unless a "
            "deterministic oracle fired. Prompt-level framing alone would not earn this."),
        "treatment": "mitigate",
        "owner": OWNER,
        "eval_cases": ["corpus-all-languages"],
        "indicators": ["verdict_contract_rejection_count"],
        "alerts": ["a sustained rise in verdict contract rejections"],
        "runbook": "docs/runbooks/triage-quality.md",
    },
    "RISK-SEC-003": {
        "title": "An exploitable vulnerability is reported as not exploitable",
        "status": "open",
        "statement": (
            "Because a probe can fail to observe an exploit for reasons unrelated to "
            "exploitability, the agent could report likely_not_exploitable for a genuinely "
            "exploitable finding, causing the operating organization to leave a real "
            "vulnerability unremediated."
        ),
        "primary_dimension": "security",
        "secondary_dimensions": ["operational", "reputational", "legal"],
        "affected_parties": ["the operating organization", "users of the affected application"],
        "affected_assets": ["the vulnerable application", "the triage backlog"],
        "causes": [
            "the probe instruments an object the target does not use, so the oracle cannot fire",
            "a per-CWE skill recommends an oracle that does not exercise the real sink",
            "context misreads a sanitizer and early-exits the finding as unreachable",
            "diagnosis classifies a valid positive as a probe defect",
        ],
        "preconditions": ["the finding is genuinely exploitable", "the probe runs to completion"],
        "consequences": [
            "a real vulnerability is deprioritized on the strength of a harness verdict",
            "trust in the triage output is misplaced",
        ],
        "inherent": rating(3, 3, "high",
            "This is the costliest error the system can make and it has been observed: a probe "
            "that wrapped a sqlite cursor the target never used produced exactly this shape, "
            "reported as a clean run."),
        "controls": [ORACLE_CONTRACT, VERDICT_EVIDENCE_CONTRACT, THREE_WAY_VERDICT,
                     CORPUS_GROUND_TRUTH, SKILL_CONSISTENCY],
        "residual": rating(3, 2, "medium",
            "Impact is unchanged — a missed vulnerability is a missed vulnerability. Likelihood "
            "drops because a probe that never reached the sink is diagnosed as a defect rather "
            "than a negative, the verdict contract refuses an unevidenced 'not exploitable', and "
            "the corpus asserts its own ground truth. It is not lower than this because the "
            "measured false-negative rate on a live model has never been established with the "
            "sandbox on."),
        "treatment": "mitigate",
        "owner": OWNER,
        "eval_cases": ["corpus-sandbox-on", "probe-diagnosis-negative_with_source"],
        "indicators": ["false_negative_rate_on_exploitable", "probe_defect_rate"],
        "alerts": ["false-negative rate above its release threshold on the corpus"],
        "runbook": "docs/runbooks/triage-quality.md",
    },
    "RISK-SEC-004": {
        "title": "A model-authored probe acts outside its intended scope",
        "status": "open",
        "statement": (
            "Because probe source is written by a model from untrusted context, the agent could "
            "author a probe that reaches the network or writes outside the sandbox workdir, "
            "causing unintended external contact or loss of integrity for the operating "
            "organization."
        ),
        "primary_dimension": "security",
        "secondary_dimensions": ["operational", "legal"],
        "affected_parties": ["the operating organization", "third parties a probe might contact"],
        "affected_assets": ["the sandbox host", "external systems"],
        "causes": [
            "the probe plan chooses a payload with a side effect outside the sandbox",
            "authored probe code contacts a real host instead of a loopback listener",
        ],
        "preconditions": ["a probe is executed"],
        "consequences": [
            "an unintended request leaves the sandbox",
            "files are written outside the intended workdir",
        ],
        "inherent": rating(3, 2, "medium",
            "Model-authored code is executed by design, but the payloads it needs for this "
            "system's weakness classes are local by nature."),
        "controls": [NO_PROBE_NETWORK, CONTAINER_HARDENING, GVISOR],
        "residual": rating(3, 1, "medium",
            "Egress is removed at the container level rather than requested of the model, and the "
            "workdir is a tmpfs on a read-only root. Impact stays at 3 because the isolation "
            "boundary itself is unverified."),
        "treatment": "mitigate",
        "owner": OWNER,
        "eval_cases": ["corpus-sandbox-on"],
        "indicators": ["probe_network_attempt_count"],
        "alerts": ["any probe container started with networking enabled"],
        "runbook": "docs/runbooks/sandbox-isolation.md",
    },
    "RISK-OPS-001": {
        "title": "Unbounded execution consumes budget without producing a verdict",
        "status": "open",
        "statement": (
            "Because agents retry and repair on failure, the agent could loop without converging, "
            "causing uncontrolled model spend and a stalled triage queue for the operating "
            "organization."
        ),
        "primary_dimension": "financial",
        "secondary_dimensions": ["operational"],
        "affected_parties": ["the operating organization"],
        "affected_assets": ["model spend", "worker capacity", "the triage queue"],
        "causes": [
            "a repair loop re-runs against an outcome that cannot change",
            "an activity retry policy is absent and inherits unlimited attempts",
            "an output contract the model cannot satisfy exhausts retries repeatedly",
        ],
        "preconditions": ["a triage run starts"],
        "consequences": [
            "spend grows without a corresponding verdict",
            "a workflow occupies a worker slot indefinitely",
        ],
        "inherent": rating(2, 3, "high",
            "Observed repeatedly: an offline stub that fabricated a clean probe run drove every "
            "case to its repair limit with context growing from 8.8k to 24k tokens, and two "
            "activity paths inherited Temporal's unlimited retries."),
        "controls": [RUN_BUDGETS, BOUNDED_RETRIES, FAILURE_CONTAINMENT, COST_TELEMETRY],
        "residual": rating(2, 1, "high",
            "Every layer now has an asserted ceiling: per-run UsageLimits, a bounded product "
            "across the four retry layers, and per-finding containment so one failure cannot "
            "consume a batch."),
        "treatment": "mitigate",
        "owner": OWNER,
        "eval_cases": ["corpus-all-languages"],
        "indicators": ["budget_exhausted_count", "average_cost_per_finding", "p95_model_requests"],
        "alerts": ["budget exhaustion on more than a small fraction of findings"],
        "runbook": "docs/runbooks/cost-and-capacity.md",
    },
    "RISK-PRIV-001": {
        "title": "Customer source is sent to an endpoint without the required terms",
        "status": "open",
        "statement": (
            "Because the model backend is deployment configuration, the agent could send customer "
            "source and unfixed vulnerability detail to a provider that lacks the required "
            "data-processing terms, causing confidentiality and contractual harm to customers "
            "and the operating organization."
        ),
        "primary_dimension": "privacy",
        "secondary_dimensions": ["legal", "security", "reputational"],
        "affected_parties": ["customers whose code is triaged", "the operating organization"],
        "affected_assets": ["customer source", "unfixed vulnerability detail"],
        "causes": [
            "a backend base_url is pointed at an unapproved endpoint",
            "a deployment inherits a test endpoint configuration",
        ],
        "preconditions": ["an agent run sends repository content to a model"],
        "consequences": [
            "source and exploitability detail are disclosed outside the trust boundary",
            "contractual or regulatory obligations are breached",
        ],
        "inherent": rating(3, 2, "medium",
            "Sending source to a model is intrinsic to the design, so the scenario turns on "
            "whether the endpoint is an approved one — a configuration error, not a rare event."),
        "controls": [REVIEWED_BACKEND_CONFIG],
        "residual": rating(3, 2, "medium",
            "The endpoint is reviewable declarative config and a self-hosted backend is "
            "supported, but nothing in the system verifies that a configured endpoint is an "
            "approved one, so this earns no likelihood reduction. Deployment-time control of "
            "config/models.yaml is the operator's responsibility."),
        "treatment": "mitigate",
        "owner": OWNER,
        "eval_cases": [],
        "indicators": ["resolved_model_backend", "resolved_model_endpoint"],
        "alerts": ["a model backend resolving to an endpoint outside the approved set"],
        "runbook": "docs/runbooks/data-handling.md",
    },
}

# Which agents materially contribute to each scenario. Attribution is by influence, not by
# membership: verdict cannot cause a sandbox escape, and recon is not on the
# false-negative path because a bad repo profile fails the build rather than clearing a
# finding.
AGENT_SCENARIOS: dict[str, list[str]] = {
    "intake":          ["RISK-SEC-002", "RISK-OPS-001", "RISK-PRIV-001"],
    "recon":           ["RISK-SEC-002", "RISK-OPS-001", "RISK-PRIV-001"],
    "env-planner":     ["RISK-SEC-001", "RISK-SEC-002", "RISK-OPS-001", "RISK-PRIV-001"],
    "build-repair":    ["RISK-SEC-001", "RISK-SEC-002", "RISK-OPS-001", "RISK-PRIV-001"],
    "partial-build":   ["RISK-SEC-001", "RISK-SEC-002", "RISK-OPS-001", "RISK-PRIV-001"],
    "context":         ["RISK-SEC-002", "RISK-SEC-003", "RISK-OPS-001", "RISK-PRIV-001"],
    "probe-planner":   ["RISK-SEC-003", "RISK-SEC-004", "RISK-OPS-001", "RISK-PRIV-001"],
    "probe-author":    ["RISK-SEC-001", "RISK-SEC-003", "RISK-SEC-004", "RISK-OPS-001",
                        "RISK-PRIV-001"],
    "probe-repair":    ["RISK-SEC-001", "RISK-SEC-003", "RISK-SEC-004", "RISK-OPS-001",
                        "RISK-PRIV-001"],
    "probe-diagnosis": ["RISK-SEC-003", "RISK-OPS-001", "RISK-PRIV-001"],
    "verdict":         ["RISK-SEC-003", "RISK-OPS-001", "RISK-PRIV-001"],
}
# The system carries every scenario, including the write-back path no single agent owns.
SYSTEM_SCENARIOS = list(SCENARIOS)


def max_tier(tiers: list[str]) -> str:
    return max(tiers, key=TIER_ORDER.index)
