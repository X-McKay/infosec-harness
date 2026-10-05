# Threat model and risk assessment: the triage system

The scored scenarios, the controls they credit, and which agents carry each live with the code
in [`src/infosec_harness/agents/risk-scenarios.yaml`](../../src/infosec_harness/agents/risk-scenarios.yaml),
where governance reads them at construction and the eval coverage gate reads them at release.
This document is the narrative and the assessment: what the system is, what an attacker can
reach, where the trust boundaries fall, and what has been decided about the residual risk.

## What the system does

It triages *pre-identified* findings. It does not scan for new vulnerabilities, propose fixes, or
touch anything outside its sandbox. For one finding it profiles the repository, builds it, writes
a unit-test probe, runs that probe with no network, and returns `potentially_exploitable`,
`likely_not_exploitable`, or `inconclusive`. How the agents compose is in
[TRIAGE_SYSTEM.md](../architecture/TRIAGE_SYSTEM.md).

## Assets

- **Customer source under triage,** including unfixed vulnerability detail. The most sensitive
  thing here: a list of confirmed-exploitable findings is an attack plan.
- **The build and probe hosts**, and the cluster they run on.
- **Triage verdicts**, which application teams act on.
- **Model spend**, which is attacker-influencable: a repository that makes builds fail can drive
  repair loops.

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
| --- | --- | --- |
| Repository snapshot | the harness's own code and specs | every byte of the target repo, including build scripts, tests, comments, and documentation |
| Sandbox container | the worker and host | everything executing inside: the repo's build, its test runner, and the model-authored probe |
| Model boundary | the recorded facts and the deterministic contracts | anything a model asserts |
| Write-back | the harness's comment text | the tracker's other content |

The third boundary is the one that shapes the design. A model's conclusion is a *proposal*; the
deterministic oracle and the verdict contract decide. That is why no agent can report
exploitability without a marker having fired, whatever it believes about the code.

## Adversaries and what they can reach

**A hostile repository.** The realistic adversary: the target repo is attacker-authored or
attacker-influenced. It reaches the model (as text) and the sandbox (as executed code).

- *Through the model:* prompt injection in source, README, or a finding description. The blast
  radius is a wrong triage conclusion, not an action, because the capability allowlist exposes no
  write tool for injected text to reach — only file reads and skill loads.
- *Through the sandbox:* arbitrary code at build time (setup.py, a Gradle task, a postinstall
  hook) and at probe time. This is the system's dominant risk, and the control that bounds it —
  gVisor — is the one control with no runtime evidence. See RISK-SEC-001.

**A hostile finding.** A crafted finding could point the harness at an unintended path. Bounded
by the same read-only tools, and by the location resolver rejecting a finding it cannot place.

**An operator error.** Pointing the model backend at an unapproved endpoint sends customer source
outside the trust boundary (RISK-PRIV-001), and enabling `HARNESS_ALLOW_INSECURE_RUNTIME` outside
development removes the isolation boundary entirely (CONDITION-002).

## What is deliberately not defended

- **A malicious operator.** Anyone who can edit `config/models.yaml` or the agent specs controls
  the system. Configuration is protected like code, not from code.
- **Model-provider compromise.** Out of scope; addressed contractually, and by the option of a
  self-hosted endpoint.
- **Denial of service by an expensive repository.** Bounded rather than prevented: per-run budgets
  and bounded retries cap the spend, but a repo engineered to be slow will still consume its
  ceiling before returning `inconclusive`.

## Risk assessment

Method: agent-playbook §13. Impact and likelihood are scored 1-4 and mapped to a tier through
the playbook matrix (`agents/risk.py`). Inherent likelihood assumes the controls are absent;
residual likelihood counts only controls whose effectiveness is `verified`. An agent's
governance tier is the highest inherent tier among the scenarios it carries, raised to `high`
where a scenario means it performs or determines privileged code execution. Governance refuses
to construct an agent whose spec declares any other tier.

Assessed 2026-09-26 by appsec; status **draft**, not yet accepted. Review by 2026-10-26 while
the system tier is critical, and on any change to a model, skill, tool, or the sandbox runtime.

**Scope.** Intended use is the triage described above, in local and production environments,
by application-security engineers and vulnerability management. Prohibited uses: scanning for
previously unknown vulnerabilities; running probes against production systems, live services,
or any host outside the sandbox; writing code changes or any modification to the repository
under triage; treating a verdict as an authoritative security sign-off without human review;
processing a repository whose source may not be sent to the configured model backend.
Affected parties are the operating organization, customers whose source is triaged, and
application teams receiving verdicts.

**Dimensions.** Security is dominant: the system executes untrusted code by design and reasons
over attacker-influenced text. Privacy, legal, financial, operational and reputational apply
for the reasons the assets above give. Regulatory and human-impact dimensions are not
applicable: the system makes no decision about a person; revisit if it is ever pointed at
software with a safety function or at findings with statutory disclosure timelines.
Jurisdictions and contractual data-handling terms are deployment-specific and must be
confirmed against the configured model backend before approval; this assessment does not
establish legal compliance.

**Classification.**

| Agent | Scenarios | Governance tier | Max residual | Decision |
| --- | --- | --- | --- | --- |
| intake, recon | SEC-002, OPS-001, PRIV-001 | medium | medium | go |
| context | SEC-002, SEC-003, OPS-001, PRIV-001 | high | medium | go |
| probe-planner | SEC-003, SEC-004, OPS-001, PRIV-001 | high | medium | go |
| probe-diagnosis, verdict | SEC-003, OPS-001, PRIV-001 | high | medium | go |
| env-planner, build-repair, partial-build | SEC-001, SEC-002, OPS-001, PRIV-001 | critical | high | conditional go |
| probe-author, probe-repair | SEC-001, SEC-003, SEC-004, OPS-001, PRIV-001 | critical | high | conditional go |
| the system | all six | critical | high | conditional go |

A critical residual would be no-go; none is. The five conditional agents are the ones whose
output determines what the sandbox executes, and their residual stays high because the
control that provides the isolation boundary, gVisor (CTRL-SBX-001), is `implemented` and not
`verified`: its fail-closed check is tested, but the isolation it selects has never executed.

**Conditions for acceptance.**

- CONDITION-001, due 2026-12-19: run `harness eval corpus` with the sandbox enabled on a host
  providing the `runsc` runtime, confirm vulnerable cases build and fire their oracle while
  fixed variants do not, and record the result as evidence for CTRL-SBX-001.
- CONDITION-002, due 2026-10-24: confirm `HARNESS_ALLOW_INSECURE_RUNTIME` is unset in every
  non-development environment and alert on it being enabled.

Acceptance also needs a named risk owner (`appsec-risk-owner`); no scenario is accepted as-is.

**Assumptions.** The repository under triage is untrusted and its build scripts and tests may
be hostile. Probes run with no network egress and are confined to the sandbox workdir.
`config/models.yaml` is controlled at deployment time and reviewed like code. No agent has a
write tool.

**Open questions.** Which jurisdictions and contractual terms apply to the configured model
backend? What false-negative rate is acceptable once measured with the sandbox enabled?

**Monitoring.**

| Indicator | Source | Note |
| --- | --- | --- |
| false_negative_rate_on_exploitable | `harness eval corpus` with the sandbox enabled | the headline quality signal; cannot be measured until CONDITION-001 is met |
| unevidenced_exploitable_verdicts | the verdict evidence contract | must be zero; non-zero means the deterministic contract was bypassed |
| sandbox_runtime_missing_count | `sandbox.policy.ensure_runtime_available` | non-zero outside development means probes are failing closed, as intended |
| insecure_runtime_override_enabled | `settings.allow_insecure_runtime` | must be false outside development |
| budget_exhausted_count | UsageLimits breaches recorded per run | a rise means runs are being stopped rather than answered |
| average_cost_per_finding | per-invocation cost accounting | catches a repair loop regressing into a storm |

Alert on: any `potentially_exploitable` verdict recorded without an oracle signal; the
insecure-runtime override enabled outside development; a false-negative rate above the release
threshold on the corpus; budget exhaustion on more than a small fraction of findings.

## The honest gap

Every control in the assessment is evidenced by a test or a measured run except the isolation
boundary itself. gVisor has never executed: no host available to this project provides `runsc`,
and it cannot run on macOS at all. Until `harness eval corpus` has run with the sandbox enabled
on a `runsc` host, the system's largest risk is mitigated by a control whose design is reviewed
and whose operation is unverified. That is why five agents and the system carry `conditional_go`
rather than `go`.
