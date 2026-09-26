# Threat model: the triage system

Companion to [`docs/risk-assessments/systems/triage-system.yaml`](../risk-assessments/systems/triage-system.yaml),
which carries the scored scenarios, controls, and evidence. This document is the narrative: what
the system is, what an attacker can reach, and where the trust boundaries actually fall.

## What the system does

It triages *pre-identified* findings. It does not scan for new vulnerabilities, propose fixes, or
touch anything outside its sandbox. For one finding it profiles the repository, builds it, writes
a unit-test probe, runs that probe with no network, and returns `potentially_exploitable`,
`likely_not_exploitable`, or `inconclusive`.

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

## The honest gap

Every control in the assessment is evidenced by a test or a measured run except the isolation
boundary itself. gVisor has never executed: no host available to this project provides `runsc`,
and it cannot run on macOS at all. Until `harness eval corpus` has run with the sandbox enabled
on a `runsc` host, the system's largest risk is mitigated by a control whose design is reviewed
and whose operation is unverified. That is why five agents and the system carry `conditional_go`
rather than `go`.
