# Playbook conformance

This system is built to the [Agent Playbook](https://github.com/X-McKay/playbooks/tree/main/agent-playbook)
and the [Multi-Agent Systems Playbook](https://github.com/X-McKay/playbooks/tree/main/multi-agent-playbook).
Conformance is checked, not asserted:

```bash
just conformance                                  # needs agentctl on PATH
just conformance AGENTCTL=/path/to/playbooks      # or a checkout of that repo
```

```
PASS agents   errors=0 waived=11 warnings=22
PASS skills   errors=0 waived= 0 warnings= 0
PASS risk     errors=0 waived= 0 warnings=22
PASS system   errors=0 waived=11 warnings=24
```

`scripts/conformance.py` mirrors the repository into the layout `agentctl` discovers and runs
its four validators against the real YAML. The warnings are the ones that should be there: the
risk assessments are drafts with open questions, and a draft cannot satisfy production
readiness until a named owner accepts it.

## Where the artifacts live

| Artifact | Path | Source of truth |
| --- | --- | --- |
| Agent Specs | `agents/<name>/agent.yaml` | hand-authored |
| Skills | `skills/<name>/SKILL.md` | `scripts/skill_specs.py` → `restructure_skills.py` |
| Tool policies | `src/infosec_harness/tools/<toolset>/tool.yaml` | hand-authored |
| Risk assessments | `docs/risk-assessments/` | `scripts/risk_scenarios.py` → `gen_risk_assessments.py` |
| Release policies | `agents/<name>/evals/release-policy.yaml` | `scripts/gen_release_policies.py` |
| System Spec | `systems/triage-system/` | `scripts/gen_system_spec.py` |
| Threat model | `docs/threat-models/triage-system.md` | hand-authored |

`just governance` regenerates everything derived. Tests assert the committed files match, so
the generators cannot drift from what is reviewed.

## Deliberate deviations

**File layout.** The playbook's golden path is `src/<package>/agents/<name>/`; we keep agent
specs, skills, and systems at the top level next to each other because they are reviewed
together as data. That is a difference in filing, not in contract — which is why the
conformance script mirrors rather than the repository moving.

**`retries` as a mapping** (waived, 11 agents). `agentctl` requires a plain integer.
pydantic-ai's own Agent Spec schema accepts an integer *or* an `AgentRetries` mapping — see
`agents/agent_schema.json`, generated from the framework — and the mapping is what lets
`verdict` carry `output: 4` while its tool retries stay at 2. Collapsing it would lose a
distinction the framework supports and the retry-bound calculation relies on. Worth raising
upstream.

**A shared threat model.** Each agent's spec points at
`docs/threat-models/triage-system.md` rather than a per-agent document, because the trust
boundaries are system-level: the same untrusted repository reaches all of them, and the same
sandbox contains the code. Eleven near-identical documents would be worse, not better.

## What conformance does and does not establish

It establishes that the contracts are complete and internally consistent: every agent has an
owner, a governance tier that matches its risk assessment, an execution class its tools
justify, a per-run budget that is enforced, an eval dataset, and an executable release gate.

It does not establish that the system is safe to launch. Five agents and the system carry
`conditional_go`, not `go`, because the control that bounds their largest risk — gVisor — has
never executed. `agentctl risk validate` is satisfied by an assessment that records this
honestly; it is `CONDITION-001` that remains open. See
[`LIVE_VALIDATION.md`](LIVE_VALIDATION.md).

## Not adopted

The playbook's `human_governed` execution class, approval policies, tenant isolation, and
authorization scopes are not implemented, because nothing here needs them: every tool is
read-only or sandbox-confined, there is no consequential write (the tracker write-back is
comment-only), and the deployment is single-tenant. They would be required before this system
could take an action on anyone's behalf.
