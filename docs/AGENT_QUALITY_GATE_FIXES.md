# Qualification gate fixes

The owner requested a 75% task-success floor and work to clear the remaining gates.
This changes quality policy explicitly; it is not evidence of improved agent performance.
Zero budget stops, p95 model requests at most 12, schema validity, risk coverage, secure
execution and unsupported-safe-decision gates remain unchanged. Golden labels and case
expectations are unchanged. The agent playbook permits use-case-specific quality floors;
this owner instruction is an explicit exception to the repository's no-threshold-relaxation
rule. The exception does not authorize relaxing other gates or regrading old releases.

## Preserved baseline

The stopped live evaluator-v6 candidate was clean commit `f9769bf`. Its first eleven
public suites scored 118 cases, with 107 successes and five usage-limit stops. Eight
agent policies passed; build-repair, partial-build and context failed. Completed second
passes included build-repair 11/14, partial-build 6/9 and context 14/15. Full three-pass
qualification was incomplete, and the ten fresh heldouts were never run.

[The sanitized retry summary](validation/agent-quality/retry-20260929-summary.json) retains
the original frozen policies, failed cases, cancelled attempts and unknown usage. It is
historical evidence, not a passing qualification under the new policy.

## Candidate changes

- The canonical release-policy generator uses 0.75 for all governance tiers. Generated
  agent policies, risk-assessment versions and system member versions are synchronized.
- Build-repair 1.0.2 and partial-build 1.1.1 start with supplied failure evidence, load
  relevant skills, batch manifest reads and scope investigation to the owning module.
  Their prompts explain that sandbox probes have no repository mount, external network
  or persistent state, and cannot reproduce the build. They preserve real dependencies
  and avoid invented versions or credentials. Production budgets are unchanged.
- Context 1.1.1 distinguishes an exposed callable's input boundary from proven private
  constant-only paths. Missing references, test scope or vendor placement cannot prove
  unreachable code. Uncertain exposure or input origin stays uncertain.
- Evaluator v7 records a closed binding-limit category and the effective configured
  ceiling for recognized SDK usage-limit messages. Changed wording remains unknown.
  Captured response/token/tool counts are explicitly partial; failed final usage stays
  null and unknown. HTTP failures retain a bounded status and closed exception type,
  omitting raw messages, provider bodies and model/tool contents.

These changes do not alter output schemas, stored domain models, activity names, workflow
commands, sandbox permissions or database schema. Agent versions and configuration
digests change. Accepted durable batches remain pinned to their accepted configuration:
use a compatible worker or a newly accepted run, rather than silently resuming with revised
behavior. Additive evaluator diagnostics need no migration; historical records remain intact.

## Validation and next experiment

Focused policy, SDK-boundary, privacy, adapter, agent-contract and budget tests passed.
The initial full suite found three stale generated-governance/version checks; their logs
are preserved and the files have been regenerated through their declared sources.
The final full suite passed 1,656 tests with zero failures, errors or skips, including the
real local Temporal integration/recovery tests. Lint, compilation, agent validation,
generated-artifact checks and development-skill drift checks passed. Playbook conformance
passed with the existing AGENT029 retries-format waiver and its reported warnings; no
new waiver was added. An independent review found no actionable defects in the scoped
changes. Live efficacy and qualification of this candidate are not checked yet.

The next controlled experiment runs the complete public datasets for build-repair,
partial-build and context once (38 cases), with unchanged limits, at most two concurrent
suites, at most one readiness request and a 90-minute aggregate deadline. Missing or
failed gates stay visible. This is a diagnostic candidate comparison, not the required
three-pass, eleven-agent qualification. No holdouts run during this experiment.

Only an independently observed binding limit can justify a targeted budget trial. A larger
allowance that still exceeds request-efficiency gates or extends unproductive exploration
does not clear qualification. A candidate that clears the affected gates must still pass
fresh complete qualification and the unused heldouts before promotion.
