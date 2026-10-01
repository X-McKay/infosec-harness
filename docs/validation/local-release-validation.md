# Local cleanup/reorganization validation — 2026-10-01

This review validates the cleanup and lowercase `ui/` reorganization together with the newer
remote `develop` work. The local checkout started 18 commits behind `origin/develop`; those
commits were merged, preserving their agent qualification/intake behavior and historical reports.
New tests and developer documents from that branch were placed into the established subsystem
folders. Historical qualification reports and held-out records retain their original provenance.
The separately authored `docs/CREDENTIAL_BROKER_SPEC.md` draft is excluded from these commits.

## Repairs and compatibility evidence

The isolated wheel test originally resolved PydanticAI 2.52 / Temporal 1.34 and failed Pydantic
schema generation for Temporal `EventGroup`. Changing only Temporal to 1.33 constructed all
11 agents. `pyproject.toml` now declares `temporalio>=1.33,<1.34`; `uv.lock` changes only that
requirement metadata and keeps every locked package version. The actual wheel installation and
construction tests remain unchanged and pass under fresh supported dependency resolution.
This is a supported-version boundary based on reproduced integration behavior, not a reduction
of test expectations or safety thresholds.

Synthetic component fixtures and the harvested Apache Shiro/Spring source paths retain their
upstream `web/` paths. The frontend directory rename applies only to this harness. A regression
case pins the independently known upstream Java paths to prevent future blanket replacement.
The merged real Temporal component test caught an additional fixture path, which was restored
before the final suite. Intermediate failures remain in local logs.

Canonical development skills now explicitly reference `ui/`, subsystem test folders, grouped
documents and separate overlay/calibration inputs. They were advanced to version 1.0.1 and
synchronized into both client discovery directories. Runtime skill reference regions and generated
governance evidence paths were updated through their declared source libraries and generators.
The generated API client remains unchanged by the frontend move.

## Temporal visibility correction

The first real `./dev` completed its pipeline smoke, but captured logs showed PostgreSQL's
`executions_visibility` table was missing. The compose configuration assigned both Temporal
history and visibility to `temporal`; their shared schema-version table caused auto-setup to
skip the independent visibility schema. This was an actual indexed-query failure despite
successful workflow execution.

The visibility database is now `temporal_visibility`; bootstrap and auto-setup retain the
existing history database and volumes. Regression tests check separate database names and
execute the bootstrap through a fake SQL client to verify both idempotent creation statements.
Managed startup, reload and smoke now require the existing completed demo to appear in the
visibility index used by Temporal UI. Query failures and an unindexed demo fail that gate.
No Temporal histories, retries, activity identities or database contents were reset.

## Runtime and test evidence

| Gate | Status | Evidence |
| --- | --- | --- |
| `just check` | passed | Ruff, compilation and all agent specs on the merged tree |
| `just generated-check` | passed | OpenAPI, canonical instructions and both development skill copies |
| `just dev-skills-check` | passed | Canonical digests and client discovery copies match |
| Maintained documentation links | passed | Relative file links in maintained docs, READMEs and development skills resolve; historical frozen reports excluded from path rewriting |
| Frontend | passed | Formatting, two search tests, TypeScript and production Vite build from `ui/` |
| Initial merged suite | passed | 1,839 passed, 14 skipped without the Temporal CLI; `.harness/logs/tests-merged.log` |
| Final full suite with Temporal | passed | 1,855 passed, zero skipped; `.harness/logs/tests-release-final.log`; includes fresh installed wheel, real Temporal workflows and retained-history replay |
| Actual sandbox and build egress | passed | `./dev`: real runsc execution, positive/negative network fixtures, resource caps, PID/memory exhaustion, allow/deny proxy checks and isolated builder; `.harness/logs/dev-final.log` |
| Managed application startup/smoke | passed | `./dev` exited successfully; API/UI/storage readiness, persisted workflow result and completed-workflow visibility query; `.harness/logs/dev-final.log` |
| Warm revalidation | passed | `./dev smoke` repeated sandbox checks, preserved the S3 sentinel and completed batch, and queried Temporal visibility; `.harness/logs/dev-warm-smoke.log` |
| Paid/live inference | not_applicable | Validation uses stub models; no model quality claim or provider call is required |
| Clean-host OS acceptance | not_checked | Existing developer host; new checkout-owned managed VM is not fresh-OS acceptance |
| External agentctl | not_checked | Deterministic governance and generated checks executed; no external conformance invocation |
| Harness database/state migration | not_applicable | No harness schema or durable state location changes; Temporal auto-setup creates its separate visibility schema while retaining history and volumes |

The optional runtime checks use the official Temporal CLI 1.9.1 (embedded server 1.32.0),
downloaded into `.harness/validation/tools/` and verified against the release asset's SHA-256
`41e0425378fcb4fb5766340b97435e20fe47bbff2d7bf644ec2d51f7662b7c56`.
Release metadata is retained locally in `temporal-release.json`; global tools are unchanged.

No workflow topology or replay patch is introduced by the directory move or supported-version
bound. Existing checkout identity, ports, VM, Compose service/volume names, workspace and artifact
references are preserved. The newer incoming durable intake generations remain intact and are
covered by their original replay tests. Source/configuration identities naturally change with
moved evidence references; development skill versions changed, while runtime schema/evaluator
versions did not. No thresholds or expected verdicts were relaxed. No state reset was performed.
