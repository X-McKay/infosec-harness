# Astra simplification review

This records the simplification branch based on develop `2aebf06`, reviewed on 2026-10-05.
It establishes deterministic regression coverage and package/UI integration for the changes
below. Python source decreased from 30,248 to 28,520 lines (1,728 net removed, 5.7%),
with two fewer Python files. Moves are excluded from that net reduction. It does not establish improved live model accuracy, cost, latency, or real OpenShell
qualification. The user explicitly allowed breaking compatibility and requested PydanticAI,
OpenAI-compatible and Bedrock inference, OpenShell, and the lightweight UI to remain.

## Review decisions

The main problem was mixed ownership and policies that confused a useful hint with a hard
contract. The branch keeps the bounded staged graph. It does not introduce a coordinator agent:
that would change the assessment strategy and require a separate quality evaluation.

- Agent definitions, datasets, release policies, and risk data remain in `agents/`.
  Shared PydanticAI construction, budgets, output contracts, and durable bindings live in
  `runtime/`; model/provider configuration lives in `inference/models.py`; repository tools
  live in `tools/`; extraction contracts live in `intake/`; sandbox policy and execution controls live
  in `sandbox/`. Imports are updated directly, without compatibility aliases.
- Build repair can continue using tools until the declared request/tool/token budgets stop it.
  The separate halfway planning cutoff and its telemetry/configuration are removed.
- Probe validation no longer scans source for language-specific skip syntax, JUnit visibility,
  or Perl plan syntax. Such scans rejected comments and alternative valid implementations.
  Output path/marker contracts remain, and observed executions constrain verdicts. Execution
  controls, isolation, egress policy, and root budgets remain deterministic.
- The environment command heuristic engine is removed. Python no longer implements a shell
  pseudo-parser to mandate runner flags, warmup strings, install directories, framework names,
  or guessed JDK compatibility. Skills provide that expertise. The single sandbox policy owns
  admissible inputs; build and positive/negative smoke controls establish executable viability.
- Zero-test diagnosis retains the model's choice between environment repair and probe repair.
  A model cannot turn marker-free, unexecuted tests into corroborated negative evidence.
- OpenAI adaptation is shared by direct inference and broker execution. One signed controller
  client handles issuance, dispatch, and closure; strict typed provenance replaces a second
  permissive parser. Broker roles remain separate because they represent credential and
  execution trust boundaries, not merely file organization. Dead inspection extension types,
  unused pricing metadata, and single-use configuration/transport helpers are removed.
- The eval trace-injection subsystem is deleted: it was restricted to a few hardcoded Python
  cases, candidate-forgeable, and explicitly not release evidence. Structural scores still
  claim no independent target attestation. Actual declared execution checks and thresholds remain.
- Recipe caching has one implementation, no unused success counter, and uses the existing
  atomic writer. A failed publication leaves the previous complete recipe intact; disabled
  caching performs no filesystem operations.

## Confirmed defects and regressions

| Defect | Repair and expectation |
| --- | --- |
| Standalone Java/JavaScript detection bypassed snapshot confinement | All entry points use the same confined file index; escaping links are rejected |
| Malformed package fields crashed discovery; descriptive prose could name a runner | Typed manifest fields are inspected; descriptions do not declare dependencies |
| Gradle Kotlin/JUnit Platform detection was inconsistent | Build-file candidates and case matching are shared |
| Cancellation could overwrite a concurrent terminal batch | Conditional database update preserves the first terminal outcome; race is forced in a regression |
| Citation validation read files inside workflow execution | Validation crosses the activity boundary; replay uses recorded activity output |
| Probe-time environment repair left the original environment in the manifest | Final and failure manifests use the actual final prepared state |
| Explicit zero cache prices were replaced by fallback prices | Only absent prices fall back; zero remains zero |
| Malformed inference containers and HTTP lengths escaped structured rejection | Invalid values fail through the existing closed broker error contract |
| Broker setup failure leaked its event loop thread | Startup and bind failures share service cleanup |

## Compatibility, provenance, and recovery

Execution generation is `v8`. Drain existing batches on their current workers before deploying
this branch: earlier workflow histories are intentionally not replay-compatible with the new
citation activities and agent behavior. This is a breaking branch with no old import shims.
Affected intake, environment-planning/repair, partial-build, probe-author, and probe-repair
specification versions are bumped. Adapter acceptance is `unit-probe-adapters/v3`; probe dataset
versions identify retirement of the diagnostic tracing feature.

Citation validation is read-only and safely retried. Its result is recorded as a Temporal
activity result rather than recomputed from mutable files during replay. Cancellation remains
idempotent and now preserves a concurrent terminal write. Manifest changes affect reporting of
the executed environment, not execution dispatch. Broker request IDs, HMAC bytes, lease state,
dispatch fences, conservative unknown-completion handling, retry ownership, and budget
reservations retain their existing contracts. No database schema or public API migration is
required.

## Validation

The first integrated pass completed with 3,380 tests passed, 24 service-qualified skips and
9 network deselections. A second pass then removed the environment heuristic engine and
unattested trace subsystem; its final gates are recorded below. Detailed local logs are under
`.harness/reports/astra-simplification/` and are not release evidence.

- `passed`: targeted repository detection (41 tests) and persistence lifecycle (13 tests).
- `passed`: focused agent autonomy, output contracts, skills, specification, and documentation
  checks (402 tests); provider/broker/OpenShell-controller focused checks (384 tests plus 18
  framing/transport tests); minimal executor image import closure and related checks (88 tests).
- `passed`: `just check` and `just generated-check`.
- `passed`: second-pass focused agent/policy/skill checks (530 tests), inference cleanup
  checks (298 then 222 tests), recipe cache checks (12 tests), and all nine isolated wheel
  install/resource-loading tests (`just test-network`).
- `passed`: `just ui-check`, including 53 UI tests and production build after refreshing the
  checkout dependencies from its lockfile.
- `not_checked`: live OpenAI-compatible/Bedrock inference, real OpenShell/runsc and egress
  qualification, live agent release-quality gates, and before/after model cost or latency.
- `not_applicable`: database/API schema migration and development-skill generation; current
  develop uses hand-maintained skills with a shared symlink rather than generated copies.

The initial full suite found six integration defects in test fixtures and the executor build
context; those were repaired before the second pass. Its full run passed 3,183 tests and found three new test expectations
using a raw output instead of the existing typed diagnostic envelope; production code was
unchanged by their correction. The UI initially lacked an already-locked
Node type dependency; `npm ci` restored it without a lockfile change.

An independent review found no additional actionable runtime issue. Seven rewritten skill
cases use synthetic recorded runner output with production evidence parsers; they do not prove
that their accompanying probe source was executed. Live quality remains unmeasured. Remaining
complexity includes skill-authored environment guidance, the staged graph, and credential
broker recovery/accounting; this branch does not claim a debt-free system or a general-purpose
autonomous investigator.
