# Harness reliability, portability, and evaluation specification

Status: **Initial implementation authorized by the user on 2026-09-29; acceptance validation in progress**
Date: 2026-09-29
Specification version: 0.4.2

Implementation scope: the initial milestone in §15.0. The user explicitly excluded live Bedrock testing for this iteration; its live acceptance remains `not_checked`. See `IMPLEMENTATION_VALIDATION.md` for the implementation and verification record.

## 1. Purpose and review boundary

Make the harness a reliable, extensible system for assessing pre-identified security findings across repositories, languages, toolchain versions, and inference providers. Establish an evaluation-driven development process, including empirical calibration of token limits and other operating parameters.

This document specifies proposed behavior, implementation boundaries, acceptance evidence, and rollout order. **MUST**, **SHOULD**, and **MAY** express requirements of the proposed design; they do not claim that the current implementation satisfies them or that this draft has been accepted.

The reviewed baseline is:

- Current harness: `6dbb09e7404c59e50c6503efc385a980816c10be`, verified against freshly fetched `origin/develop` in the root `develop` checkout. Original review: `68ac3ae998fa2f54610855b54bd3d509bbda7ef9`.
- Playbooks: `9e7fc03f2e1253be3e2adea10663ddf429646cea`, from `/Users/al/git/playbooks`.
- Reconciled all 31 commits between the original review and freshly fetched develop; §1.3 identifies delivered capabilities and remaining work. Future implementation should check for subsequent drift.
- The original review passed 710 selected tests and structural playbook validation with existing warnings/waivers. The first refresh at `f1c4b2d` passed 660 selected deterministic/component tests; the follow-up at `6dbb09e` passed 260 focused skill-eval tests. Scope and exclusions are recorded in §1.3. Structural conformance was not rerun in this refresh.
- Live provider inference, production Docker/buildx isolation, and Temporal recovery were not verified during this review. Historical measurements are not new validation evidence.

This is a proposed evolution of [the existing redesign](redesign/SPEC.md), not an instruction to replace the framework or rewrite the system. Preserve working components unless comparative evidence supports replacement. On acceptance, reconcile overlapping requirements and mark superseded decisions explicitly.

### 1.1 Goals

1. Make every verdict traceable to evidence at an identified source revision and environment.
2. Prevent missing evidence, failed execution, or unsupported environments from becoming negative exploitability conclusions.
3. Contain untrusted repository and generated probe execution, including build hooks.
4. Recover from worker, submitter, provider, and infrastructure failures without silently losing completed work.
5. Support declared language/toolchain combinations through versioned, tested adapters.
6. Support OpenAI-compatible endpoints and AWS Bedrock as first-class inference backends.
7. Use comparable, production-equivalent evals to select prompts, models, skills, budgets, and execution parameters.
8. Give Codex, Claude Code, and human contributors consistent development workflows backed by executable checks.
9. Let a new developer bootstrap and run the repository with one documented command on supported macOS and Linux hosts.
10. Provide a clean, Linear-inspired UI using shadcn/ui components, with authoritative workflow progress, evidence, agent evals, per-run telemetry, and trustworthy cross-run metrics.

### 1.2 Non-goals and deferred scope

- Discovering new vulnerabilities, generating fixes, or attacking deployed systems.
- Claiming support for every language, framework, API-compatible server, or weakness class.
- Enterprise tenancy, SSO/RBAC, organization-wide billing, compliance workflows, and consequential production actions.
- Introducing dynamic agent membership, unrestricted delegation, or additional specialist agents without a measured benefit.
- Replacing PydanticAI, Pydantic Graph, Temporal, or the existing persistence stack without a separate decision.
- Making Kubernetes a prerequisite for initial acceptance. A production-capable local Linux runner is sufficient; alternative runners need their own conformance evidence before being advertised as supported.

Deferring enterprise features does not waive applicable tool confinement, data handling, durability, provenance, or budget requirements. The project MUST describe the scope of conformance instead of claiming complete playbook conformance.

### 1.3 Reconciliation with latest develop

On 2026-09-29, fetched `origin/develop` and fast-forwarded the review worktree from `68ac3ae` to `f1c4b2d36c0e6b8654fdb45bbefea99a4b8f9b95` (30 commits). The root `develop` checkout already matched that fetched commit. The draft was preserved; no application changes were authored during reconciliation. The playbook reference remains pinned to its original reviewed revision.

The following status overrides any interpretation that all requirements below are new implementation work. Preserve the delivered capabilities and extend their contracts where necessary; implementation acceptance remains separate from source presence.

| Area | Delivered in current develop | Remaining proposal / qualification |
| --- | --- | --- |
| Packaging — DX-04 | Runtime agent specs, skills, and model catalog moved into `src/infosec_harness`; `resources.py` resolves packaged data; installed-wheel tests exist (`c735a28`) | Preserve this layout and regression suite. Do not recreate the old root-level runtime directories. Verify wheel deployment/migrations in the release environment; development-skill distribution remains separate. |
| Schema evolution — DUR-05 | Alembic revisions 0001–0003, `harness migrate`, invocation request/repeated-call persistence, experiment provenance columns, and setup documentation (`0b6f305`, `f1c4b2d`) | Extend the existing migration chain for richer records. SQLite schema/legacy-adoption checks passed in this review; PostgreSQL and installed-wheel migration acceptance remain unchecked here. |
| Eval provenance/comparison — EVAL/CAL | Incremental experiment persistence, truncated-run handling, p50/p95 latency/cost/request/tool summaries, confusion and repetition metrics, risk coverage, model/code/pricing provenance; sequential multi-model runs, comparison/results commands and committed baselines (`7e03cd8`, `f6bb250`, `c4d2ff4`) | Reuse these commands and records. Add production invocation parity, effective parameter provenance, complete attempt accounting, strict comparability, held-out selection and raw observations needed for distribution plots. Summary percentiles alone cannot reconstruct a histogram. |
| Eval cases and skills — EVAL/DX | Expanded agent datasets, deterministic runtime-skill checks, validator-convergence tests, external Vul4J harvesting and benchmark PoV masking (`e855ade`, `61b1ef7`, `1c87206`, `70542a3`, `09de53d`) | Preserve this coverage and distinguish deterministic recipe validation from live skill usefulness. Add grouped holdouts, independent ground-truth validation, real runner/provider evidence, and separate Codex/Claude development skills. |
| Environment compatibility — ENV | Better declared-JDK selection, JUnit variants, Gradle execution, JavaScript/Perl recipes, pytest handling, and a generated canary test during smoke checks (`d783e08`, `af27d15`, `00fc708`, `b7b1ac5`, `383e167`, `7c9028e`) | Extract/extend these paths rather than replace them. A canary checks runner discovery/output, not target-specific exploit evidence or sandbox containment. Preparation smoke failure still terminates outside the build-repair loop. |
| Environment reuse and recovery — SNAP/ENV | Shape-keyed recipe cache, smoke verification/eviction, cache-disabled serial corpus evaluation, bounded probe-time environment repair (`e3a88b3`, `e872a6e`) | Keep this behavior; version cache identity/policy and record cache mode in comparisons. Unify readiness repair and root accounting; a reusable recipe is not a reusable immutable source snapshot. |
| Failure transparency — DUR/EVID | Provider/infrastructure failures separated from repository failure; preparation failure carries completed invocation evidence and failed repository groups no longer necessarily sink the batch (`90187b6`, `8dbd528`) | Preparation failure containment is partially delivered. Finding-child failures can still propagate through `gather`; persistence still depends on the submitter after the workflow returns. Successful Temporal preparation invocations are not attached to returned finding outputs. Complete progress, accounting, cancellation and recovery requirements remain. |
| Evidence semantics — EVID | `neutralized` is distinct from `unreachable`, requires a named control, and continues to probing; outputs now carry context and probe executions (`7ea7617`, `e872a6e`) | Preserve these distinctions. Uncorroborated static-unreachable dismissal, directory-based prefilters, marker trust, and durable storage of the additional output evidence still require work. |
| Budget efficiency — CAL | Source-file-count budget scaling, batched repository reads/digests, request/repeated-tool telemetry, exploration measurements, and a thinking/output-budget regression invariant (`3441941`, `006b062`, `2b44af5`, `17852f2`) | Treat the scaling curve and provider output floor as measured hypotheses to calibrate, not final universal defaults. Record the exact effective limits and preserve provider constraints. Root ceilings and eval/production limit parity are still required. |
| Test isolation — DX-04 | Tests use per-process SQLite and recipe-cache paths, with cleanup | Retain this fix. Complete isolation still covers workspace/snapshot/container/service identities and concurrent development stacks. |
| UI, API and inference factory | `web/`, `api/app.py`, and `agents/models.py` have no changes across this reconciliation range; both backend families already exist in the factory | UI-01 findings remain applicable. Extend existing Bedrock/OpenAI-compatible support and acceptance tests, not a new provider implementation from scratch. |

**Measurements at `f1c4b2d` and evidence limits:** 660 selected deterministic/component tests passed against that refreshed worktree: migration/persistence, eval provenance/model comparison/report/coverage/truncation, budgets, canaries/recipes, ecosystem detection, scheduling/graph, validator convergence, runtime-skill cases, harvesting/external corpus, exploration/cache-prefix, repository tools, and validators. Runs used stub inference and process-isolated temporary state. The framework emitted missing-price warnings explaining that monetary limits cannot be enforced without calculated cost; these passes do not validate priced-provider enforcement. No paid inference, live Temporal recovery, actual sandbox containment, clean-host onboarding, rendered-browser accessibility, built-wheel installation, or PostgreSQL migration checks were performed in this refresh. The earlier 710-test result belongs to the original baseline and is not presented as a rerun of the current tree.

**Additional data gaps confirmed during reconciliation:** `EvalCaseResult` declares latency but the agent-eval insertion path does not populate it; measured per-case latency currently feeds aggregate summaries. The store computes `TriageRun.latency_s` as the sum of invocation durations, not acceptance-to-terminal wall time. `TriageRunOutput.context` and `.executions` are not included in the persisted `result` by `save_run_output`. Existing zero/default values therefore cannot be backfilled into truthful historical distributions or complete evidence. Preserve them as legacy fields and add explicit measurement semantics/availability for new records.

#### Follow-up reconciliation: `6dbb09e`

Fetched develop again and confirmed the root checkout already matched `6dbb09e7404c59e50c6503efc385a980816c10be`. This one additional commit removes obsolete Docker `COPY agents/skills/config` instructions now that resources are packaged under `src`, fixes local setup branch guidance, removes the unused sandbox task-queue setting and unused skill-validator argument, removes an old example overlay and pre-redesign research files, and ignores generated TypeScript build state and nested worktrees. It does not change the proposed architecture, provider support, evaluation/calibration requirements, UI behavior, or delivery priorities.

Credit the Docker path correction as delivered under DX-04: preserve the packaged resource layout in container builds rather than proposing this fix again. Actual container build/start and isolation acceptance remain unverified. The removed research documents and example overlay are not dependencies of this specification. No substantive requirement additions or removals are needed for this commit.

The affected `tests/test_skill_evals.py` suite passed **260 tests** with stub inference; this focused check is not a rerun of the 660-test set or live deployment validation. The previous review worktree was no longer present; its v0.4.0 draft was located in `.harness/worktree-salvage/HARNESS_EVOLUTION_SPEC.md` and restored to `docs/HARNESS_EVOLUTION_SPEC.md` with this baseline update. The salvage copy was preserved unchanged.

## 2. Playbook alignment and proposed departures

References below are paths within the pinned playbooks checkout. Portable links point to the same revision.

- **A3**: [Agent contract](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/03-agent-contract.md).
- **A4**: [Skills](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/04-skills.md).
- **A5**: [Tools](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/05-tools.md).
- **A6**: [Temporal execution](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/06-temporal-execution.md).
- **A7**: [Evaluation](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/07-evaluation.md).
- **A8**: [Observability](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/08-observability.md).
- **A9**: [Cost optimization](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/agent-playbook/09-cost-optimization.md).
- **M6**: [Durable coordination](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/multi-agent-playbook/06-durable-coordination.md).
- **M7**: [System evaluation](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/multi-agent-playbook/07-evaluation.md).
- **M9**: [System cost and capacity](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/multi-agent-playbook/09-cost-and-capacity.md).

| Requirement group | Classification | Basis or qualification |
| --- | --- | --- |
| EVID: evidence and conservative verdicts | Direct alignment plus domain extension | A3/A7 require typed, grounded outputs; exploitability criteria are harness-specific |
| SNAP: immutable and confined source access | Direct alignment plus implementation choice | A5/A7/A9 cover confinement, reproducibility, and source-version-aware caching |
| SBX: isolation and execution lifecycle | Direct alignment | A5/A6; runtime and network implementation remain harness choices |
| ENV: ecosystem adapters and compatibility matrix | Compatible extension | Implements typed capability boundaries; no playbook mandates this adapter architecture |
| INF: Bedrock and OpenAI-compatible inference | Direct alignment | A3/A7/A9 require model policies, evaluation, provenance, and bounded usage |
| DUR: durable results and bounded coordination | Direct alignment | A6/M6/M9 |
| EVAL: repeatable evaluation and release gates | Direct alignment | A7/M7 |
| CAL: empirical parameter calibration | Direct alignment plus procedural extension | A7/A9 prescribe measured optimization; the sweep format and selection procedure are new |
| DX: development skills and shared checks | Direct alignment plus distribution extension | A4/A7; cross-client packaging and repository commands are project choices |
| UI: workflow visibility, evals, telemetry, aggregate metrics | Direct alignment plus presentation extension | A7/A8/A9/M6/M7/M9; visual system, interaction patterns, and exact cohort definitions are local choices |

No core safety or durability requirement is proposed for relaxation. The following qualifications MUST remain visible:

1. **Cumulative budgets:** the playbook does not require cumulative ceilings to equal requests multiplied by per-request ceilings. Revising that harness invariant is not a playbook departure. The strictest applicable limit still governs.
2. **Budget exhaustion:** designated exhaustion tests may pass when stopping is correct. This requires a versioned change to the harness's current zero-exhaustion release policy; existing reports MUST NOT be retrospectively reinterpreted.
3. **Shared invocation:** shared configuration and accounting MUST NOT collapse a durable agent into one ordinary activity that retries its entire effectful run.
4. **Local execution:** real effectful assessments remain Temporal-hosted under A6. Stub/component tests can simulate those effects. Existing direct local execution MUST NOT be promoted as conformant production execution. General exemptions for local artifacts or short writes remain an unresolved playbook question, not an assumed waiver.
5. **Skill discovery:** this proposal uses `.agents/skills` for current Codex discovery. That differs from the pinned playbook installation guide's `.codex/skills` recommendation, and is an explicit proposed documentation correction already noted in backlog F10. Verify client compatibility before publishing the bundle.

### 2.1 Items to table for a later playbook update

| Item | Existing overlap | Treatment in this project |
| --- | --- | --- |
| A repeatable calibration protocol, including effective settings and held-out validation | A7/A9 establish principles but not this complete procedure | Specify locally; generalize after practical validation |
| Expected budget exhaustion versus enforcement failure | Budget and hard-gate wording needs a worked example | Use explicit case expectations and separate metrics |
| Observations, assertions, corroborated claims, and accepted decisions | Opinion backlog OP-005 | Use a local evidence taxonomy; do not claim types prove truth |
| Immutable release identity when providers expose mutable aliases | OP-007 | Record provider identifiers and observed metadata; document replay limits |
| Cross-client development-skill packaging and compatibility | Implementation backlog F10 | Keep canonical sources, pinned references, and discovery checks |
| Release-bound provenance and integrated readiness status | Implementation backlog F09/F03 | Validate exact report identity and distinguish passed/failed/not-checked |
| Clarification of effectful local eval execution and recovery units | OP-001 and implementation backlog F06 | Keep the current Temporal boundary; defer exceptions |

See the pinned [opinion backlog](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/backlog/opinions-worth-revisiting.md) and [implementation backlog](https://github.com/X-McKay/playbooks/blob/9e7fc03f2e1253be3e2adea10663ddf429646cea/backlog/implementation-changes.md). Open backlog entries do not amend the standard. No playbook edits are part of this specification's implementation scope.

## 3. Architectural direction

Keep deterministic orchestration around typed agent contributions:

```text
Submission -> source resolution -> immutable snapshot -> component discovery
                                                    -> assessment routing
                                                    -> environment preparation/cache
                                                    -> bounded agent + probe execution
                                                    -> evidence validation -> verdict
Every stage -> durable events, usage accounting, and evidence references

Eval execution uses the same resolved contracts and execution components.
```

The implementation SHOULD establish the following boundaries by extracting existing behavior incrementally, not by introducing a new general-purpose agent framework:

| Boundary | Responsibility |
| --- | --- |
| Source service | Resolve revisions, materialize immutable snapshots, validate paths and leases |
| Ecosystem adapter | Discover components, resolve toolchains, prepare dependencies, select tests, parse results |
| Execution backend | Build and run under verified isolation; stream bounded output; cancel and clean up |
| Inference resolver | Resolve policies to backend/model/capabilities/effective settings |
| Invocation accounting | Apply limits, capture all attempts, preserve usage and outcome metadata |
| Orchestrator | Route, reserve budgets, own repair decisions, enforce deadlines, persist progress |
| Evidence service | Store content-addressed artifacts and validate provenance and references |
| Evaluation service | Execute frozen experiments, score claims, compare baselines, apply release policy |

### 3.1 Proposed domain records

These are conceptual contracts, not an executable schema. Each implemented record needs a versioned Pydantic model and migration rules where persisted.

| Record | Required information |
| --- | --- |
| `RunManifest` | Harness build/commit and dirty-state identity; graph/agent/policy versions; model routing; effective settings; skill/tool/evaluator hashes; dataset/environment identities |
| `SourceIdentity` | Input mode, normalized repository identity, requested revision, resolved commit when applicable, content digest, submodule/LFS policy |
| `ComponentProfile` | Component root, language(s), manifest/lockfile paths, declared version constraints, build/test frameworks, dependency relationships |
| `EnvironmentPlan` | Adapter/version, target component, exact toolchain resolution, base image digest, dependency preparation, test selector, network/resource policy, scope limitations |
| `InvocationRecord` | Run/member/attempt IDs, effective config digest, provider request metadata when available, usage status, tokens, cost basis, timing, tool events, failure class |
| `ExecutionRecord` | Stable operation ID, environment/probe digests, command/selector identity, discovered/executed tests, structured observations, exit/timeout/cancellation, artifacts |
| `EvidenceBundle` | Source and manifest identity; citations; environment/build/probe records; claims and supporting observations; limitations and verdict rationale |
| `ExperimentReport` | Subject and manifest identities, dataset/split/evaluator hashes, planned/completed counts, per-case attempts, metrics/uncertainty, hard-gate status, comparison eligibility |

Secrets MUST NOT be embedded in these records or Temporal history. Redacted endpoint/configuration identities must still distinguish materially different execution configurations.

## 4. Evidence and verdict semantics — EVID

### EVID-01: Separate execution status from security judgment

Preserve the existing `neutralized` reachability state and its requirement to name the control and continue probing. Do not collapse it back into `unreachable`. Retain the three public verdict labels during initial migration. Add explicit assessment status and evidence basis, rather than inventing a security conclusion for every terminal state.

| Situation | Proposed behavior |
| --- | --- |
| Independently supported exploit condition observed | `potentially_exploitable`, with evidence and assessed scope |
| Valid negative experiment with required controls and coverage | `likely_not_exploitable`, explicitly limited to tested conditions |
| Corroborated static unreachability under the configured policy | `likely_not_exploitable`, with a distinct static evidence basis |
| Unsupported toolchain/strategy, missing source, infrastructure failure, insufficient evidence | `inconclusive`, with a precise reason |
| Scope policy excludes the finding | Mark `out_of_scope`; if a legacy verdict is required, use `inconclusive`, not a safety claim |

Directory names such as `vendor`, `tests`, or `examples` MUST NOT alone establish that code is unshipped or unexploitable. A valid negative proves only the supported claim under the stated conditions, not absence of every possible exploit.

### EVID-02: Validate references and preserve uncertainty

- Code references MUST resolve inside the immutable snapshot and identify existing line ranges and source digests.
- Distinguish model assertions from execution observations and independently corroborated evidence.
- A populated citation field MUST NOT be treated as proof that the cited code establishes the claim.
- The proposed default is to disable uncorroborated context-only dismissal. Static dismissal requires a documented criterion and validated supporting evidence; otherwise continue assessment or return inconclusive.
- Conflicting evidence MUST be retained and resolved by explicit policy. Model confidence alone cannot override contradictory observations.
- Infrastructure failure MUST NOT automatically lower a critical finding to the lowest priority. Separate security priority, assessment confidence, and operational retry priority.

### EVID-03: Strengthen probe evidence

Replace permissive marker-substring matching with a versioned result protocol. Record execution identity, probe digest, exact test selection, discovered/executed counts, precondition observation, sink completion or expected rejection, and oracle result.

Parsing an event does not make it trustworthy: generated probes and target code can print arbitrary strings. Each assessment adapter MUST state which observations are self-reported and which are independently collected. Use positive controls, benign controls, target binding, and independent filesystem/process/service observations where applicable. Nonces correlate events; they do not authenticate exploitability.

Keep a legacy marker adapter during migration, clearly identifying its weaker evidence level. Echoed source, compiler diagnostics, unrelated tests, swallowed exceptions, zero-test runs, and missing/truncated output MUST NOT silently satisfy a stronger evidence contract.

**Acceptance:** regressions cover shipped vendored code, misleading paths, fabricated citations, reachable code with partial sanitization, marker echoes, zero-test runs, conflicting signals, and failed execution. No unsupported negative verdict may pass the critical regression suite.

## 5. Source identity, confinement, and caches — SNAP

### SNAP-01: Explicit source modes

- `git_revision`: resolve local or remote Git input to a commit before assessment. Do not substitute the current local working directory for a requested revision.
- `working_snapshot`: explicitly capture local working content, including a digest and dirty-state provenance. Do not describe it as assessment of a commit it does not match.
- Define explicit handling of submodules, LFS, generated sources, ignored files, and dependency directories. A blanket exclusion by directory name must not silently remove relevant code.

### SNAP-02: Immutable materialization

Materialize in a temporary location and publish atomically after validation. A completed snapshot MUST NOT be overwritten in place. Concurrent requests for the same identity should share immutable data or coordinate materialization; mutable branches must first resolve to commits.

Hash file types, normalized paths, contents, executable modes, and validated link targets with unambiguous serialization. Do not follow links outside the approved root while copying, hashing, scanning, or reading. Reject unsupported special files. Apply limits on file count, individual/total bytes, clone time, and traversal work.

### SNAP-03: One repository-access boundary

All repository tools, location resolution, stack detection, and build-context assembly MUST use consistent confinement rules. Reject absolute/traversal escapes, outside-root symlinks, and invalid ranges. Permit internal symlinks only under a tested policy. Search needs bounded work and protection against pathological regular expressions; line limits do not replace byte limits.

### SNAP-04: Cache validity and lifecycle

Extend the existing shape-keyed recipe cache in `persistence/recipes.py`; retain build/smoke revalidation and eviction. Distinguish recipe reuse, prepared-image reuse, and source identity. Include benchmark exclusion/masking policy in snapshot identity before materialization: masking currently affects the final content hash but not the mutable destination key. Record cold/warm/cache-disabled execution in experiment provenance.

Prepared-environment keys MUST include source digest, component, resolved toolchain/base-image digest, plan/dependency identities, adapter version, and relevant policy/configuration identity. Store resolved dependency information; flag non-reproducible resolution explicitly.

Use leases for snapshots/images used by active runs. Garbage collection MUST NOT evict active resources. Cache hits must still satisfy the current isolation policy. Cache corruption, missing images, or expired compatibility evidence should cause rebuilding or an explicit failure, not a misleading ready state.

**Acceptance:** two concurrent runs cannot replace one another's snapshot; nonexistent local revisions fail; external links never enter the snapshot; content/mode/toolchain/policy changes invalidate relevant cache entries; active resources survive cleanup.

## 6. Sandbox and execution lifecycle — SBX

### SBX-01: Verify the execution boundary

Builds and probes execute untrusted code. The runner MUST verify the actual selected build executor and probe runtime against the declared policy. Merely finding a runtime name in daemon configuration is insufficient. Missing required isolation fails closed.

Use non-root execution, resource limits, minimal privileges, isolated writable areas, and no host credentials or daemon socket inside target workloads. Generated build instructions MUST be structurally validated; model strings must not inject new Dockerfile directives or alter the prescribed security context.

### SBX-02: Enforce networking outside process environment variables

- Build traffic may reach policy-approved dependency services through an enforced boundary.
- Repository registry declarations are requests, not permission to widen egress.
- Direct connections, proxy bypass, alternate protocols, redirects, and resolved private/metadata destinations must be covered by the policy and denial tests.
- Unit probes have no external network. Loopback fixtures are allowed within the sandbox.
- Future multi-service strategies may use an isolated, explicitly declared internal network with denied external egress.
- Diagnostic sandbox-shell calls obey the same applicable policy as build/probe execution.

### SBX-03: Own the full operation lifecycle

Assign stable operation IDs and persist enough state to reconcile retries. A deterministic container name alone does not provide idempotency. On retry, discover whether the operation is active, completed, or lost before starting another execution.

Cancellation and timeout MUST terminate the actual workload, collect bounded diagnostic evidence, and release or quarantine resources. Handle worker loss with leases and reconciliation. Stream stdout/stderr through byte-bounded buffers and artifact storage; preserve structured observations independently from human-readable log tails.

**Acceptance:** real-runner tests establish build/probe isolation, network denials, resource exhaustion behavior, output flooding bounds, actual workload termination, orphan cleanup, duplicate delivery behavior, and fail-closed startup. Docker command-shape tests alone cannot clear these gates.

## 7. Ecosystem adapters and assessment strategies — ENV

### ENV-01: Discover components before choosing an environment

Represent repositories as components with manifest paths and dependency relationships. Do not collapse a polyglot repository into one language and one framework. Resolve a finding to its owning component, with uncertainty represented explicitly.

Separate repository-wide discovery from component-specific preparation. Share preparation only when findings require the same compatible environment. A partial-build plan MUST identify the finding/component it serves and retain limitations introduced by omitted components or substituted dependencies. Substituting a dependency on the path under assessment can invalidate the experiment and must not yield an unrestricted negative verdict.

### ENV-02: Versioned adapter contract

Each adapter MUST provide or explicitly decline:

1. Component and manifest discovery.
2. Toolchain constraints and resolution using repository declarations, wrappers, lockfiles, and tested compatibility data.
3. A typed preparation plan, including dependencies and resource/network requirements.
4. An offline readiness check using the same filesystem layout and runtime conditions as the actual probe.
5. A test selector and injection location appropriate to the native framework.
6. Structured parsing of discovery, execution, failures, and oracle observations.
7. Failure classification and supported repair actions.
8. A compatibility declaration with fixtures and evaluation evidence.

Agents MAY propose environment changes within these contracts. Deterministic code MUST validate them. Global rules must not require all JVM projects to adopt one JUnit/Surefire version or replace a project's framework merely to fit a known fixture.

Start by extracting and verifying the currently supported Python, Java, JavaScript, and Perl paths. Additional languages are admitted incrementally through the same contract. A detected language is not automatically a supported assessment environment.

### ENV-03: Compatibility matrix

Track support by language/runtime, build/package-manager version, test framework/version, OS/architecture, dependency mode, repository layout, and assessment strategy. Use explicit states: `tested`, `experimental`, `unsupported`, and `not_checked`.

Representative matrix dimensions include Python packaging/import layouts; JVM versions, wrappers, JUnit variants and multi-module builds; JavaScript/TypeScript module systems, package managers and workspaces; Perl versions and dependency layouts. Exact supported version ranges are review decisions informed by target repositories and fixtures, not claims made by this draft.

Each supported slice needs at least a working positive/negative pair and environment-failure evidence. Expand with native dependencies, generated code, incompatible locks, offline caches, private registry failures, and large repositories. Avoid treating a full Cartesian product as necessary; use risk-based combinations and report uncovered slices.

### ENV-04: Repair the failing layer

Preserve the existing generated-canary smoke check and `RepairEnvironment` probe-time branch. Close the remaining preparation-stage gap: smoke is currently checked after the build-repair loop, so a failed canary ends preparation instead of returning to repair. Build and readiness checks form one bounded preparation state machine. A missing test runner or offline dependency discovered during readiness returns to environment repair within the shared preparation budget.

At probe time, distinguish probe defects, environment defects, unsupported capability, target rejection, infrastructure failure, and valid observations. Route environment defects back to bounded environment repair when safe, then invalidate/rebuild the environment and rerun the probe. Detect repeated equivalent plans and no-progress loops.

### ENV-05: Additional strategies

Keep unit probes as the initial supported strategy. Define extension points for static analysis, integration tests, local HTTP/service fixtures, property-based tests, differential execution, and browser-based checks. Each strategy needs its own threat boundary, evidence contract, fixtures, resource budget, and acceptance suite before activation.

Static strategies may avoid a build when their evidence contract is sufficient. Unsupported strategies produce an explicit inconclusive result; models cannot enable unregistered tools or networking to work around that limitation.

**Acceptance:** demonstrate two affected components with different toolchains in one repository; correct version/framework selection; a readiness failure repaired at the environment layer; bounded no-progress handling; explicit unsupported results; and reproducible offline execution for every declared supported slice.

## 8. Inference backend contract — INF

### INF-01: Two first-class backend families

The harness MUST support:

- **OpenAI-compatible inference**, including the current locally hosted model endpoint. Initially retain the supported chat-completions path; do not imply every OpenAI API feature is required or available.
- **AWS Bedrock inference**, through the supported PydanticAI Bedrock integration and an explicit region/model or inference-profile configuration.

Backend choice is configurable globally and per agent. Agent prompts and workflow control flow MUST NOT encode backend-specific transport logic. A logical policy resolves to an admitted backend/model configuration with a recorded version.

Prefer supported framework integrations. Keep necessary compatibility adaptations small, independently tested, and bound to explicit profiles instead of silently applying them to every endpoint.

### INF-02: Resolve and validate capabilities

Maintain a tested capability profile for each backend/model combination:

| Capability | Required handling |
| --- | --- |
| Structured output | Record supported mechanism and validate returned types identically across providers |
| Tool calling | Verify argument encoding, tool-result handling, repeated calls, and multi-step behavior |
| Message layout | Apply declared adaptations, such as system-message merging, with equivalence tests |
| Reasoning controls | Map supported settings explicitly; identify whether reasoning consumes the output allowance |
| Token limits | Record context/output constraints, requested values, provider floors, and effective values |
| Usage and pricing | Identify observed, estimated, unavailable, and known-zero values separately |
| Prompt caching | Record support and actual cache usage; unsupported caching is not a failed quality result |
| Timeouts/retries | Use bounded policies with combined attempt accounting and permanent-error classification |
| Cancellation | Record whether a request was cancelled locally and whether remote work/billing is unknown |

Unsupported required capabilities fail preflight. Optional adaptations require a declared policy and appear in provenance. Do not silently drop an unsupported reasoning setting or silently raise a token limit without recording it. An OpenAI-compatible URL alone is not evidence of capability parity.

### INF-03: Effective configuration and credentials

Construct an immutable resolved configuration before a run: policy version, backend identity, requested/resolved model identifiers, capability profile, effective model settings, usage limits, price-table version, retry policy, and fallback policy.

The digest MUST reflect effective settings after overlays and backend adjustments. The same digest accompanies production runs and eval reports. Resolve credentials in worker/activity context, using environment/secret references for compatible endpoints and configured AWS credential mechanisms for Bedrock. Secrets never enter prompts, reports, artifacts, or workflow history.

Provider aliases may remain mutable. Record the provider's exposed revision metadata when available and state when an exact model snapshot cannot be guaranteed. Do not imply that identical configuration guarantees identical stochastic output.

### INF-04: Explicit fallback and routing

Fallback is disabled unless configured. An allowed fallback chain MUST specify admitted models/backends, triggering error or quality signals, data-handling restrictions, maximum attempts, and remaining-budget behavior. Record every attempted route, failure, usage, and final model.

Authentication errors, invalid requests, and policy failures are not reasons to try arbitrary alternate providers. Fallback chains must be evaluated as chains; comparing a candidate that used fallback with a baseline that did not must be explicit.

### INF-05: Acceptance for both backends

Both backend families MUST pass common contract tests and live smoke tests covering typed outputs, tool calls, skill use where applicable, semantic correction, usage accounting, limit enforcement, timeout/permanent-error handling, and representative end-to-end assessments. Provider fault cases may use controlled transport simulation where live faults are impractical; label that evidence.

Maintain provider-specific calibration profiles. The same budget values need not be optimal for Bedrock and the locally hosted model. Missing credentials or an unavailable provider produces `not_checked`, never an inferred pass. A dual-backend release requires fresh evidence for both supported profiles; a deliberately narrower release must state its supported scope.

## 9. Durable orchestration, results, and budgets — DUR

### DUR-01: Submission and terminal state

The API SHOULD return a batch identifier after durable acceptance, without waiting for assessment completion. Use typed status endpoints/events for progress, results, and cancellation. Persist acceptance and workflow-start intent through an idempotent protocol with reconciliation, so a crash between database write and workflow start cannot strand a batch indefinitely.

Each finding reaches a durable terminal state independently. Persist outputs inside activity-backed workflow execution, not solely after the submitting process receives the complete batch result. A failed finding or repository MUST NOT discard successful unrelated results.

Terminal status distinguishes completion, inconclusive assessment, unsupported scope, cancellation, and infrastructure failure. A batch exposes expected, completed, failed, cancelled, and pending counts. Duplicate inputs receive a documented deduplication or distinct-submission policy; they must not accidentally collide on child workflow IDs.

### DUR-02: Preparation sharing

Use immutable preparation identities and an explicit cache/coordination protocol. Independent workflow chains MUST NOT reuse a workflow ID as an implicit cache. Concurrent requests can join a documented preparation operation or reuse its validated durable result. Failed and stale preparations have explicit retry/invalidation behavior.

### DUR-03: Recovery boundaries

Keep durable agents workflow-hosted. Model calls, tools, filesystem/network work, database operations, and artifact writes execute as activities. Pin run configuration through serialized identity and replay-compatible execution; do not read mutable configuration to alter decisions during replay.

Specify activity start-to-close and schedule-to-close bounds, retry ownership, permanent failures, heartbeat behavior, and cancellation. Compute combined retry bounds across semantic correction, provider transport, activity retry, repair loops, and fallback.

Add stable idempotency records for persisted results and execution operations. Reconcile operations that may have completed before activity acknowledgment. Completed partial work remains accessible after worker loss or cancellation.

### DUR-04: Root and child budgets

Enforce a root budget for requests, tokens, tool calls, agent runs, execution resources, cost, and elapsed time, plus applicable member/operation limits. Before dispatch, reserve bounded capacity from the parent; reconcile consumption and release unused reservations at durable terminal states.

Unknown usage cannot silently return to the available pool. Provider responses may reveal actual token/cost consumption only after a request; reserve conservatively, reconcile overshoot, stop new dispatch, and report uncertainty. No hard billing guarantee should be claimed where the provider cannot support one.

Use a durable accounting mechanism compatible with worker restart and concurrent children. Prefer supported framework budget facilities when they meet the contract; add only the necessary reservation/reconciliation integration. Concurrency, queue age, and admission limits are separate from token or dollar budgets.

### DUR-05: Persistence and artifacts

Extend the existing packaged Alembic migration chain (0001–0003 at this baseline) and `harness migrate`; do not introduce a second migration system. Retain fresh-schema, legacy-adoption, metadata-parity and downgrade tests, and add target-database acceptance. `create_all` remains a bootstrap facility, not an upgrade path. Store large artifacts outside Temporal history using digest-verified references. Define retention, deletion, and missing-artifact behavior; a deleted evidence bundle can no longer support a reproducibility claim.

Persist preparation invocations, all probe executions, failed attempts, effective configuration, evidence references, and ordered tool/skill events. Report preparation cost once, with a separate documented amortization view for per-finding comparisons. Full batch cost must equal accounted preparation plus finding work without double counting.

**Acceptance:** saved-history replay; worker loss before/after external effects; duplicate delivery; submitter loss; concurrent preparation; sibling failure; cancellation during build/model/probe work; bounded history; durable budget reservations; idempotent persistence; and database migration/rollback compatibility tests.

## 10. Evaluation architecture and release evidence — EVAL

### EVAL-01: Production-equivalent execution

Close the verified invocation gap: `evals/run.py` still calls `built.run(prompt, deps=deps)` without the `usage_limits` supplied by LocalOps/TemporalOps. Introduce shared invocation configuration, validation, accounting, and outcome handling used by LocalOps, TemporalOps, and eval adapters. Eval runs MUST apply the same effective usage limits and relevant timeouts as the production configuration being assessed.

Component tests may use controlled models/tools; their reports identify the substituted boundaries. Behavioral release claims require live-model evidence, and execution/isolation claims require the real runner. Full effectful acceptance runs use Temporal. Stub success is infrastructure evidence, not model-quality evidence.

### EVAL-02: Dataset and evaluator contracts

Build on the expanded packaged agent datasets, `evals/coverage.py`, runtime-skill evals, validator-convergence tests and external corpus harvesting. Preserve benchmark PoV masking, and verify that excluded ground-truth artifacts remain unavailable through alternate paths or cache reuse. Each case has a stable ID, dataset version, provenance, risk/claim tags, language/environment slices, expected invariants, permitted variation, and required execution path. Labels used for scoring MUST NOT leak into prompts, repository paths exposed as clues, or runtime skills.

Use separate development/calibration and held-out evaluation sets. Split related repositories, vulnerable/fixed variants, and near-duplicates as groups to reduce leakage. Independently validate ground truth; do not edit expected results merely to make a change pass.

Required suites:

- Contract and deterministic policy tests.
- Agent/component behavior, including tool/skill selection and negative activation.
- Build and runner compatibility.
- End-to-end evidence-supported outcomes.
- Adversarial repository content and prompt-injection propagation.
- Durability, retries, cancellation, replay, and budget exhaustion.
- Historical regressions and larger realistic repositories.
- Provider/model compatibility and cross-provider comparisons.

Prefer deterministic assertions for enforceable properties and execution-based scoring for build/probe claims. Substring presence is only a structural check. Any model judge needs a versioned rubric, calibration evidence, and limited scope; it cannot be the sole grader of isolation, authorization, idempotency, or budgets.

### EVAL-03: Required measurements

| Metric group | Required distinctions |
| --- | --- |
| Outcome | Correct evidence-supported outcomes, false positives, false dismissals, inconclusive/unsupported rates |
| Coverage | Planned/completed cases, required branches, build/probe completion, material risk scenarios covered/uncovered |
| Evidence | Citation validity, target execution, oracle/control validity, unsupported conclusions |
| Behavior | Tool arguments/results, successful skill loads, procedure adherence, redundant calls, repair effectiveness |
| Resources | Per-request and cumulative tokens, reasoning/cache tokens where exposed, requests, tools, retries, compaction, execution resources |
| Operations | End-to-end and stage latency, queue time, cancellation/recovery outcome, failure categories |
| Cost | Known/estimated/unknown values, failed work, preparation, cost per correct supported outcome |

Define a **false dismissal** as a ground-truth exploitable case labeled `likely_not_exploitable`. Report exploitable cases returning inconclusive separately. This prevents an honest abstention from being confused with a safety claim while still measuring failure to complete the task.

Every rate declares its denominator. Report macro and case-weighted aggregates where useful, per-slice counts, distributions, and uncertainty. A perfect score on a tiny slice is not proof of broad support.

### EVAL-04: Report integrity

Extend the existing incremental experiment store, distribution/coverage reports, pricing/code provenance, and `evals/baselines` records. Preserve rejection of dirty/truncated baseline saves. Existing comparison warnings are not yet strict comparability enforcement; existing failure branches still assign zero cost and cannot establish complete usage. Capture source/configuration identity before execution, write incrementally to a unique experiment, and atomically publish the final report. Record `running`, `complete`, `truncated`, `cancelled`, or `failed`; retain all completed attempts and partial usage.

Comparisons MUST reject incompatible subjects, case sets, evaluator versions, or incomplete coverage unless the user explicitly requests a descriptive non-equivalent comparison. Such output cannot clear release gates. Validate finite numeric values, schema versions, nonempty required coverage, and planned-versus-completed counts. Unknown cost remains null with an explanation, never zero.

### EVAL-05: Release gates

Hard gates include evidence-contract compliance, confinement, output validity under the case contract, enforced limits, safe failure handling, idempotency, replay, and zero known critical regression failures. Expected denial/error cases pass only by producing their specified safe outcome. Weighted quality cannot compensate for a hard-gate failure or missing required evidence.

Graded gates include supported-workload success, false-dismissal/false-positive thresholds, abstention, build/probe rates, latency, and cost. Thresholds and minimum sample/repetition requirements must be declared before the comparison. Their exact values are an approval item after a credible baseline exists; do not copy arbitrary starter thresholds and call them calibrated.

CI tiers:

1. PR: deterministic/component tests, generated-artifact checks, focused regressions, provider contract simulations, and changed-area smoke evidence.
2. Protected integration: real sandbox compatibility and Temporal failure/replay suites.
3. Behavioral release: repeated live-model agent and system evals against the supported backend profiles and held-out cases.
4. Periodic checks: provider drift, larger corpora, and reviewed operational failures promoted into regression cases.

Unavailable infrastructure is `not_checked`; it blocks the affected release claim without being mislabeled a model failure. Pin playbook tooling used by CI. Structural conformance and behavioral readiness are separate results.

### EVAL-06: Composition benefit

Compare the current agent graph with a simpler agent using equivalent tools, evidence, permissions, and verdict constraints. Run targeted ablations before retaining or adding optional stages. Evaluate safety, task success, cost, latency, and operational complexity. Removing a stage is acceptable only when its required invariants remain enforced and the comparison supports the change.

**Acceptance:** a deliberately wrong verdict, absent metric, stale report, unpriced model, incomplete run, irrelevant tool call, non-executing probe, or incompatible baseline cannot silently produce passing release evidence. Reports identify the failed claim, case, execution, configuration, and blocking policy.

## 11. Empirical parameter calibration — CAL

### CAL-01: Parameters in scope

Use the existing sequential `harness eval run <agent> --model <tier> --model <tier>` workflow and overlays as the starting point. Extend it for bounded parameter trials rather than building a separate experiment engine. Include the current repository-size policy in calibration: baseline 16 source files, growth 0.25 per doubling, and maximum factor 3.0. These are implementation constants to evaluate across realistic repository-size slices, not accepted tuned defaults. Record source-file measurement, formula/version, requested limits, rounding, effective scaled limits, provider output floor, and binding root ceiling for every trial. Evaluate batched tool/context strategies before concluding that higher budgets are the best fix.

Calibration MUST support agent-specific and backend/model-specific overlays for:

- Per-request input limits and output allowances.
- Cumulative input/output tokens and request/tool-call ceilings.
- Reasoning settings supported by the model.
- Compaction/trimming thresholds and retained evidence policy.
- Tool result byte/context bounds.
- Agent/provider/activity timeouts within valid timeout nesting.
- Build/probe repair budgets and no-progress thresholds.
- Concurrency and explicit fallback policies in later controlled experiments.

Safety permissions, mandatory evidence requirements, and isolation controls are not optimization variables that can be weakened to improve a score. Per-agent settings remain constrained by root budgets and provider limits.

### CAL-02: Operating budgets and hard ceilings

Use empirically selected operating limits beneath deployment safety ceilings. Both are enforced. A cumulative token limit may intentionally be lower than the sum of all theoretical per-request maxima; the resulting early-stop behavior must be evaluated and documented.

Replace tests that encode one arbitrary numerical policy with tests of wiring, valid constraints, effective values, stopping behavior, and approved configuration identity. Preserve meaningful provider constraints and budget arithmetic; do not turn tuning into an exemption from enforcement.

Separate metrics:

- `budget_enforcement_violations`: continuing/dispatched work contrary to the applicable enforced policy; hard gate zero.
- `expected_budget_stops`: designated adversarial/limit cases ending safely; evaluated against their expected outcome.
- `unexpected_budget_stops`: supported workloads cut short; quality metric with an explicit threshold.
- `usage_unknown` and `cost_unknown`: unresolved accounting; cannot be treated as free execution.

A provider response can cross a post-response token/spend threshold. Record that event separately from a failure to stop subsequent work, consistent with A9's billing caveat. The current zero-exhaustion policy remains authoritative until a versioned replacement is reviewed.

### CAL-03: Experiment lifecycle

1. **State the hypothesis.** Identify the affected agents, workload slices, parameter, expected benefit, risks, and blocking metrics.
2. **Freeze the baseline.** Pin source/configuration, provider profile, datasets, evaluator versions, preparation-cache conditions, and pricing basis.
3. **Collect complete traces.** Include successful, failed, retried, timed-out, and budget-stopped attempts. Where usage is unavailable, preserve uncertainty and comparison limitations.
4. **Choose candidate ranges.** Use observed per-request/context-growth distributions as starting evidence, not final limits. Validate candidates against provider and deployment constraints.
5. **Run paired repeated trials.** Use the same case groups and declared repetitions, randomizing/interleaving order where practical to reduce load/time bias. Record cold/warm cache conditions separately.
6. **Inspect case-level regressions.** Identify which failure modes increased, rather than selecting on aggregate accuracy or average cost alone.
7. **Explore interactions.** After single-variable experiments, use a declared factorial or staged design for coupled parameters such as compaction × input ceiling × request count. Limit search using an experiment-level spend/deadline budget.
8. **Select admissible candidates.** First reject hard-gate failures and unacceptable slice regressions. Then compare the remaining quality/cost/latency frontier.
9. **Validate on held-out cases.** Run the chosen candidate through end-to-end and durability checks, including both supported provider profiles when applicable.
10. **Propose promotion.** Produce a configuration diff, version changes, report references, limitations, rollback target, and monitoring criteria. Experiment code never silently overwrites the production baseline.

Fixed-trace replay can estimate how often a limit would have fired, but cannot establish quality after that limit changes agent behavior. Actual reruns are required before promotion. If a backend floor causes several requested token values to resolve identically, mark them as the same effective candidate rather than claiming distinct trials.

### CAL-04: Selection and statistical discipline

Optimize cost or latency per correct, evidence-supported outcome subject to quality and safety constraints. Track absolute spend as well; a candidate that answers almost nothing must not look efficient by excluding failed work.

Reports MUST show per-slice and worst-case behavior, sample sizes, repeated-run variability, and confidence intervals appropriate to the sampling unit. Repeated runs of one repository do not create independent repository coverage. Predeclare stopping and selection rules, limit repeated peeking, and use held-out confirmation to reduce selection bias from large sweeps.

For a self-hosted endpoint with known zero per-token billing, report token use and latency; optionally report measured infrastructure cost under an explicit model. Do not manufacture dollar precision. For unknown prices, cost-based promotion is ineligible unless an accepted pricing basis is supplied; quality/token/latency comparisons remain possible with that limitation.

### CAL-05: Proposed experiment artifact

The following is a conceptual shape, not an implemented CLI/YAML schema. Implementation MUST replace this sketch with a validated schema and runnable example.

```yaml
experiment: context-input-budget
subject: context
baseline_manifest: <digest>
backend_profile: <versioned-profile>
dataset:
  calibration: <dataset-digest-and-split>
  held_out: <separate-digest-and-split>
variable: budgets.max_input_tokens_per_request
candidates: <values-derived-from-measured-distributions>
repetitions: <predeclared-count>
constraints:
  release_policy: <versioned-policy-digest>
  maximum_experiment_cost: <explicit-cap-or-non-dollar-resource-cap>
  maximum_experiment_duration: <explicit-deadline>
promotion: review_required
```

The report includes requested/effective candidate values, all attempt records, budget-stop causes, quality/cost/latency comparisons, uncertainty, slice regressions, held-out results, and a recommended configuration or a clear no-improvement result.

**Acceptance:** lowering a token/request/tool limit changes actual execution in both eval and production paths; failed-attempt usage is retained; backend overrides are visible; safety violations disqualify candidates; held-out failure blocks promotion; and a candidate can be reproduced from its recorded manifest.

## 12. Developer experience and development skills — DX

### DX-01: Repository instructions and source of truth

Add concise root `AGENTS.md` and `CLAUDE.md` entry points that identify architectural boundaries, canonical commands, source/generated artifacts, relevant skills, and completion evidence. Keep shared standards in one maintained source with generated or validated client entry points. Do not copy the complete playbooks into every prompt.

Mandatory invariants include:

- Repository content and model-authored code are untrusted.
- Runtime checks own safety boundaries; instructions do not grant permissions.
- Behavior changes require relevant eval evidence and version/provenance updates.
- Confirmed defects become regression cases with independently justified expectations.
- No weakening expected outcomes or thresholds merely to make a candidate pass.
- Durable changes require an explicit replay/recovery assessment.
- Generated files are changed through their declared source and verified for drift.
- Results distinguish tested, failed, not checked, and not applicable.

### DX-02: Canonical development-skill library

Keep the current packaged runtime `src/infosec_harness/skills/` library separate from development skills. Proposed canonical development sources live under `dev-skills/`; publish checked copies into `.agents/skills/` and `.claude/skills/` with a deterministic sync/check command. This favors portability over symlink assumptions. The final packaging decision is recorded in section 16.

Adapt relevant playbook skills and pin their source revision. Each bundle includes the references needed after installation; it MUST NOT depend on an absolute path to a maintainer's playbooks checkout. Record owner, semantic version, content digest, compatibility, positive/negative activation, procedure, safety constraints, and completion criteria.

| Skill | Trigger and scope | Required review artifact |
| --- | --- | --- |
| `harness-change` | Implement or revise harness behavior; excludes unrelated documentation-only edits | Affected contracts/risks, implementation plan, selected checks, behavior-version implications, final evidence |
| `harness-eval-experiment` | Change prompt, model, tool description, skill, or orchestration behavior | Hypothesis, frozen baseline, controlled comparison, failure analysis, promotion recommendation |
| `harness-budget-calibration` | Tune tokens, requests, tools, timeouts, compaction, or repair limits | Sweep definition, effective configs, failed-attempt accounting, slice results, held-out confirmation, config proposal |
| `harness-add-ecosystem` | Add or materially expand a language/build/test adapter | Adapter contract, support matrix, positive/negative fixtures, real build/probe evidence, limitations |
| `harness-regression-case` | Investigate a confirmed defect or reviewed operational failure | Sanitized reproducer, ground-truth rationale, violated invariant, case tags, failure-before/fix-after evidence |
| `harness-durability-review` | Change workflow topology, activities, side effects, identities, retries, or persistence | Retry/idempotency analysis, history compatibility, cancellation/recovery scenarios, rollout constraints |

A skill does not enforce CI policy or authorize spending. It invokes the approved commands and produces review artifacts. Expensive live experiments need an explicit experiment budget and the caller's authorized scope. Skill automation must not silently promote configurations, broaden sandbox access, or rewrite golden labels.

Evaluate the development skills with positive, negative, and ambiguous trigger cases and representative maintenance tasks. Score procedure adherence, selected checks, patch correctness, preservation of unrelated changes, and quality of the evidence report. Evaluate runtime skills separately for useful activation and behavior, not load count alone.

The proposed Codex location follows [current discovery documentation](https://learn.chatgpt.com/docs/build-skills); Claude's repository location follows [Claude Code skills documentation](https://code.claude.com/docs/en/skills). Revalidate host conventions when implementing distribution, and record the explicit difference from the pinned playbook guide.

### DX-03: Proposed command surface

This table combines existing commands with proposed extensions; it does not claim that all entries exist. Current develop already provides `harness migrate`, `harness eval run` with repeatable `--model`, `harness eval results`, `harness eval compare`, and `harness eval baseline save/list`. Preserve these interfaces and extend their validation/provenance. Other entries below remain proposed; finalize new flags through an implementation ADR.

| Command/workflow | Outcome |
| --- | --- |
| `./dev` | Bootstraps the supported host environment, starts the local stack, verifies readiness and a smoke assessment, and prints access URLs |
| `./dev status`, `./dev logs`, `./dev stop` | Inspects and manages this checkout's services without removing persisted work |
| `harness doctor` | Reports dependency, configuration, provider-profile, Temporal, storage, and sandbox readiness; network checks are explicit |
| `harness explain-config <agent>` | Shows redacted requested and effective settings, provenance, limits, and incompatibilities without inference |
| `harness reproduce <run-or-case>` | Reconstructs the recorded case/environment subject to artifact availability; states any unavoidable drift |
| `harness eval run` | Runs versioned agent suites through the shared invocation contract |
| `harness eval system` | Runs full graph/runner assessments and emits a release-compatible report |
| `harness eval sweep <experiment>` | Executes bounded calibration trials without editing production configuration |
| `harness eval compare` | Checks comparability, then reports distributions, slice deltas, gates, and missing evidence |
| `harness release check` | Resolves required report identities and evaluates policy; may wrap pinned agentctl with harness-specific validation |
| `just check`, `just test`, focused recipes | Deterministic fast path with explicit optional service requirements |
| `just generated-check`, `just dev-skills-check` | Validates generated artifacts in temporary directories and reports drift without rewriting the checkout |

### DX-04: Worktree, packaging, and API quality

- Retain per-process test database/recipe-cache isolation, now implemented. Extend worktree/session isolation to temporary storage, snapshots, resource names, service/database identities, and configurable ports.
- Use locked dependency installation in reproducible checks; add formatting and targeted static typing for core contracts. Avoid broad unrelated cleanup in behavior changes.
- Preserve the newly packaged agent specs, runtime skills, model catalog and resource resolver, and retain installed-wheel checks. Extend release validation to the packaged migrations and declared deployment profiles.
- Add explicit Pydantic API response models and consume generated client types in the web application instead of parallel handwritten response shapes.
- Surface partial/error states, missing evidence, unknown cost, effective model configuration, and experiment comparability in the UI.
- Preserve analyst review history and reasons. A review does not silently overwrite the original machine verdict or automatically become ground truth without adjudication.

**Acceptance:** a clean worktree can run the offline fast path without another worktree's state; package resources load outside the checkout; generated checks leave files unchanged; both supported coding clients discover the intended skill packages; and API/client compatibility is checked automatically.

### DX-05: One-command onboarding on macOS and Linux

After cloning the repository, the documented entry point MUST be:

```bash
./dev
```

This is a proposed launcher, not an existing script. It MUST handle first-time setup and subsequent startup using the same command. A developer must not have to discover and sequence Python, Node, uv, just, database, Temporal, worker, web, and sandbox setup instructions independently.

**Starting assumptions:** a supported macOS or Linux host, a checked-out repository, a compatible system shell, network access for initial dependency/image downloads, adequate disk/memory, and permission to run the required container/virtualization environment. Document exact supported OS/architecture combinations and measured resource requirements. Do not assume an existing Python/Node toolchain, just installation, configured container builder, cloud account, or model API key.

The launcher MUST:

1. Detect the OS, CPU architecture, required host capabilities, available resources, and existing managed runtime state. Fail early with a specific explanation on unsupported combinations.
2. Provision or reuse pinned development tools and the supported container/VM environment. Prefer project-managed or isolated installations; verify downloaded artifacts and avoid replacing global tools or changing shell profiles unnecessarily.
3. Install locked project dependencies and provide an editable backend/frontend development loop with documented reload behavior. A running prebuilt demo alone does not satisfy developer onboarding.
4. Generate local configuration and service credentials without overwriting existing configuration or requiring tracked-file edits. Keep secrets out of Git and logs; expose services on loopback by default.
5. Start the API, web UI, worker, Temporal, database, artifact storage, and required supporting services under a unique checkout/worktree identity. Select available ports or provide a deterministic, actionable conflict resolution.
6. Configure and verify the build/probe isolation boundary. On macOS, manage the supported Linux VM/container environment; on Linux, provision or reuse the supported isolated executor. Do not assume that an ordinary container daemon provides the required build isolation.
7. Apply local database migrations and wait for actual health/readiness with bounded timeouts. Process startup alone is not readiness.
8. Run a deterministic smoke assessment through local Temporal, persistence, and the sandbox using controlled fixtures. Verify known positive and negative reference-probe observations independently of stub model judgment. Seed an example result visible in the UI, clearly labeled as a demonstration.
9. Print the selected execution profile, readiness results, UI/API and diagnostic URLs, log locations, and concise stop/restart instructions. Return success only after the selected profile's checks pass.

The default profile MUST require no inference credentials and make no paid model requests. Use stub inference for the demonstration while verifying the real service and sandbox path with reference fixtures. Label stub verdicts clearly; successful onboarding is not evidence of model accuracy.

**Platform setup boundary:** OS-level installation or virtualization may require a password, license acceptance, or a platform permission dialog. The launcher should guide that unavoidable step and resume idempotently; it must not silently grant privileges or claim zero host interaction. Any prerequisite that cannot be automated must be stated before the quickstart, with the smallest possible one-time setup. Routine startup after that setup remains `./dev`.

**Failure and recovery:** rerunning `./dev` after an interrupted download, partial migration, or service failure MUST safely resume or explain the necessary recovery. The launcher MUST preserve existing local findings, artifacts, configuration, and unrelated host containers. `./dev stop` preserves data; destructive reset is a separate explicit operation. Logs must identify the failed stage and a reproducible diagnostic command.

**Explicit lightweight mode:** an optional `./dev --profile offline` may provide stub/component development without container services. It MUST state that real sandbox/Temporal acceptance was not checked. The full default profile must fail closed when required isolation is unavailable; it must not silently fall back to the lightweight profile or an insecure runtime to show a green startup.

**Live inference:** after credentials/endpoint settings exist, the same launcher SHOULD accept an explicit OpenAI-compatible or Bedrock profile without source edits. Run bounded provider preflight only when requested. Model hosting, AWS account/model access, and SSO sign-in are external prerequisites for live inference, not prerequisites for first-time onboarding.

**Documentation:** the README's primary quickstart becomes clone, `./dev`, and the displayed UI link, with minimum host assumptions above it. Detailed platform troubleshooting and manual setup remain secondary. Report first-run versus warm-start timings and dependency/download sizes on reference hosts; agree performance targets after measuring them.

**Acceptance:** test clean-host setup, warm restart, interrupted setup, port conflicts, paths containing spaces, multiple worktrees, configuration/data preservation, missing permissions, insufficient resources, unavailable downloads, and missing isolation. Validate real onboarding on both macOS and Linux for every architecture claimed as supported, including an actual macOS VM path and Linux sandbox path. Initial priority is Apple Silicon macOS and x86-64 Linux; Intel macOS and ARM64 Linux require explicit support decisions and evidence before advertising them. Mocked platform detection or a developer machine with preinstalled tools cannot substitute for clean-host acceptance.

This onboarding procedure is a harness-specific extension compatible with the playbook's reproducibility, least-capability, durable-execution, and evaluation requirements. It does not introduce a playbook exemption for local execution or isolation.

## 13. Observability, evidence access, and user interface

Every batch, finding, preparation, agent invocation, tool call, build, probe, and eval attempt carries stable correlation IDs and manifest identity. Preserve ordered events with attempts and outcomes; distinguish tool requests from successful execution and skill load attempts from successful loads.

Record spans and usage while the relevant operation is active, including failures. Required accounting cannot depend exclusively on best-effort telemetry export. Exporter failure should not fabricate successful evidence or erase durable usage records.

The run detail view SHOULD expose:

- Original finding, source revision/content identity, assessment scope and status.
- Environment/toolchain profile and preparation outcome.
- Probe source, selected tests, structured observations, controls, and bounded logs.
- Evidence supporting each decision and any contradictory or missing evidence.
- Repair/fallback history and which limit or failure ended the run.
- Complete known cost, unknown-cost indicators, latency, and token breakdown.
- Review history and a reproduction manifest.

Capture only required source and provider data; redact secrets before persistence/export. Artifact retention and access boundaries remain applicable even in a single-user deployment. Raw tool arguments, URLs, and error messages may contain credentials and require filtering.

### UI-01: Review findings and scope

The UI review covered all current routes, shared components, theme/styles, query configuration, client types, and the backing API. Findings below are **source-confirmed** against the baseline in §1. This was not a rendered-browser, screen-reader, contrast-measurement, or live-workflow validation; those checks remain implementation acceptance requirements. The reconciliation in §1.3 confirmed that the web sources and API application are unchanged across the 31-commit update (only generated web build state/ignore rules changed); these findings remain applicable.

| Area and evidence | Current limitation | Proposed improvement |
| --- | --- | --- |
| [Application shell](../web/src/main.tsx), [styles](../web/src/index.css), [document](../web/index.html) | Centered top-navigation layout; dark mode hardcoded; limited semantic theme tokens | Compact navigation, contextual breadcrumbs, coherent neutral theme, accessible theme preference |
| [Components](../web/src/components/ui), [package manifest](../web/package.json) | Small set of locally implemented shadcn-style primitives; no established broader component conventions | Adopt shadcn/ui components selectively, with one shared token and interaction system |
| [Finding queue](../web/src/routes/TriageQueue.tsx), [API](../src/infosec_harness/api/app.py) | Counts derive from filtered rows returned by an endpoint capped at 200 by default; no full-result pagination/search; little execution-state visibility | Server-derived counts with explicit scope, pagination, URL filters, and separate execution/verdict indicators |
| [Finding detail](../web/src/routes/FindingDetail.tsx) | Failed/not-found fetches can remain at “Loading”; large raw JSON panels; invocation summary rather than live execution history | Explicit error/not-found states, evidence-first detail, ordered workflow activity, expandable diagnostics |
| Finding detail review actions | Reviewer is hardcoded to `analyst`; override only offers `likely_not_exploitable`; no history view or pending/error feedback | Explicit local reviewer identity, symmetric allowed corrections, reason, pending/error handling, append-only review history |
| [Experiments](../web/src/routes/Experiments.tsx) | Loading/errors appear empty; missing cost becomes zero; summary-only accuracy; config hash expected by UI is absent from API response | Typed detailed reports, completeness and gate status, comparable baselines, honest missing-data indicators |
| [Configuration](../web/src/routes/ConfigView.tsx) | Minimal model/config list; no requested/effective settings, provider capability or readiness detail; loading/errors appear empty | Read-only effective configuration and diagnostic status with links to provenance |
| [Client](../web/src/api/client.ts), application query defaults | Parallel handwritten response types despite generated-type comment; global eight-second polling applies broadly | Generated response contracts, targeted active-state refresh, cancellation, freshness, and reliable error handling |
| API submission and persistence boundary | Submission awaits processing; result-oriented API does not expose sufficient incremental phase/attempt data | Persist submission identity early, return promptly after durable acceptance, expose authoritative progress snapshots |
| UI validation | Package scripts contain no dedicated UI interaction, accessibility, or visual checks | Small deterministic fixture-backed UI suite covering critical flows and state semantics |

These issues make the UI a limited result viewer today. Styling changes alone cannot deliver reliable live transparency or trustworthy aggregate analytics.

### UI-02: Visual direction and components

Use [Linear's public product interface](https://linear.app/) as a design reference for compact navigation, readable lists, contextual properties, and activity visibility. This is a proposed interpretation of the desired aesthetic, not a claim to reproduce Linear's internal design system. Use original assets and system or appropriately licensed fonts.

- Prefer neutral charcoal surfaces, subtle borders, restrained elevation, one muted accent, and consistent typography/spacing. Reserve semantic colors for meaningful states; avoid dashboard decoration that competes with findings.
- Establish shared tokens for background, surfaces, borders, foreground/muted text, focus, selection, and semantic status. Follow [shadcn/ui's semantic CSS-variable theming approach](https://ui.shadcn.com/docs/theming). Provide dark/light/system preferences with persistence; verify both themes before declaring support.
- Use a compact desktop sidebar, contextual page title/breadcrumb, and a consistent filter/action bar. Keep lists dense but readable; numeric columns use consistent precision and tabular figures. Full titles and identifiers remain accessible despite truncation.
- Adopt shadcn/ui Table, Button, Badge, Input, Select, Tabs, Tooltip, Sheet/Dialog, Alert, Skeleton, Label/Textarea, and Collapsible as needed. Use an accessible confirmation dialog only for consequential actions. Keep existing TanStack Query/Router and compatible table utilities; a framework or Tailwind major upgrade is not a prerequisite.
- Keep component source reviewable in the repository, document local changes and dependency compatibility, and avoid installing the entire component catalog. Components do not remove the need to test accessibility.
- On narrow screens, collapse navigation and move secondary properties into an accessible panel. Preserve primary status, finding title, and actions; wide telemetry tables may scroll within a labeled region without making the whole page overflow.

### UI-03: Navigation and core user journeys

Use five simple destinations: **Findings**, **Workflows**, **Evaluations**, **Metrics**, and **Settings**. These may share list/detail components; they do not require separate services. Preserve existing run links and redirect renamed experiment/config routes. Store meaningful filters, sort order, date range, and selected comparison in shareable URLs. Browser Back restores the prior list context.

| Destination | Primary question | Initial content |
| --- | --- | --- |
| Findings | Which finding needs attention, and what supports its verdict? | Search/filterable paginated queue; source, priority, execution state, verdict, review state, cost completeness; evidence detail |
| Workflows | What is running, waiting, retrying, or stopped? | Batches and child assessments; preparation dependencies; current phase, elapsed time, last update, failure/stop reason |
| Evaluations | Is this agent/configuration better, and is the evidence sufficient? | Agent/system eval reports, progress, gates, baseline comparison, case drill-down, parameter trials |
| Metrics | Where are time, tokens, and cost going across runs? | Filtered population counts, totals, means and percentiles, coverage, stage/provider/configuration breakdowns |
| Settings | What configuration and services are actually in use? | Read-only requested/effective settings, provider profile, model identity, limits, readiness and reproduction information |

A new developer arriving from `./dev` MUST find the labeled demonstration workflow and result, understand which services were checked, and distinguish stub inference from real inference. Empty screens explain the next supported action and offer a copyable, correctly configured CLI example. A complex submission wizard is deferred; any later submission UI must use the same validated API contract.

### UI-04: Authoritative live workflow visibility

The backend MUST persist a batch/run identity before acknowledging acceptance and expose incremental progress independently of the submitting HTTP connection. Apply DUR's idempotency and recovery requirements; an accepted request must survive submitter loss. Do not claim live tracking by animating a client timer over completed-result data.

Use a small typed status snapshot plus a paginated ordered activity list. Include stable parent/child IDs, lifecycle status, normalized outcome, current phase, attempt, timestamps, last durable update, stop reason, relevant artifact references, and known usage. Link shared preparation once to its dependent findings. Persist meaningful transitions at the execution boundary; do not require a general event-sourcing framework.

Keep three concepts visibly separate:

1. **Execution:** queued, active, waiting, retrying, cancellation requested, or terminal status, with normalized outcome such as timeout or budget exhaustion.
2. **Assessment:** verdict and evidence basis, including inconclusive or no verdict yet. A completed workflow need not establish exploitability; an execution failure is not a negative verdict.
3. **Freshness:** last update, refreshing, disconnected/stale, or unavailable. Losing connectivity does not prove the worker stopped.

Show checkout, environment preparation, assessment, tool/probe execution, repair, validation, and persistence when those phases actually occur. Display durations, retry reasons, and dependencies; loops must not produce invented completion percentages or ETAs. Batch progress may show terminal children / accepted children, with failures and cancellations separately counted. Cancellation requested remains distinct from cancellation confirmed; expose the control only when backend cancellation semantics are implemented.

Start with bounded polling of active lists/details, targeting one-to-two-second refresh while visible, with backoff on errors and slower aggregate refresh. Stop frequent polling for terminal records and hidden views; refresh on reconnect/focus. Measure event-commit-to-visible latency and publish the tested target. Preserve last good data with a stale marker on transient failure. Use ordered sequence/cursor semantics to avoid duplicate or out-of-order events and avoid resetting selection, focus, or scroll during updates. SSE can be added later if polling latency/load measurements justify it; WebSockets are not required.

### UI-05: Run telemetry and evidence detail

A run detail page MUST explain the result before presenting diagnostics. Show source revision, scope, verdict/evidence basis, execution outcome, environment, provider/model, effective configuration identity, and review status. Put rationale and supporting/contradictory evidence first. Use tabs or sections for **Evidence**, **Activity**, **Usage**, and **Review**; raw payloads are secondary expandable diagnostics.

The activity view includes agent invocations and tool/build/probe attempts with durations, outcomes, retries, and correlation links. Expose bounded redacted logs and retained probe/source artifacts, including truncation and expiry indicators. Show structured action summaries and evidence, not hidden model reasoning. Prompt/completion capture remains off by default under A8; a trace viewer must not implicitly enable it. Do not render repository/model text as trusted HTML or executable markup.

The usage view MUST include, when known:

- End-to-end elapsed time and queue, preparation, model, tool/probe, and retry/wait components. Overlapping component durations are labeled and not falsely presented as an additive wall-clock total.
- Request/tool counts, input/output tokens, provider-reported cached/reasoning categories where available, effective limits, and stop/enforcement reasons. Define category inclusion so cached or reasoning tokens are not counted twice.
- Known inference cost, estimate/reconciliation status, pricing identity/currency, unknown usage, and shared preparation attribution. Zero is displayed only when measured or explicitly justified; no rate configured for a local model means unknown/unpriced, not free.
- Root versus child usage and retry attempts, including failed and cancelled requests. Separate reservation, observed consumption, and estimated in-flight exposure; missing provider usage after interruption remains explicit.

Do not label model self-reported confidence as empirically calibrated probability. Use “model-reported confidence” until calibration evidence supports a stronger interpretation. Preserve the machine assessment independently of subsequent human corrections. Reviews require a local reviewer identifier and reason for override, offer all supported corrected labels, and retain history; this does not require enterprise identity management or imply authenticated identity.

### UI-06: Agent evaluations and parameter experiments

Replace the current UI experiment summary with read-only report list/detail views backed by EVAL/CAL records. Reuse the new backend confusion matrices, percentile summaries, coverage and provenance; expose them through typed API contracts rather than recalculating competing definitions in the browser. The current API still omits important newly persisted experiment fields. Persist measured case-level time/token/cost observations or versioned histogram bins before rendering distribution plots: percentile summaries cannot supply them, and the current per-case latency column is not populated by the agent-eval loop. Support both individual-agent and whole-system evals and distinguish real-model, stub/component, and live operational data. Display planned/completed/failed/skipped case attempts, repetitions, current state, report completeness, dataset/version/split, evaluator/policy identity, harness revision, and effective model/configuration identity.

Show quality, operational, and budget/safety gates separately. A weighted score or high accuracy MUST NOT obscure a failed gate. Status is passed, failed, not checked, or justified not applicable; partial reports cannot masquerade as accepted releases. Accuracy and other rates show their numerator/denominator and uncertainty where supported. Include false-dismissal/false-positive rates, inconclusive and failure rates, budget stops, latency, cost, and tokens as defined by the report schema. Slice by relevant ecosystem, weakness, difficulty, provider/model, and agent; show sample sizes and insufficient-data warnings.

A baseline/candidate view MUST show comparability checks before ranking: same case population/split, scoring semantics, execution profile, repetitions policy, and declared changed variables. Present paired case deltas where appropriate, distributions and worst-risk slices, failed attempts, and raw report/artifact links. Do not rank incomparable or incomplete candidates as winners. Held-out evidence remains separate from tuning evidence; operational reviews do not silently become golden labels.

For token limits and other CAL parameters, expose requested **and effective** values per trial, the bounded search range, actual token/request consumption, stop rate, quality-gate results, time/cost distributions, and selection rationale. Initially use a sortable trial table and polished quality-versus-cost/time scatter plots with an accessible table equivalent. Show the feasible quality/cost frontier where the data supports it, with quality gates and incomplete trials visibly distinguished. Each point links to its cases/configuration. Mark noncomparable, incomplete, or dominated candidates without automatically promoting a configuration. Experiments continue to run through the CLI; a graphical optimizer, experiment authoring workflow, and one-click promotion are deferred.

### UI-07: Aggregate metrics across runs

Provide a dedicated read-only Metrics page, using server-side aggregation over the full selected population rather than the rows loaded by the browser. Share filters and definitions with exported reports. The first version includes counts, total and mean time/cost/tokens, p50/p95 durations and token consumption, failure/inconclusive rates, a breakdown table, and the polished distribution and diagnostic visuals defined below. These visuals are initial product requirements, not deferred dashboard decoration.

**Population and filters:** default to a clearly labeled time window of assessment runs created within `[start, end)`, with displayed timezone and an `as_of` snapshot time. Show active, terminal, successful, failed, cancelled, and missing-data counts. Distinguish findings, assessment runs, retries/attempts, batches, and eval cases. Retried attempts add resource consumption to their logical run; a separate rerun is a separate run. Default operational metrics exclude demo/stub and eval populations, with explicit switches to inspect them. Allow date range, repository, agent, provider/model, effective config, ecosystem, execution outcome, and verdict filters where recorded. Unknown historical fields remain an explicit category.

| Metric | Required semantics |
| --- | --- |
| Average end-to-end time | Sum of valid acceptance-to-terminal durations / number of terminal runs with those timestamps. Include failed/cancelled terminal runs and show an optional successful-only view. Active elapsed time is separate and excluded from completion averages. |
| p50/p95 time | Distribution over the same explicitly selected terminal population; state sample size and quantile method. Do not average per-batch percentiles. Stage duration panels distinguish queue, preparation, execution, and wait. |
| Total and average inference cost | Known monetary total plus incomplete/unpriced-run count. Mean fully accounted cost uses only fully accounted runs and reports coverage; never present that mean as unbiased population-wide cost when coverage is incomplete. Include failed attempts and show estimated versus reconciled status. |
| Average tokens | Sum of complete canonical token totals / number of runs with complete token accounting, with coverage. Break down input/output and provider-specific subcategories without double counting. Present partial observed totals separately. |
| Cost per successful compliant outcome | Total attributable cost of the selected cohort, including failed runs, divided by successful outcomes that passed the applicable checks. Unknown cost/checks make it incomplete; zero qualifying outcomes yields unavailable, not zero. |
| Rates | Display numerator, denominator, exclusions, and cohort definition. Execution success, assessment verdict, reviewer agreement, and eval correctness are different measures. Operational runs without adjudicated labels cannot supply accuracy. |
| Cache and retry metrics | Define whether cache rate means cached input tokens / eligible input tokens or preparation-cache hits / lookups; never merge these. Distinguish retried logical runs from number of attempts. |

Count shared preparation once in root/batch totals. Initially show shared preparation separately from assessment-only per-run usage; label these boundaries adjacent to metrics. If amortized per-finding costs are later offered, version and display the allocation rule, identify cache reuse, and ensure drill-down sums reconcile without counting both allocated children and their parent. Inference cost is not total compute/VM/storage cost; keep infrastructure cost separate until measured.

Migrate metric semantics explicitly: the existing stored run latency is summed invocation time, not end-to-end duration; existing cost totals coalesce unknown invocation costs to zero. Label historical values by their actual semantics and show unavailable coverage rather than relabeling them as the new metrics.

Show provider/model/configuration breakdowns alongside aggregates so changing workload mix is visible. Averages alone are not evidence of a better configuration: evaluation comparison remains subject to UI-06. Allow drill-down from each metric to its constituent runs and export the same filtered summaries with schema version, filters, time window, units, sample/coverage counts, and source identities. Avoid exporting raw prompts, secrets, or unredacted repository content.

#### Initial visualization requirements

Keep the initial UI polished and visually explanatory. Deferring visual workflow builders does **not** defer charts, interaction quality, typography, spacing, or visual QA. Prefer a small maintained chart library integrated with the shared shadcn/ui theme over a bespoke chart framework. Confirm compatibility with the repository before choosing it; keep transformations and statistical definitions in tested shared/reporting code.

| Visual | Question answered | Required behavior |
| --- | --- | --- |
| Token distributions | How variable is consumption, and which runs exhaust limits? | Histogram for total/input/output tokens with metric selector, sample/coverage counts, p50/p95 and relevant limit markers; isolate heterogeneous limits by configuration or label them explicitly. Include failed attempts in run totals. |
| Cost distributions | Is the mean representative, or do a few expensive runs dominate? | Histogram of fully accounted per-run inference cost, known-cost coverage, mean/median/tail markers, and drill-down to expensive runs. Keep incomplete/unpriced costs outside complete-cost bins and visibly counted. |
| Latency distributions | What is typical, and how bad is the tail? | Histogram of terminal elapsed time with p50/p95 markers; selectable queue/preparation/execution measures where known. Active elapsed durations are separate. Failed/cancelled runs remain identifiable. |
| Time trends | Is performance, reliability, or quality changing? | Aligned small charts for volume, latency, cost/tokens, and failure/inconclusive rates over the same cohort and time buckets. Show sample counts and configuration changes; label creation-cohort versus completion-time semantics. No unsupported causal attribution. |
| Stage and agent breakdowns | Where do time, requests, tokens, and money go? | Ranked or grouped bars with exact values and links to constituent runs. Use stacked time bars only for mutually exclusive intervals; overlapping spans require separate bars. Shared preparation remains separately identified. |
| Eval efficacy | Which errors does the agent make, and in which slices? | Confusion matrix for adjudicated labeled cases, including explicit inconclusive/failure handling; per-slice quality/error-rate bars with denominators and supported uncertainty intervals. No operational accuracy chart without ground truth. |
| Parameter tradeoffs | Which settings preserve quality while reducing resources? | Comparable-trial scatter plot for quality versus cost/latency/tokens, with baseline, effective token limit, quality gates, and held-out status in selection details. Failed or incomplete trials cannot disappear from the comparison. |

The Metrics page SHOULD lead with a compact summary, token/cost/latency distributions, then trends and explanatory breakdowns; put eval efficacy and parameter tradeoffs on Evaluations and link between the relevant filtered views. Avoid rendering every possible chart on every page. Consistent selection, labels, units, legends, tooltip formatting, and color semantics make charts feel like one product.

**Statistical and interaction rules:**

- Compute distributions over the full filtered population server-side, not the visible table page. Define and version bin edges, quantile calculation, timezone/time buckets, and inclusion rules. Use common bin boundaries and axes for side-by-side cohort comparisons; disclose any approximation and its method.
- Show zero, missing, partial, and unavailable values distinctly. Empty or tiny populations get an honest small-sample state, without invented smoothing or visually precise probability claims. Never silently clip long tails or winsorize outliers. Optional logarithmic scales must be labeled and handle zero values explicitly.
- Each chart displays units, population/coverage, sample size, filters, and freshness. Tooltips show interval boundaries/counts or exact point values. Selecting a bin, slice, or trial opens the matching records and preserves the filter context; provide keyboard-accessible equivalent controls and a tabular view.
- Keep color stable across screens and distinguish series without color alone. Use readable axis labels and restrained grid lines, responsive layouts, reduced-motion behavior, and loading/error states consistent with the rest of the app. Polling must not animate all chart points repeatedly or move the user's active selection.
- Show uncertainty only when its statistical method is defined and appropriate. Repeated evals on the same repository/case are not independent observations; report case/group counts separately from attempts and use the EVAL/CAL comparison method. Distinguish exploratory slice inspection from release-gate evidence.
- Support a bounded, readable default window and server-side bins/series, with query limits and visible refresh state. Visual polish does not require unbounded client downloads, a warehouse, or a dashboard builder.

**Visual acceptance:** fixture tests must reconcile chart bins and tooltips to table/export totals, verify tail and missing-data handling, and ensure comparison axes and denominators match. Review rendered charts in both themes, desktop/narrow layouts, keyboard navigation, and long-label/zero/sparse/extreme-value cases. Include charts in the new-developer usability walkthrough: identify a latency tail, locate the expensive runs, explain a token-limit tradeoff, and distinguish improved eval efficacy from a changed workload mix. A table-only metrics screen does not satisfy this requirement.

### UI-08: Data contracts, accessibility, and acceptance

Add typed API responses for paginated lists, full-population counts/aggregates, progress snapshots/activity, and eval details/comparisons. Response metadata MUST state population, units, definitions/schema version, completeness, and `as_of` time. Use null plus an explicit availability reason where necessary, never fabricated zeros. Consume generated types in the client and validate contract drift. Reuse durable operational/eval records; start with indexed database queries and bounded pagination. A separate warehouse, metrics platform, or generic analytics service is not required.

Keep high-cardinality run IDs, repository URLs, and raw errors out of telemetry metric labels per A8. SQL report filters and restricted trace lookup may use recorded identifiers; they are not a reason to violate metric-cardinality rules. Use existing vendor-neutral trace links where configured, with a useful in-app summary when no external exporter is available.

Every screen MUST distinguish initial loading, valid empty data, no filter matches, error, stale data, partial results, and missing/expired records. Actions show pending state, prevent accidental duplicate submission, preserve typed input on errors, and provide actionable retry feedback. Maintain keyboard navigation, visible focus, labels, semantic tables, non-color state cues, restrained live announcements, and reduced-motion support. Verify text/control contrast, 200% zoom, and narrow layouts; do not assume a dark palette or component library ensures accessibility.

**Initial acceptance evidence:**

1. Deterministic fixture-backed route checks cover the queue, workflow detail, eval comparison, metrics, and settings, including empty/loading/error/stale/partial states. Filter/navigation state survives reload and browser Back.
2. A real local Temporal fixture run exposes durable accepted identity, preparation, retry, and terminal transitions; browser reconnect recovers current state without inventing completion. A failed child remains visible while siblings complete.
3. A known metrics fixture includes failed/cancelled/active runs, missing cost/tokens, duplicate event delivery, shared preparation, overlapping stages, multiple configurations, and more than 200 rows. Exact totals/means/denominators reconcile to records; pagination cannot change global counts. Zero-denominator and partial-coverage displays are verified.
4. A bounded parameter experiment visibly compares effective token limits, quality/stop rates, cost/time, case deltas, and held-out status; incomplete or incompatible reports cannot appear release-ready.
5. Manual keyboard and screen-reader checks plus automated accessibility checks cover core journeys. Review dark/light screenshots at desktop and narrow widths, long findings/IDs, large numbers, zoom, focus, and error states. Record actual browser/platform coverage.
6. A small usability walkthrough with a developer unfamiliar with the implementation verifies: finding an active run; explaining a failed run; tracing a verdict to evidence; interpreting mean cost with incomplete coverage; and determining whether a token-limit candidate is eligible for adoption. Record confusion and task completion, without inventing numerical usability claims.

### UI-09: Alignment and deliberately limited first delivery

**Direct alignment:** A8 requires application-level traces, aggregate metrics, logs, correlation, and behavioral results; A7/M7 require valid evaluation gates and failure visibility; A9/M9 support complete cost accounting and measured optimization; A6/M6 support durable progress/recovery. UI-04 through UI-08 make those requirements inspectable. Missing exporter data must not erase required accounting, and a stale screen must not fabricate workflow state.

**Compatible project extensions:** Linear-inspired presentation, shadcn/ui adoption, navigation, accessible interactions, refresh targets, metric population definitions, and parameter-comparison UX are local design choices. The playbook does not mandate this visual system, a web dashboard, or these exact aggregate formulas. No new safety/durability departure is proposed. Table reusable guidance on freshness/unknown-data presentation, aggregation denominators/shared-cost attribution, and eval-comparison UX for a later playbook update; implement the local definitions now rather than blocking on that update.

**Build first:** coherent shell/components; honest loading/error/empty states; corrected counts and unknown values; minimal durable workflow snapshots with polling; evidence/run-usage detail; read-only eval comparisons; one polished Metrics page with documented means/percentiles/coverage, token/cost/latency distributions, trends, stage breakdowns, and linked eval efficacy/tradeoff visuals. Deliver small vertical slices using existing services and CLI experiment execution.

**Defer until justified:** interactive workflow graphs, SSE/WebSocket streaming, arbitrary dashboard builders, a telemetry warehouse, graphical eval/sweep authoring, automatic configuration promotion, advanced cohort/query languages, custom chart frameworks, a global command palette, extensive animation, enterprise administration, and a broad theme system. Add virtualization or precomputed rollups only after measuring the initial implementation. Live state, metric correctness, polished core presentation, and the specified diagnostic charts are initial requirements. Open-ended visual builders and configurable analytics infrastructure are deferred.

## 14. Migration and compatibility

1. **Preserve the reconciled baseline.** Use §1.3 as the current-state map through `6dbb09e`; check for subsequent develop changes before implementation. Do not reintroduce solved defects or discard unrelated work.
2. **Inventory contracts.** Record public API fields, persisted schemas, agent/toolset names, workflow/activity identities, and existing report formats before edits.
3. **Add records compatibly.** Introduce versioned manifests, evidence basis, and richer execution records with migrations and readers for supported previous versions. Mark missing historical provenance as unavailable; never backfill guessed evidence.
4. **Version verdict policy.** Changes to early exits and negative-evidence criteria produce a new policy identity and a fresh baseline. Do not silently relabel historical runs.
5. **Preserve workflow compatibility.** Replay captured histories and use a tested worker-versioning/patching strategy when command ordering or durable names change. Retain compatible workers for existing executions.
6. **Version eval semantics.** Changes to budget-stop metrics, false-dismissal definitions, dataset partitions, or evaluators invalidate direct comparisons unless an explicit migration establishes comparability.
7. **Retire legacy protocols deliberately.** Support legacy evidence readers for investigation while preventing weak historical protocols from clearing stronger release gates.
8. **Roll out candidates explicitly.** Promote reviewed configuration artifacts, observe quality and operational metrics, and retain a known-good configuration. Rollback must not disable confinement or re-enable known unsafe verdict rules.

Persistence migrations should be additive where practical. Destructive migrations and changes that require active workflow cancellation need a separate concrete rollout plan. This draft does not authorize them.

## 15. Delivery plan and acceptance gates

Assign a named owner when work is scheduled; role labels below are proposed responsibilities, not existing assignments. Each phase should be split into small reviewable changes. No calendar estimates are asserted before reconciliation and environment validation.

| Phase | Priority and scope | Primary owner role | Exit evidence |
| --- | --- | --- | --- |
| 0 | Maintain §1.3 reconciliation, requirement tracking, initial change/eval skills | Maintainer | Current-state mapping; pinned playbook/tool versions; agreed open decisions and verification environment |
| 0–1 | DX-05: single-command launcher and supported macOS/Linux development environments | Developer-experience/runtime engineering | Clean-host bootstrap, editable development loop, warm restart, safe recovery, and real stack/sandbox smoke evidence on both OS families |
| 1 | EVID, SNAP, SBX: verdict integrity, source confinement, actual workload lifecycle | Harness/security engineering | Critical regressions; immutable snapshot concurrency; real isolation/egress/cleanup tests |
| 2 | INF, EVAL, CAL: effective configuration, invocation parity, full usage, bounded parameter experiments | Agent/evaluation engineering | Both provider profiles pass required tests; an end-to-end calibration report with held-out evidence |
| 3 | DUR and evidence persistence: durable completion, budgets, artifacts, recovery | Runtime engineering | Submitter/worker loss, duplicate execution, replay, cancellation, migrations, complete accounting |
| 4 | ENV: extract current ecosystems into adapters and establish support matrix | Ecosystem maintainers | Real positive/negative and failure fixtures for each claimed compatibility slice |
| 1–3 | UI-01–09: shell and state correctness, durable progress, run telemetry, eval reports, aggregate metrics | Frontend/runtime/evaluation engineering | Typed contracts; live local workflow evidence; fixture-reconciled metrics; accessible core journeys |
| 5 | Additional strategies, larger corpora, composition experiments, advanced UI/DX refinements | Maintainer and evaluation engineering | Strategy-specific gates; broader held-out results; documented composition benefit |

Phases describe delivery sequencing, not permission to release an incomplete safety boundary. Work may overlap when dependencies are satisfied. Full effectful release claims require phases 1–3's applicable gates even if individual improvements merge earlier. Initial development skills accompany phases 0–2 so subsequent work follows the proposed process.

### 15.0 Initial iteration scope

Keep the first milestone focused on a trustworthy experiment loop. Start with one tested OpenAI-compatible profile and one Bedrock profile, the existing ecosystem boundaries, one reference execution environment per supported OS, bounded CLI-driven YAML/JSON experiments, and two development skills (`harness-change` and `harness-eval-experiment`). Initially include budget calibration, regression-case creation, ecosystem checks, and durability review as procedures within those skills; the six-skill catalog in DX-02 describes possible later extraction.

Use existing persistence for the fixed workflow topology, minimal durable progress/accounting records, and read-only UI reports. Defer a general plugin platform, distributed optimization scheduler, fleet-wide accounting infrastructure, extra assessment strategies, broad version matrices, and UI-09’s advanced interfaces until concrete use cases or measurements justify them. This narrows implementation machinery, not evidence quality, confinement, failed-attempt accounting, recovery, both requested inference backends, or macOS/Linux onboarding. Deferred capabilities must not be advertised as implemented or tested.

### 15.1 Minimum release acceptance matrix

| Gate | Required evidence | Cannot be substituted by |
| --- | --- | --- |
| Source/evidence integrity | SNAP/EVID deterministic regressions plus real execution cases | Populated citation fields or marker strings |
| Isolation | Real build/probe denial, escape-boundary, resource, and cleanup tests | Docker argument assertions or runtime-name discovery |
| Durability | Captured-history replay and injected recovery/cancellation scenarios | One successful integration run |
| Provider support | Common contract suite plus live smoke/end-to-end evidence for each claimed profile | API compatibility claims or stub responses |
| Parameter calibration | Effective limits applied, all-attempt accounting, controlled comparison, held-out validation | A lower average token count or historical observed maxima alone |
| Ecosystem support | Versioned adapter fixtures and actual build/test execution | Filename-based language detection |
| Evaluation integrity | Complete comparable reports, finite metrics, required risk coverage, immutable provenance | Structural agentctl pass or aggregate accuracy |
| Development consistency | Skill activation/adherence evidence, generated checks, portable package/API tests | Instructions existing on disk |
| UI and metrics integrity | Live durable progress, explicit partial/stale states, reconciled aggregate fixtures, valid eval comparisons, and accessible core journeys | Screenshots alone, browser-only averages, fake progress, or missing usage treated as zero |
| Developer onboarding | `./dev` succeeds on clean supported macOS/Linux hosts, validates the real stack, and preserves data on restart | A multi-command manual guide, preconfigured maintainer machine, or silent insecure fallback |

A release report classifies every required gate as `passed`, `failed`, `not_checked`, or justified `not_applicable`. Missing infrastructure and missing measurements do not count as success.

### 15.2 Proposed implementation areas

| Existing area | Expected evolution |
| --- | --- |
| `domain/models.py` | Versioned status/evidence/manifest contracts; stronger typed boundaries |
| `repo/checkout.py`, `repo/detect.py`, repository tools | Immutable sources, unified confinement, component discovery |
| `sandbox/`, `workflows/activities.py` | Verified runner policies, bounded streaming, stable operations, cancellation |
| `agents/models.py`, `registry.py`, `budgets.py` | Resolved backend profiles, effective config identity, shared enforced limits |
| `graph/prepare.py`, `triage.py`, `ops.py` | Conservative decision rules, component preparation, failure routing, invocation parity |
| `workflows/`, `persistence/` | Durable incremental results, coordination, resource accounting, migrations |
| `evals/`, `eval-corpus/`, release policies | Executable scoring, report schemas, compatible comparisons, calibration and held-out suites |
| `src/infosec_harness/skills/`, new development-skill sources, root instructions | Separate runtime/development procedures with versioning and checks |
| API, web, CI, justfile | Typed results, evidence/experiment views, readiness and reproduction commands, layered gates |

These are responsibility mappings, not a requirement to preserve oversized files. Extract focused modules where necessary; avoid moving code without a behavioral or maintenance benefit.

## 16. Review decisions

Recommendations below remain proposals. Acceptance of this draft should resolve or explicitly defer each item.

| ID | Decision | Recommended starting position | Evidence or consequence |
| --- | --- | --- | --- |
| D01 | Automatic static dismissal | Disable uncorroborated context-only dismissal; admit specific validated static criteria | May increase probing/cost; reduces unsupported negative claims |
| D02 | Initial platform support | One-command onboarding on Apple Silicon macOS and x86-64 Linux, each with a verified Linux execution boundary; declare other architecture support separately | Both OS families are onboarding acceptance requirements; shared runner code does not establish tested platform parity |
| D03 | First ecosystem/version matrix | Stabilize existing four ecosystems; select version ranges from actual target repositories | Requires an inventory of representative codebases and toolchains |
| D04 | Provider acceptance profiles | One configured local OpenAI-compatible model and one Bedrock model/profile initially, both tested | Requires available endpoint/AWS access and bounded live-eval spend |
| D05 | Quality and sample thresholds | Establish repeated baseline, then approve per-slice thresholds and minimum sample sizes before candidate selection | No empirical numerical defaults can be honestly finalized from this review alone |
| D06 | Budget-stop policy migration | Separate enforcement violations, expected stops, and unexpected stops | Requires versioned report/policy changes and new baseline |
| D07 | Root budget accounting | Use framework facilities where suitable with a durable reservation/reconciliation layer | Validate restart/concurrency semantics before choosing exact implementation |
| D08 | Development-skill packaging | Canonical `dev-skills/` plus checked generated client copies | Explicit Codex discovery-guide correction; adds a drift check |
| D09 | Next assessment strategy | Prioritize isolated integration/local-service fixtures after unit-probe reliability | Choose based on unsupported real findings, not generality alone |
| D10 | Scope and artifact retention | Single deployment; configurable bounded retention with explicit evidence expiry | Exact durations/resource quotas need operational input |
| D11 | Local effectful execution | Require local Temporal for conformant real assessments; keep direct mode clearly scoped to development/testing | Broader exemptions await playbook OP-001/F06 resolution |
| D12 | Agent graph simplification | Keep current topology initially; remove/add stages only after controlled baseline/ablation results | Avoids an unmeasured rewrite |
| D13 | Development runtime distribution | A checked-in `./dev` launcher managing pinned tools/services and a supported macOS VM/Linux executor; select the runtime after a platform spike | Validate installation rights, licensing, host resource needs, architecture support, and reproducible isolation without requiring paid inference |

UI review decisions: start with polling and database-backed aggregation; adopt shadcn/ui incrementally; keep eval execution/configuration changes in reviewed CLI workflows; preserve demo/eval/operational population separation. More elaborate streaming, charting, and optimization infrastructure requires a measured need.

## 17. Risks and tradeoffs

- **Cost of stronger evidence:** fewer early dismissals and more controls can increase latency/spend. Calibrate routing and budgets after correctness gates are in place.
- **Corpus overfitting:** repeatedly tuning against tiny paired fixtures can optimize to names or conventions. Use independent grouped holdouts, realistic repositories, and reviewed ground truth.
- **Adapter complexity:** a broad plugin abstraction can outgrow the product. Extract current ecosystems first and add extension points only where actual cases require them.
- **Provider drift:** an endpoint or alias can change without a code change. Record identity limitations, rerun drift suites, and invalidate stale acceptance evidence.
- **Accounting uncertainty:** cancelled/time-out requests can be billed without complete usage. Preserve uncertainty; do not claim exact cost optimization when inputs are missing.
- **Environment reproducibility:** mutable registries, unavailable artifacts, platform differences, and repository build assumptions can prevent exact reconstruction. Record resolved artifacts and limitations rather than hiding them.
- **Workflow migration:** changing configuration resolution or graph ordering can break replay. Treat saved-history validation and compatible workers as release requirements.
- **Stricter gates expose existing gaps:** initial supported scope may become narrower. Publish tested support explicitly instead of weakening the gates to preserve broad claims.

## 18. Definition of completion

The initial hardening milestone is complete when an assessment can be submitted, recovered after failure, reproduced from retained evidence, and explained without relying on an agent's unsupported assertions; both declared inference backends pass their acceptance profiles; and at least one parameter-calibration experiment demonstrates that a reviewed setting was chosen from controlled data and held-out validation.

Developer onboarding is complete when a new contributor on each supported macOS/Linux platform can run `./dev` from a fresh checkout, reach a healthy editable development stack with a verified smoke result, and safely stop/restart it without manually assembling the underlying services or supplying inference credentials.

The initial UI milestone is complete when a developer can follow a real workflow, inspect evidence and complete/unknown usage, compare agent evals and parameter trials, and understand cross-run time/cost/token metrics with explicit populations and coverage. UI-08 defines the required validation; visual polish alone does not satisfy this milestone.

Broader language/strategy support is complete only per declared compatibility slice. Development procedures are complete when both coding clients and human contributors use the same executable standards and a behavior-changing proposal arrives with comparable evaluation evidence.

This specification itself is complete for review when the recommendation groups, playbook classifications, proposed departures, deferred playbook items, acceptance gates, migration constraints, and unresolved decisions are explicit. Approval authorizes planning against the agreed scope; implementation and release evidence must still satisfy the resulting requirements.
