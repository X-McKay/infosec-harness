# Agent quality improvement experiment

Baseline: develop `1fdef7d7d20485346cdb9a59d0b49fc38ee196a3`.
The earlier cross-source results are diagnostic evidence, not a controlled new baseline.

## Ordered work

1. Make partial-build, context and verdict model-facing output schemas explicit. Keep stored
   domain models backward compatible and retain independent safety validators. Version changed
   agents and test captured workflow replay before claiming durable compatibility.
2. Replace the ambiguous Perl build-repair literal check with a declared secure execution check.
   Version the evaluator/dataset; preserve historical records and original expectations. Missing
   secure execution is not checked and cannot count as passing release evidence.
3. Retain bounded call traces, locate repeated work in probe-author/probe-repair, and test a
   compact target/framework context strategy before reducing runtime budgets. Collect controlled target-invocation diagnostics and explicitly distinguish them from
   independent attestation; do not promote marker or in-process trace observations to proof.
4. Freeze a tested candidate. Run bounded parameter overlays on identical code/data/provider
   settings, with requested/effective values and every failed attempt retained. Verify a provider
   setting is actually enforced before attributing outcomes to that setting. No automatic promotion.
5. Qualify all eleven agents on one clean commit with three repetitions, then run fresh grouped
   held-out cases. Cases used to diagnose or develop a fix are regressions, not fresh holdouts.

## Boundaries and experiment limits

The authorized inference endpoint is `https://llm.almckay.io`; live Bedrock is excluded.
No sandbox access, quality threshold or golden outcome is relaxed. Repository content and model
outputs remain untrusted. A requested label is never supplied to the candidate as ground truth.
Default prices describe token billing only, not hardware cost.

Initial live envelopes: at most 354 full-suite case attempts (118 cases x 3; any newly declared
execution checks keep the same cases), at most 48 additional diagnostic/calibration/held-out
attempts, at most two concurrent suites, and a four-hour aggregate wall-clock ceiling. Every
invocation keeps its production request/token/timeout limits. Calibration runs alone and declares
its split, parameter values and smaller local budget before inference. The maximum combined
case-attempt envelope is 402; explicit status is retained for interrupted or unscored attempts.
Do not claim passed qualification if any required case, execution check or hard gate is missing.

Output-contract changes affect model activity schemas and output-tool names. Replay and resumed
execution must be tested separately; unchanged persisted domain fields alone do not prove replay.
Acceptance-time configuration pinning remains active, so changed workers must not silently execute
an accepted old configuration under a new identity. Execution checking uses the existing runsc
builder and sandbox, never host execution of candidate commands.

## Status

Implementation is complete pending the final combined checks and clean candidate commit.
No new live inference or promotion has run. An initial complete offline run passed 1,578 tests;
the final Perl and execution-gate changes receive fresh combined validation before freezing.

The Perl check exposed a native-module loading failure under the existing noexec work mount.
Resolve this through read-only installed libraries; do not broaden sandbox mount permissions.
Probe tracing is diagnostic-only for three existing Python SQLi cases. Exact source identity,
call argument and return behavior are observed inside runsc, but the candidate shares the
interpreter and can forge these observations, including reading its appended instrumentation.
It contributes no passing release evidence and does not override structural scores. Independent
target attestation (EVID-03), including Java and other languages, remains tabled; implementing
a general attestation framework here would conflict with the requested small, iterative scope.
The release report must retain that limitation; passing agent gates is not full system release.

## Controlled token-limit trial

`evals/experiments/verdict-output-token-ceiling.yaml` compares cumulative output-token ceilings
of 4,096 and the current 128,000 on seven fixed verdict groups, then checks the selected value
on two disjoint **previously known regression** groups. Maximum: 16 case attempts, 400 reserved
model requests, 20 minutes, serial execution. The ten fresh grouped cases remain separate.
A scripted real-agent test confirms the configured limiter rejects reported usage of 4,097
under the small ceiling and accepts it under the baseline ceiling. This is a post-response
usage brake, not a server generation cap: one response can cross it before enforcement. The
server's per-call floor remains 16,000. This trial cannot establish that the server enforces
`thinking_token_budget`, and cannot justify such a claim. No automatic production promotion.

The secure Perl controls confirmed both manifest-based and explicit driver installs pass with
`PERL5LIB=/opt/home/perl5/lib/perl5`; a literal-only no-op fails. Historical `/work/home` specs
remain parseable for replay, but new candidates must pass the actual dependency query. No mount
permissions changed. Captured replay and pending-activity replay passed; old workflows reaching
an unscheduled revised output-contract agent fail before budget reservation and must restart.
