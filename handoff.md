# Harness development handoff

Updated 2026-09-30. Resume the agent qualification work from this checkpoint. Implementation is on `develop`; **full live qualification failed and main has not been merged**. This handoff/documentation commit is not itself a qualified source revision.

## Start here

1. Read `AGENTS.md`, `dev-skills/harness-change/SKILL.md`, `dev-skills/harness-eval-experiment/SKILL.md`, and `docs/HARNESS_EVOLUTION_SPEC.md`. The shared agent playbook is `/Users/al/git/playbooks/`; enterprise aspects remain deferred.
2. Read `docs/validation/agent-quality/canonical-qualification-20260930.md` and its numeric JSON checkpoint. The v17 prototype report is background evidence, not qualification credit.
3. Check the branch, working tree, and remote before editing. The original active checkout is `/Users/al/git/infosec-harness/.claude/worktrees/harness-evolution`, branch `codex/agent-quality-gates`. The primary `/Users/al/git/infosec-harness` checkout is a different checkout; do not assume it contains the current files or ignored evidence. Use `login: false` and an explicit working directory for shell tools.
4. Read the preserved closed run and frozen controller before launching anything. Root controller session 23426 exited with code 1; there are no active evaluation children from that run. No evaluation should be resumed by appending cases or recycling its scores.

## User scope and authorization

- Implement and validate the evolution spec with a simple, typed, well-organized codebase; use cost-effective Sol/Luna subagents for independent work where useful.
- Commit and push progress to `develop`. Merge to `main` only after verification and full qualification pass; no main merge is authorized by the current failed evidence.
- Run full agent evaluation using `https://llm.almckay.io/v1`, model `gateway:Qwen3.6-35B-A3B-NVFP4`. Do not use paid inference or perform live Bedrock testing. Mocked Bedrock checks are allowed.
- The task-success floor is 75%. Safety, schema, budget, coverage, and provenance requirements remain unchanged. Never weaken expected outcomes, suppress failed attempts, stitch partial runs, hide retries, or promote prototype scores as qualification evidence.
- The local-model endpoint recovery procedure is explicitly authorized; see `docs/runbooks/local-model-endpoint.md`. Stop and preserve an affected cohort first, delete the pod with `kubectl -n vllm delete pod -l app=vllm`, allow about six minutes to load, then verify real chat generation. Never use rollout restart or treat `/v1/models` 200 as serving evidence.

## Implemented code and validation

Runtime implementation commit: `880a7bfe61e238fcd738d1e5e5c86d4e28f2a039` (`Stabilize intake claim transport and retain durable generations`). It was pushed to develop before qualification. Measured source digest: `b837896092295e35fc02c83463b0700562a7423a591576e367629a79fe4212f2`.

- Intake 1.0.3 uses atomic claims with original-line source references, an intake-only inline OpenAI output-tool schema, and requested temperature 0.0. The unchanged evidence guard validates reconstructed public `ExtractedFinding` output. CWE/classification remain independently nullable. Current instructions and schema match the selected v17 prototype; no v16 wording change was selected. Private server application of temperature is unverified.
- Important files: `src/infosec_harness/agents/intake_claims.py`, `intake_schema.py`, `intake_contracts.py`, `intake_generations.py`, `replay_only.py`, `registry.py`, `models.py`, and the durable workflow/Temporal adapters. Shared prompt construction removes only top-level `report`, adds `report_source_lines`, and preserves the remaining input payload, including known finding descriptions.
- New execution identity `intake-output-v3` and workflow entry marker `intake-atomic-inline-v1`; retained bare `intake` and quote `intake-output-v2` remain registered. `src/infosec_harness/agents/intake/agent-v1.0.2.yaml` is byte-for-byte retained (SHA-256 `39a68a0f21bdb3c2c8c0e10881cde0dab4b0354aae8cff0e83567ee6932b5da3`). Old completed histories replay; fresh historical provider operations fail non-retryably. Old workflows at a live frontier require a new workflow. Arbitrary historical operator overlays are not reconstructed.
- Evaluator: `deterministic-agent-output-v11`. Atomic/quote observations are bounded and do not export raw claims. No captured final proposal correctly reports unknown capture. Agent budgets, retries, qualification policies, and acceptance guards were not relaxed.
- Final deterministic suite: **1,846 passed, zero failed/skipped**, 100.73 seconds. `just check`, `just generated-check`, and `just dev-skills-check` passed. Wheel packaging and managed local Temporal Worker/Replayer tests passed, including completed old histories, parked old frontiers, pending semantic retries, cancellation/accounting, and recovery. Mocked Bedrock factory checks passed; live Bedrock is `not_applicable` by owner exclusion. Live-provider cancellation remains `not_checked`. UI checks were `not_applicable` for this backend change.
- Actual live sandbox preflight passed, including runsc positive/negative checks, bounded execution, PID/memory exhaustion, build egress allow/deny, and cleanup. Log: `.harness/validation/quality-gates/canonical-intake-live-sandbox-preflight.log`.
- Failed intermediate deterministic attempts were preserved; a mocked provider-settings cache leak was fixed and independently regression-tested before the final passing suite. Do not present intermediate failures as the final result.

## Closed live qualification

Run: `full-canonical-20260930T155930Z-2whsyifq`, under `.harness/validation/quality-gates/` in the original worktree. Ended after **16,194.656 seconds**, with 25 completed suites, 265 attempted runs and 264 scored attempts. Plan: three independent public cohorts per 11 agents (33 suites / 354 cases), then ten unused sealed cases only after all public gates pass. The controller stopped on a nonzero build-repair CLI exit, not the eight-hour wall cap. Held-out admission never occurred.

| Item | Status | Finding |
|---|---|---|
| Overall qualification | failed | Public incomplete and mandatory gate failure |
| Frozen source/controller provenance | passed | Source unchanged throughout run |
| Intake cohorts 1, 2, 3 | passed | Each 9/9; all eight gates passed independently |
| Probe-author cohort 2 | failed | One 16-request-limit stop; other nine cases passed |
| Build-repair cohort 3 | failed | HTTP 502 / `ModelHTTPError`; one attempted, no scored result |
| Original context/probe-planner diagnostic closure | failed | Unicode hashing defect in external controller |
| Independent typed config/budget audit | passed | All 50 affected cases match canonical runtime derivation |
| Held-out | not_checked | No claim/admission; no sealed semantic reads |
| Post-run endpoint serving | passed | Actual ten-token chat HTTP 200 and generated text; no restart needed |

The request-limit attempt lasted 69.49 seconds and made 19 tool calls, including seven repeated identical `describe_callables` calls. All 16 model responses had usage (169,151 input / 4,342 output tokens); terminal usage stays unknown because no accepted final result was produced. The request cap was binding; other limits were not. Repetition's causal role is **not_checked**, and this single outlier does not justify increasing the budget.

The external diagnostic controller uses generic JSON hashing with default `ensure_ascii=True`; canonical `ResolvedAgentConfig.digest` uses `ensure_ascii=False`. Non-ASCII context/probe-planner instructions cause all 50 first/second-cohort config rehash comparisons to fail. Independently derived typed budgets and canonical config digests match every recorded attempt; an ASCII control agrees, and a Unicode synthetic control reproduces the false rejection. No runtime configuration inconsistency was found in those examined records. **This controller fix has not been implemented.** The original failed run and frozen packet must remain unchanged.

## Ordered next work

1. Correct diagnostic closure in a **new** controller version: use `ResolvedAgentConfig.model_validate({...snapshot, "budget": derived}).digest` and `BudgetResolution.digest` instead of generic configuration rehashing. Keep separately declared manifest hashing unchanged. Add meaningful, independent Unicode and ASCII regressions. Preserve the old controller/run; correct observation evidence does not make it qualified. An external-controller-only fix needs new controller/freeze identity, not a runtime/evaluator bump.
2. Study the bounded public probe-author trajectory and test one small loop-mitigation change under the same 16-request budget. First establish independently expected behavior; do not make a fixture mirror a proposed implementation. Compare fresh declared cohorts, known terminal usage, safety, request distributions, and regressions. Prefer preventing redundant inspection or clarifying stopping behavior before budget increases. No loop-mitigation implementation or experiment has yet been performed.
3. Run focused checks and relevant deterministic checks for the chosen change; record contract/risk, behavior/provenance implications, and replay/recovery assessment. Generated artifacts must use their canonical generators. Commit a clean candidate before qualification.
4. Prepare and independently review a new frozen all-agent qualification packet anchored to the **new checkout commit/source digest**. Check current model health and actual sandbox execution. Preserve prior attempt counts and unknowns. Do not invoke the old frozen helper against a new docs/runtime commit: it should reject drift.
5. Run all 33 fresh public suites with unchanged gates. Only then admit unused sealed cases. Preserve failed/incomplete runs; no pooling, stitching, hidden retries, or reused held-out claims. Record all relevant gates with the four explicit statuses.
6. Push evidence to develop. Merge to main only when full qualification actually passes. Permanent endpoint engineering was deferred until testing and develop checkpointing are done; pod recovery does not solve availability permanently.

## Local artifacts and operational limits

These artifacts are **ignored and not pushed**. A fresh context in the same worktree can inspect them. A new clone needs the original artifacts or a separately declared fresh controller/run; committed summaries cannot replay the experiment. Do not commit secrets, raw model/probe bodies, expected labels, SQLite databases, or new sealed-case exports. The original sealed fixtures are already tracked under `evals/heldout/quality-gates-v1`; do not inspect their semantic content, move them into prompts, or export them during debugging.

```text
.harness/validation/quality-gates/run-full-canonical.py
.harness/validation/quality-gates/canonical-full-qualification/
.harness/validation/quality-gates/monitor-full-canonical-independent.py
.harness/validation/quality-gates/full-canonical-20260930T155930Z-2whsyifq/
.harness/validation/quality-gates/latest-full-canonical.txt
.harness/validation/quality-gates/canonical-intake-final-r3-tests.log
.harness/validation/quality-gates/canonical-intake-final-checks.log
.harness/validation/quality-gates/python-3.12.14/bin/python
```

- Frozen helper SHA-256: `ba6de39cfaef1cebc6db0b2b0fdab2d927eea53d2dbb07cac7a4aef00abbce7d`.
- Freeze SHA-256: `064e811213b5cc1920cfe642d37ed21e8c1de6b522b152eac59e479a18dab684`.
- Plan SHA-256: `08ca6ac500e533aabfe46edfe6945b964bf749474f0e82d393fd8fe6427a9f3d`.
- Eight-hour admission certificate SHA-256: `3068338c1dedcd9785621e95be91c0c85b5af7359be519b4cd0df1773871dcd6`.
- Operational caps: public 28,800 seconds, held-out 2,400, aggregate 31,200, owned cleanup 30; concurrency one; at most one readiness + 354 public + ten held-out attempts. These are controller caps, not increased agent limits. No paid inference.
- Original packet was reviewed by Sol, with 36 synthetic admission tests and metadata-only dry-run. The safe observer had four synthetic tests. These do not prove a newly corrected packet; rerun affected independent checks before refreezing.
- The sealed directory was not read during this run. Preserve atomic, candidate-specific single-use admission. An earlier five-hour packet is preserved under `superseded-five-hour-prelaunch/`; it was superseded before inference and is not the executed packet.
- Frozen interpreter is 3.12.14; pinned setup currently specifies 3.12.13. This known discrepancy was recorded; do not silently claim identical environments or broaden tool upgrades while debugging qualification.

Canonical commands are in `AGENTS.md`. Existing tools may require a managed PATH rather than the login shell. During prior checks, `UV_PROJECT_ENVIRONMENT=/Users/al/git/infosec-harness/.venv`, `UV_NO_SYNC=1`, `UV_OFFLINE=1`, and `HARNESS_MODEL_MODE=stub` were used for deterministic checks; **do not carry stub mode into live qualification**. The live launcher sourced the checkout-owned `.harness/dev.env`, used the frozen interpreter, `PYTHONPATH=src`, and the actual canonical CLI, with no copied package or monkeypatch. Preserve source/config/controller freeze and explicit attempts on every candidate.

The existing UI was available at `http://localhost:8263` (API 8183) during this session; verify current status before reporting availability. UI fixtures are stub data; private qualification databases are not automatically imported. Do not reset the stack or local VM/data implicitly.

Automatic approval review previously rejected exporting the production pod's private cached tokenizer-template contents/hash. Do not bypass that rejection. Public versioned vLLM parser/template sources and SDK mock regressions were used instead; actual private server-template behavior remains unverified. Endpoint recovery authorization does not authorize exporting private configuration.
