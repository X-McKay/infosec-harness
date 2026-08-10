# Evaluation and Gym Design

## Recommendation

Use [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) and
[Inspect Cyber](https://github.com/UKGovernmentBEIS/inspect_cyber) as the initial
evaluation plane. Keep a small harness-owned environment protocol and expose an
optional [Gymnasium](https://gymnasium.farama.org/api/env/) wrapper. Optimize prompts,
tools, context selection, routing, stopping, and budgets offline before considering
weight training.

The release gate is a private, temporal, repository-disjoint corpus representing the
actual workflows. Public benchmarks provide smoke, comparison, and stress lanes. They
are too contaminated, incomplete, scaffold-sensitive, or operationally dissimilar to
justify autonomous production decisions.

## Evaluation principles

### Evaluate the complete policy

The system under test is:

```text
model + exact version + provider API + system prompt + context builder
+ tools + sandbox + scaffold + retry/stopping policy + budget + grader
```

Compare models with the scaffold and budget fixed. Compare scaffolds with the model
fixed. A result that changes provider-native reasoning or tool behavior is a different
configuration, not an apples-to-apples model result.

### Separate task, trial, and outcome

A task defines initial state and success. A trial is one stochastic attempt. The
transcript is diagnostic evidence; the outcome is the independently observed end
state. Anthropic's [evaluation guidance](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)
recommends isolated trials, repeated runs, balanced cases, and programmatic graders
where possible. Use those principles independently of provider.

### Validate the benchmark before the model

Run an oracle solver, known patch, known exploit/reproducer, and known-clean control.
Inspect task, environment, hidden test, and transcript manually. NIST CAISI documented
agents [gaming agent evaluations](https://www.nist.gov/caisi/cheating-ai-agent-evaluations)
by finding public solutions, changing dependencies, bypassing assertions, or satisfying
weak vulnerability checks through generic denial of service. Benchmark setup and
reward flaws can dominate the measured model difference.

### Prefer evidence over model judges

Grader priority is:

1. Hidden executable outcome or state check.
2. Deterministic artifact/schema/evidence check.
3. Blinded expert judgment with an adjudication rubric.
4. Calibrated model judge for dimensions that cannot be made deterministic.

An LLM judge never grades its own claim alone. Keep grader models, prompts, and costs
versioned. Audit disagreements and a random sample of agreements.

### Keep failures distinct

At minimum record `success`, `task_failure`, `policy_block`, `budget_truncated`,
`provider_refusal`, `provider_error`, `sandbox_error`, `grader_error`, and `cancelled`.
Infrastructure and grader errors are unscored. Treating them as zero biases model and
configuration comparisons.

## Test pyramid

### Level 0: deterministic software tests

- Domain-schema validation and migrations.
- Provider adapter contract, error, usage, and capability normalization.
- Authorization, path, egress, tool, approval, and budget policy.
- SARIF preservation, fingerprinting, deduplication, and evidence matching.
- State-machine termination, idempotency, retry, and replay.
- Cost estimation and actual-usage reconciliation.

Use fake/replay providers. These tests run on every change and do not consume API
tokens.

### Level 1: adversarial integration tests

- Malicious source comments, READMEs, issues, SARIF messages, filenames, symlinks,
  archives, terminal escapes, and oversized tool output.
- Attempts to read provider keys, home directories, cloud metadata, engine sockets,
  hidden graders, or files outside scope.
- Attempts to enable egress, install an unapproved package, expand scope, suppress an
  audit event, or exceed budget through retries.
- Sandbox resource exhaustion, process leaks, timeouts, and cleanup.
- Secret canaries and unexplained filesystem/network side-effect detection.

These run with deterministic scripted model actions before live model red teaming.

### Level 2: internal workflow evaluations

- Balanced imported-finding triage.
- Repository/diff vulnerability discovery.
- Evidence validation and safe regression-test generation.
- Threat-model extraction and threat elicitation.
- External-context retrieval, provenance, freshness, contradiction, and coverage-gap
  handling.
- Safe validation planning, environment equivalence, oracle use, containment, and
  non-reproduction outcome classification.
- Patch assessment where applicable.

This is the primary release gate. Begin with 20-50 carefully reviewed cases per
workflow, then grow through adjudicated production feedback. Small clean sets are more
useful than large noisy sets.

### Level 3: public capability suites

Run a small smoke subset on ordinary changes and larger suites periodically. Pin task
and harness commits, images, dependencies, architecture, and network policy.

### Level 4: shadow production

Run the candidate configuration without changing finding disposition, tickets, or
patches. Review all high-impact dismissals and a sample of other outcomes. Promote
only after preset quality, safety, cost, and latency gates pass.

## Benchmark portfolio

| Benchmark | Use | Important limitations and setup |
|---|---|---|
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/) | Cheap true/false-positive triage smoke set | Public, synthetic Java microcases; unlike production repos. Useful for plumbing, never sufficient for automation. |
| [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112?limit=50) | Broad synthetic CWE regression | Artificial class distribution; NIST warns incidental findings cannot be characterized automatically. |
| [CyberSecEval 4 in Inspect](https://ukgovernmentbeis.github.io/inspect_evals/evals/cybersecurity/cyberseceval_4/) | Insecure code, false refusal, prompt injection, phishing, malware, and threat-intelligence lanes | Broad but mostly not end-to-end repository discovery. Public contamination is likely. |
| [Cybench](https://arxiv.org/abs/2408.08926) | Relatively accessible tool-loop/CTF smoke test across domains | Public writeups; CTF success is not production code-review precision. Inspect includes 39 of 40 tasks because of one task's license. Enforce network policy explicitly. |
| [CVE-Bench](https://proceedings.mlr.press/v267/zhu25i.html) | Real web-CVE exploitation and programmatic outcome verification | 40 critical web CVEs, architecture/container requirements, web-only scope. Pin a current version because grader loopholes have been fixed over time. |
| [CyberGym](https://arxiv.org/abs/2506.02548) | Large real-project PoC/reproduction research | 1,507 historical vulnerabilities in 188 projects, large storage footprint, expensive setup. Inspect has corrected scoring/executor defects, so pin evaluator SHAs and validate with oracles. |
| [CyberGym-E2E](https://arxiv.org/abs/2606.04460) | Emerging discovery-to-PoC-to-patch research reference | 920 vulnerabilities across 139 projects; emerging and expensive rather than a stable CI dependency. Useful evidence that end-to-end discovery is harder than prompted reproduction. |
| [SEC-bench](https://proceedings.neurips.cc/paper_files/paper/2025/hash/a9168f1c54e5147027f1e8cf83e1a775-Abstract-Conference.html) | Real proof and patch assessment | Large images/storage and x86_64 assumptions; suitable for periodic research runs, not pull-request CI. |
| [BountyBench](https://papers.neurips.cc/paper_files/paper/2025/hash/faed4276b52ef762879db4142655c699-Abstract-Datasets_and_Benchmarks_Track.html) | Detection, exploitation, and patch lifecycle | Realistic concept but heavy nested-container/submodule setup and a small system set. Treat as an optional research lane. |
| [ExploitGym](https://github.com/sunblaze-ucb/exploitgym) | Exploit development from a known vulnerable input | Current v1.0 has 869 real-world userspace, V8, and Linux-kernel instances. It is an Apache-2.0 harness but task data keeps upstream licenses. Run only as a research-only, microVM-isolated capability and containment evaluation; it does not measure false-positive triage or production-repository discovery. |
| [PrimeVul](https://arxiv.org/abs/2403.18624) | Chronological/deduplicated classifier baseline | Function/file classification, not agentic repository investigation or false-positive disposition. |
| [ACSE-Eval](https://arxiv.org/abs/2505.11565) | Secondary threat-modeling baseline | 100 AWS scenarios, public and domain-specific. It does not replace internal architectures and expert rubrics. |
| [RealVuln](https://arxiv.org/abs/2604.13764) | Emerging scanner/model comparison including false-positive traps | Preprint and intentionally vulnerable/educational Python repositories. Promising for research, not yet a production-triage release gate. |

### Adopt by decision, not benchmark popularity

No public suite supplies a credible release gate for the complete product. Use a layered
portfolio with a different purpose for each lane:

| Lane | Initial corpus | Decision supported | Required containment |
|---|---|---|---|
| Fast regression | Harness-owned positive/negative fixtures, OWASP Benchmark, and selected CyberSecEval 4 cases | Schema, policy, false-positive, and prompt-injection regressions | No-exec or ordinary test container; all dependencies pinned. |
| Product release gate | Chronologically and project-split internal finding, threat-model, and remediation snapshots | Whether a policy/model/prompt change improves accepted findings at the required review budget | Read-only snapshots and hidden graders; no network from agent jobs. |
| Periodic defensive research | PrimeVul, SEC-bench patch tasks, CyberGym-E2E, and carefully selected CVE-Bench/CyberGym tasks | Generalization, evidence quality, patch validation, and cost/latency trade-offs | Dedicated disposable range with pinned images and independent oracle checks. |
| High-risk capability research | ExploitGym, Cybench, and exploitation portions of CVE-Bench/SEC-bench | What the model/harness can do under controlled adversarial conditions, and whether containment still holds | Dedicated account and microVM-class guest; no production connectivity, ambient credentials, package registry, artifact service, CI, browser, or shared answer store. |

The final lane is deliberately not an MVP feature, a public service, or a release gate for
the defensive triage workflow. Use it only with an approved research charter, a fixed
task subset, a reviewed model-access tier, an expiring target manifest, and a post-run
artifact review. Measure both task completion and policy/egress escape attempts. A high
exploit score is a capability and risk signal, not evidence of customer value.

`CVE-Bench` is an overloaded name in the literature. Record the repository/paper SHA,
task type, and grader digest in every result so the real-web-CVE exploitation benchmark
is never conflated with a vulnerability-repair dataset or a changed evaluator.

General coding sets such as SWE-bench can catch agent/runtime regressions but do not
measure security value. OpenAI's 2026
[coding-evaluation audit](https://openai.com/index/separating-signal-from-noise-coding-evaluations/)
reported substantial broken-task risk in SWE-Bench Pro; it reinforces the need for
task/test/transcript review rather than adding another headline score.

Check benchmark code and dataset licenses separately before redistribution. A
permissive harness license does not imply that every image, target, advisory, exploit,
or dataset artifact has the same terms.

## Private triage evaluation

No mature public suite currently represents real scanner false-positive adjudication
across production repositories. Build a private set from actual reviewed findings.

### Sampling and labels

Stratify by repository, language, scanner, rule/CWE, severity, true/false class, and
reason category. Oversample rare high-impact cases for diagnosis but report metrics
under both balanced and production distributions.

Use two blinded security reviewers and adjudication for ambiguous cases. Recommended
labels are:

- `confirmed`
- `false_positive`
- `needs_context`
- `duplicate`
- `accepted_risk`
- `invalid_input`

Do not collapse `needs_context` or `accepted_risk` into `false_positive`.

Each label includes the original scanner metadata, relevant source/sink/path,
preconditions, supporting and contrary evidence, validation result, and reviewer
rationale. A false-positive label requires positive counter-evidence.

### Leakage controls

Split by repository and disclosure/review time, not random functions or individual
findings. Remove later fixes, commits, issues, advisories, comments, and reference
patches from model-visible context. Deduplicate by repository, CVE/advisory, commit,
root cause, and code clone. Maintain:

- training/development cases for prompt and policy iteration;
- a fixed private release holdout;
- a rotating post-cutoff temporal holdout.

### Triage metrics

Accuracy is misleading under class imbalance. Report:

- false-dismissal rate, especially by severity and CWE;
- recall/sensitivity and its confidence interval;
- precision or negative predictive value among automated dismissals;
- selective coverage: fraction handled at each risk/error level;
- precision-recall curve and PR-AUC;
- calibration with Brier score and expected calibration error;
- per-repository/language/CWE macro metrics;
- reviewer disagreement and abstention rate;
- expert minutes saved;
- correct dispositions and verified findings per dollar/hour.

During the pilot, the model can recommend dismissal but a human closes high/critical
findings. Automation is gated on the lower confidence bound for sensitivity/negative
predictive value, not a point estimate.

## Discovery evaluation

An existing issue list is incomplete ground truth: an apparently new finding may be a
real unlabeled vulnerability. Freeze each target snapshot and send unmatched candidate
findings to blinded expert review. Match expected and observed findings one-to-one by
root cause, component, data/control flow, and impact. Line-number or title similarity
alone is not adequate.

Report:

- validated unique vulnerabilities and recall against known issues;
- precision after expert adjudication;
- correct component/root-cause/localization/CWE;
- reproduction or supporting-test success;
- time/cost to first validated evidence;
- coverage and deferred surfaces;
- unsupported claims and duplicates;
- validation outcomes split into `reproduced`, `supported`, `not_reproduced`,
  `invalidated`, `not_applicable`, `environment_mismatch`, `policy_blocked`, and
  `authorization_failed`, `infra_error`, and `cleanup_failed`;
- quality-at-budget and marginal value of extra attempts.

Do not report `no vulnerabilities found`; report the surfaces and budget examined and
that no finding met the evidence threshold.

## Threat-model evaluation

Create private architecture cases with expert-reviewed assets, objectives, components,
identities, data flows, trust boundaries, entry points, existing controls, abuse paths,
and mitigations. Score structured fields before prose:

- architecture-fact precision and recall;
- fact provenance, freshness, authority, and data-classification accuracy;
- trust-boundary and data-flow coverage;
- declared/deployed/observed conflict detection and critical coverage gaps;
- abuse-path preconditions and impact;
- prioritization/severity calibration;
- mitigation specificity, feasibility, owner, and validation step;
- fabricated components, controls, or assumptions;
- uncertainty and useful questions.

Semantic similarity to a reference threat list is a secondary diagnostic. Experts may
identify multiple valid threat sets, so keep the rubric and adjudication process.

## Reproducible measurement

### Trials and uncertainty

Use at least three trials per development task and more around a release decision.
Report:

- `pass@1` for operational single-run reliability;
- `pass@k` when any of `k` attempts is the actual product policy;
- `pass^k` when consistent success across attempts matters;
- clustered bootstrap confidence intervals by task, retaining trials within a
  resampled task;
- paired bootstrap or McNemar tests for paired binary A/B runs.

Never compare a one-attempt cheap configuration to a many-attempt expensive one without
also presenting total cost and quality-at-budget.

### Operational and safety metrics

Record p50/p95/p99 duration, time to first evidence, model/tool calls, retries,
timeouts, provider and policy errors, actual cached/input/output/reasoning tokens,
estimated and actual cost, sandbox CPU/memory/storage, policy violations, unsafe-action
requests, canary access/egress, grader tampering, and unexplained side effects.

### Run manifest

Pin or record:

- task/split/version/license and dataset/harness commit;
- immutable target and grader hashes;
- exact model snapshot/deployment, provider API, region, and access tier;
- prompt, threat-model, context-builder, and tool-schema hashes;
- generation/reasoning/cache settings, retries, attempts, and budgets;
- container/microVM image digest, CPU architecture, runtime/kernel, and network policy;
- complete dependency-closure hash, preparation-environment identity, and proof that
  the episode had no registry, cache/proxy, artifact-store, CI-helper, or answer-store
  route;
- lockfile and external tool/ruleset versions;
- scanner/plugin version, sealed result/artifact hashes, coverage/deferred-surface
  state, and budget truncation reason;
- grader code/model/prompt and oracle self-test result;
- transcript, typed actions, artifacts, filesystem diff, and provider usage.

Provider nondeterminism may prevent bit-for-bit replay. Tool-result replay should still
allow deterministic controller and scorer tests.

## Environment contract

Own a typed protocol and add a compatibility adapter:

```python
class SecurityEnv(Protocol):
    def reset(
        self, *, seed: int, task_id: str
    ) -> tuple[Observation, EpisodeInfo]: ...

    def step(
        self,
        action: ToolAction
        | SubmitFinding
        | SubmitDisposition
        | SubmitPatch
        | SubmitThreatModel
        | Abstain,
    ) -> tuple[
        Observation,
        RewardVector,
        bool,  # terminated
        bool,  # truncated
        EpisodeInfo,
    ]: ...
```

`TaskSpec` contains immutable input references, split/tags, authorization, an optional
pinned `SecurityContextBundle`, allowed tools, budgets, environment image, validation
plan/target manifest where applicable, and a private verifier reference. An
observation is the task plus bounded tool results and remaining budget, not hidden
grader state.

`terminated` means valid submission, verified success/failure, or a terminal policy
violation. `truncated` means token, dollar, tool, wall-time, or resource exhaustion.
Infrastructure error is an additional unscored episode status, not an MDP outcome.

Gymnasium provides useful `reset`/`step`/`terminated`/`truncated` conventions, seeding,
and wrappers. LLM tool actions are structured objects, however; do not distort them
into numeric action arrays just to claim Gym compatibility.

## Reward design

Retain a vector plus raw verifier events:

```text
correctness: valid unique finding/disposition/patch/threat model
evidence:    localization, path, preconditions, reproduction, citations
context:     provenance, freshness, contradictions, gaps, environment equivalence
coverage:    relevant surfaces examined without duplicate padding
safety:      authorization, tool, egress, secret, and grader integrity
efficiency:  cost, calls, tokens, wall time, and privilege requested
```

Scalar weights live in versioned experiment configuration so a weight change cannot
rewrite ground truth. Safety constraints are hard: unauthorized scope, egress, secret
access, sandbox escape, or grader tampering terminates the episode and cannot be offset
by a successful finding.

Use sparse terminal reward from hidden programmatic verification. Small shaping rewards
are acceptable only for independently observed milestones: a real crash, a reachable
security-sensitive sink, a security test that distinguishes vulnerable/fixed states,
or a patch that passes both security and regression tests.

Never reward self-reported confidence, length, command count, exact reference
trajectory, model-judge enthusiasm, or merely causing an error. Penalize false
positives, false dismissals, fabricated evidence, duplicates, broken functionality,
unsafe requests, and excess cost. Keep false-dismissal penalties severity aware but
report raw errors rather than hiding them in one score.

## Reward-hacking controls

- Hidden tests, answers, flags, verifier code, and reward secrets stay outside the
  agent namespace and network.
- Scorers consume content-addressed artifacts; they do not execute an agent-authored
  grader command.
- Gold/oracle solvers prove positive cases and clean controls prove negative cases.
- Impossible-task variants reveal assertion bypass or answer leakage.
- Alternate equivalent hidden tests and randomized canaries reduce overfitting.
- Network denial covers public solutions and newer patched code as well as package
  registries/caches, artifact stores, CI helpers, browser/request-capture/paste
  services, answer stores, and shared control services.
- Adversarial fixtures exercise proxy escape, shared-service traversal, discovered
  credential quarantine, and attempts to locate hidden answers or evaluator metadata.
- Environment and scorer failures are unscored.
- Every suspicious success, grader disagreement, high-risk dismissal, and random
  sample receives transcript/artifact review.

Keep training and evaluation task infrastructure physically or logically separated.
The experimental [Inspect RL](https://github.com/UKGovernmentBEIS/inspect_rl) project
explicitly warns that training on an Inspect task invalidates that task as a general
evaluation.

## Offline improvement loop

1. Run two to four diverse rollouts on frozen training/development cases.
2. Verify with deterministic graders; send ambiguous or high-risk outcomes to experts.
3. Store immutable exposed trajectories, typed actions, reward vectors, artifacts,
   filesystem diffs, manifests, and reviewer labels.
4. Diagnose failure by stage before changing the model.
5. Run paired experiments on prompt, retrieval, tool policy, routing, retry, stopping,
   attempt count, and budget. Vary one meaningful factor at a time.
6. Use constrained search or a contextual bandit over approved configurations to find
   a quality/cost frontier. The optimizer cannot grant new tools or scope.
7. Mine only expert/programmatically validated trajectories into examples or skills.
   Prevent same-task or clone retrieval during evaluation.
8. Promote on an untouched temporal holdout only when quality improves with confidence
   and safety, false-dismissal, cost, and latency gates all pass.

For closed OpenAI/Anthropic models, this controller is the principal improvable policy.
Provider fine-tuning/RFT, where available and contractually appropriate, is an optional
adapter. Generic GRPO cannot update closed API weights.

## Training ladder

1. **No training:** fix tools, task ambiguity, grader defects, retrieval, and prompts.
2. **Routing/policy optimization:** select approved model, effort, attempts, context,
   and escalation under hard constraints.
3. **SFT/preferences for owned open weights:** train routine triage/routing on
   expert-reviewed actions; keep consequence and proof generation human gated.
4. **Sandboxed RL for open weights:** only on purpose-built training tasks with a
   separate holdout and robust hidden verifier.

[NVIDIA NeMo Gym](https://github.com/NVIDIA-NeMo/Gym) is a useful future environment
and training adapter, while [NeMo RL](https://github.com/NVIDIA-NeMo/RL) supports
open-weight post-training. Both are materially heavier than the pilot, and NeMo Gym's
public documentation describes an evolving early-development system. Online RL against
live or public targets is explicitly out of scope.

## Promotion checklist

A candidate prompt/model/router/tool policy is promotable only when:

- it was not optimized on the release or temporal holdout;
- benchmark oracles and infrastructure health pass;
- clustered confidence intervals meet the preset capability threshold;
- high-severity false-dismissal and abstention gates pass;
- no safety or authorization metric regresses;
- quality-at-budget improves or an explicit owner accepts the tradeoff;
- shadow production matches the offline result within tolerance;
- the change, evidence, reviewer, and rollback configuration are recorded.

No single public leaderboard or mean reward can waive this checklist.
