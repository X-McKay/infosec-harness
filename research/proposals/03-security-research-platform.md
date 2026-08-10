# Proposal 3: Security Research and Improvement Platform

## Summary

Build a dedicated, distributed platform for large cyber-evaluation campaigns,
high-assurance isolated environments, trajectory collection, controller optimization,
and optional open-model fine-tuning. This includes the controlled service from
Proposal 2 but separates production, evaluation, data curation, and training into
different trust zones.

This is not the recommended starting point. It is appropriate for an organization
running a sustained security-model research program, not merely using closed models to
improve AppSec work.

## Intended deployment

- Dedicated security/evaluation researchers plus platform and AppSec owners.
- Thousands of isolated multi-step episodes and repeated stochastic trials.
- Private benchmark creation, temporal holdouts, red-team environments, and local
  GPU training.
- Higher-risk historical vulnerability reproduction or synthetic ranges.
- Strong reproducibility and experiment lineage requirements.

## Architecture

```text
                 production control plane
                         |
              approved policy candidates only
                         |
  -----------------------------------------------------------
  |                    research zone                         |
  |                                                         |
  | dataset/context registry -> experiment scheduler -> Inspect|
  |        |                    |                 |           |
  | split firewall       isolated episode pool   scorers     |
  |        |        worker + target micro-ranges   |         |
  | trajectory lake <--------- events ---------- reward svc  |
  |        |                                      |          |
  | offline analysis -> prompt/router search -> candidate    |
  |        |                                      |          |
  | optional GPU zone: SFT/DPO/GRPO on open models           |
  -----------------------------------------------------------
                         |
               fixed held-out safety/capability gates
                         |
                   signed promotion bundle
```

The production service never imports a research prompt, router, model, tool, image, or
policy automatically. Promotion produces a signed, reviewable bundle with evaluation
evidence and rollback metadata.

## Platform components

### Dataset and environment registry

Each task version records:

- provenance, license, sensitivity, and intended use;
- immutable repository/data snapshot and container/microVM image digests;
- immutable `SecurityContextBundle`, signed target manifest, declared/observed fact
  provenance, contradictions, coverage gaps, and environment-equivalence claims;
- train/development/test designation and access policy;
- repository, time, project family, language, CWE, and difficulty strata;
- task authorization, tools, network profile, and resource limits;
- hidden grader/reward version and gold-oracle self-test;
- known contamination and benchmark-validity risks.

A split firewall prevents training and prompt-search jobs from reading held-out task
contents, grader source, answer keys, or test artifacts. Merely marking a directory
`test` is not isolation.

### Experiment scheduler

Schedule a Cartesian but budgeted experiment over model, exact version, provider,
prompt, tool policy, reasoning level, scaffold, attempt count, and seed. Require an
experiment hypothesis and maximum spend. Adaptive experiment allocation may stop
clearly inferior configurations, but the stopping rule is recorded before the final
test.

Use Inspect as the primary eval abstraction and adapters for upstream benchmark
harnesses. Keep the original scorer semantics and record any deviation. Oracle agents
or gold patches validate that an environment and scorer can succeed before expensive
model runs.

### Episode isolation

Use a stronger boundary for exploit-capable tasks: dedicated nodes with gVisor or Kata
Containers, or microVMs such as Firecracker where the operational environment supports
them. Images are minimal, signed, digest-pinned, scanned, and rebuilt from source.
Episode networks contain only synthetic targets and a controlled proxy when required.

Exploit-capable episodes separate the agent worker from the target range. The worker
can reach only named synthetic target services; the target cannot reach the worker's
provider path, scheduler, verifier, evidence collector, or kill switch. Identity,
storage, queue, notification, payment, webhook, DNS, metadata, and callback services
are deterministic local fakes. Active actions require immutable validation plans and
registered out-of-band oracles.

The agent cannot reach the scheduler, grader/reward service, answer store, cloud
metadata, peer episodes, production code, or provider credentials. Destroy or reimage
the compute boundary between sensitivity classes.

### Trajectory store

Store exposed messages, typed actions, bounded observations, state transitions,
rewards, policy decisions, resource usage, artifacts, and reviewer labels. Do not
collect hidden chain-of-thought. Apply secret scanning/redaction before persistence;
encrypt and restrict vulnerability trajectories as sensitive security data.

### Scoring and reward service

Scorers run outside the episode boundary and receive content-addressed artifacts, not
an agent-controlled command. Prefer programmatic hidden tests and exact state checks.
Model graders handle only rubric dimensions that cannot be made deterministic and are
calibrated against security experts.

Reward code and secrets are inaccessible to the agent. Randomized canaries, alternate
equivalent tests, impossible-task controls, and grader-infrastructure health checks
detect reward hacking and benchmark exploitation.

## Gym and improvement path

The environment follows the contract in
[Evaluation and gym](../evaluation-and-gym.md). The improvement ladder is deliberately
ordered from least to most risky and expensive.

### Level 1: offline diagnosis

Cluster failures by workflow state, tool behavior, missing context, model refusal,
hallucinated evidence, budget stop, and infrastructure error. Improve task contracts,
tools, retrieval, prompts, and graders before training anything.

### Level 2: controller optimization

Use development trajectories to choose model tier, reasoning level, retry, retrieval,
attempt count, and escalation. A constrained contextual bandit can minimize cost under
quality/safety thresholds. The action set contains approved configurations only.

### Level 3: prompt/policy search

Search concise system prompts, examples, tool descriptions, and stop rules against
training/development tasks. Penalize tokens and policy violations. Require broad
held-out evaluation because benchmark-specific prompt overfitting is easy.

### Level 4: supervised/preferences training

For an approved local open-weight model, train on expert-reviewed actions and
dispositions. SFT or preference methods are easier to debug than end-to-end online RL.
Use the model for routine routing/triage only until independent gates support more.

### Level 5: sandboxed RL

Only then consider GRPO or another RL method for open models in synthetic or historical
tasks. Inspect RL demonstrates a connection between Inspect task rewards and TRL, but
its repository explicitly labels itself experimental research code with no maintenance
commitment. Vendor reinforcement fine-tuning is provider-specific and must remain an
optional adapter, not the platform architecture.

Never perform policy-gradient updates from production scans, live systems, public
targets, held-out evals, or unreviewed model-judge rewards.

## Reward design

Use a lexicographic safety constraint or hard episode termination before scalar task
reward. A policy violation cannot be offset by finding a vulnerability.

An illustrative decomposed reward is:

```text
hard fail: unauthorized scope/egress/secret access, sandbox escape, grader tampering

task reward:
  + independently validated unique vulnerability or correct disposition
  + correct localization, preconditions, exploitability reasoning, safe patch/tests
  + calibrated abstention on insufficient evidence
  - false positive and especially false dismissal of a real high-impact issue
  - unsupported/fabricated evidence, duplicate claim, broken functionality
  - unnecessary calls, tokens, wall time, retries, and excessive privileges requested
```

Do not expose the exact scalar weights or hidden checks to the episode. Report each
component separately; a single reward number conceals dangerous tradeoffs.

## Benchmark program

Maintain three lanes:

1. **Public comparison:** pinned CyberGym/CyBench/CVE-Bench/SEC-bench and agent-safety
   tasks for ecosystem comparability. Treat contamination as likely.
2. **Private temporal evaluation:** vulnerabilities, safe patches, clean controls, and
   false-positive traps whose disclosure postdates model training/access where
   possible. This is the release gate.
3. **Training/development gym:** procedurally varied and historical tasks designed for
   optimization, never reported as generalization evidence.

Add internal threat-model and backlog-triage tasks because public offensive benchmarks
do not represent those workflows. Balance negative cases and include cases where
abstention is correct.

Add a remediation lane with an independently verified patch, functional regression
tests, owner-review simulation, and a deployed-artifact check. A discovery-to-patch
benchmark is incomplete when it rewards a plausible patch that does not land or does
not hold in the represented deployment.

Add context-retrieval tasks with stale, contradictory, missing, and poisoned external
facts, plus validation tasks where the correct outcome is `not_reproduced`,
`invalidated`, `not_applicable`, `environment_mismatch`, `policy_blocked`, or
`authorization_failed`, `infra_error`, or `cleanup_failed`. Otherwise optimization
will teach the controller to equate a
failed experiment with a false positive.

## Security and governance

This proposal concentrates offensive capability and sensitive data. Require:

- formal authorization and acceptable-use review for every task family;
- tiered access to vulnerability details, proof artifacts, and exploit-capable tools;
- disclosure coordination and embargo handling;
- separate cloud accounts/projects, identities, keys, networks, and storage for
  production, evaluation, and training;
- no unrestricted internet egress from episode or GPU environments;
- signed datasets/images/promotion bundles and complete lineage;
- anomaly detection for unusual tool, network, secret, artifact, and cost behavior;
- kill switches at episode, experiment, tenant, provider, and platform levels;
- periodic independent sandbox and benchmark-security review;
- review of licenses and vulnerability-disclosure obligations before dataset use.

Model safety filters and provider cyber policies can block legitimate episodes. Record
policy stops separately, use approved research-access programs, and never evade a
provider safeguard as a retry strategy.

## Cost strategy

Research cost is controlled at experiment design:

- smoke-test one or two samples and validate the scorer with an oracle;
- use cheap/replay models for harness debugging;
- preregister the comparison and cap total trials;
- allocate repeated attempts only where pass@k is a relevant product objective;
- stop configurations that fail infrastructure or safety prerequisites;
- use provider batch/caching only for data that is eligible under current terms;
- schedule local GPU experiments by measured utilization and total energy/compute;
- preserve full lineage so an unchanged result is not recomputed;
- report quality-cost frontiers instead of a single leaderboard.

Include platform engineering, sandbox capacity, labeling, reviewer time, and incident
response in total cost. API tokens are only one component.

## Delivery sequence

### Phase 1: reproducible evaluation platform

Build registry, split firewall, experiment manifests, Inspect integration, oracle
self-tests, evaluation storage, statistics, and signed reports. Reuse Proposal 2
workers initially.

### Phase 2: high-assurance episode pool

Add isolated accounts/nodes, gVisor/Kata/microVM runtime, synthetic network ranges,
signed images, reward-service separation, and sandbox red-team tests.

Add context snapshots, validation-plan and target-manifest signing, separate worker
and target guests, deterministic service fakes, out-of-band health/oracle collection,
and independent teardown janitors.

### Phase 3: trajectory and controller lab

Add redacted trajectory storage, replay, failure analysis, constrained routing/prompt
experiments, and production shadow evaluation.

### Phase 4: optional GPU training

Add a separately approved GPU zone, open-model registry, SFT/preference baselines, then
limited sandboxed RL only if simpler improvements plateau and the reward is robust.

A credible platform is a multi-quarter program. A small senior team should plan on at
least 30-50 engineer-weeks beyond Proposal 2 before optional model training, plus
ongoing security research, labeling, infrastructure, and operations. High-assurance
microVM and GPU work can substantially increase that range.

## Acceptance criteria

- Dataset permissions technically enforce train/development/test separation.
- Oracle runs prove every task and scorer; infrastructure failures cannot become model
  failures or rewards.
- Episode agents cannot observe or alter graders, rewards, answer keys, other episodes,
  production systems, control-plane APIs, secrets, or unauthorized networks.
- Episode agents cannot alter context provenance, target equivalence claims,
  validation plans, health thresholds, external oracles, or teardown evidence.
- Every result is reproducible from immutable code/data/image/model/prompt/policy
  versions and a recorded seed/budget, subject to provider nondeterminism.
- Reward-hacking controls detect answer-file access, grader tampering, output injection,
  and impossible-task cheating.
- A signed promotion bundle passes private held-out capability, false-dismissal,
  calibration, safety, cost, and latency gates in shadow mode.
- Rollback requires no retraining and is rehearsed.

## Advantages

- Strongest isolation and experiment lineage.
- Supports realistic repeated agent evaluation and private temporal benchmarks.
- Enables principled controller optimization and optional local-model training.
- Makes quality, safety, and cost frontiers measurable rather than anecdotal.

## Limitations

- Highest fixed cost, staffing need, and operational attack surface.
- Benchmark construction and expert labels are often harder than runtime engineering.
- RL can optimize evaluator flaws and reduce external validity.
- Closed model weights cannot be trained locally; much of the platform may only tune
  the controller.
- Results can still be contaminated, scaffold-specific, and non-generalizing.

## Decision rule

Choose this proposal only if at least two of these are funded objectives: continuous
private benchmark development, high-risk cyber-range evaluation, local open-model
fine-tuning, large-scale controller research, or publication-grade reproducibility.
Otherwise Proposal 2 plus a disciplined Inspect suite provides most practical value
with far less risk and cost.
