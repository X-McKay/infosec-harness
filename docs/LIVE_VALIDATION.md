# Live-model validation

What changed when the harness was first pointed at a real model instead of the deterministic
stubs, what the agents actually do, and what is still unverified. Run against
**`llm.almckay.io`**, an OpenAI-spec endpoint serving one vLLM model,
`Qwen3.6-35B-A3B-NVFP4` — a mid-size open-weights MoE, not a frontier model. Read the
accuracy numbers with that in mind; the *mechanisms* they expose generalise, the absolute
values do not.

```bash
export HARNESS_MODEL_MODE=live HARNESS_MODEL_BACKEND=gateway
uv run harness eval corpus --no-sandbox --language all
uv run harness eval run verdict --repeat 6
```

## What a live model broke that stubs could not

Stub models answer instantly, always satisfy their output schema, and never call a tool.
Every item below was invisible until a real model ran, and four of them stopped the pipeline
outright.

| Problem | Effect | Fix |
| --- | --- | --- |
| Two consecutive system messages (instructions + the Skills capability's deferred-capability preamble) | HTTP 400 `System message must be at the beginning` on **9 of 11 agents** | merge the leading system run for OpenAI-spec backends (`merge_system_messages`) |
| Reasoning billed against `max_tokens` | agents died with "token limit exceeded before any response was generated" — the specs budget for Anthropic's *separate* thinking budget | per-backend `min_max_tokens` floor rather than inflating 11 specs for one endpoint |
| `context` emitted the nested `sink` as a JSON **string** while getting the sibling `list[CodeRef]` right | burned the agent's output retries, then killed the run | decode a nested object that arrives as a JSON string; a string that is not an object is still rejected |
| Model catalog named ids the endpoint does not serve | first call failed | point the `gateway:` column at the served model |
| One 502 `upstream_unreachable` | discarded a whole batch — outside Temporal nothing retried | per-backend `max_retries` |
| `verdict` repeated an `inconclusive` verdict five times, each omitting the contract-required `inconclusive_reason` | exhausted retries; the exception killed the finding **and the batch behind it** | fall back to `inconclusive`/`error`; say in the prompt that the field is required |
| `load_capability` exceeded its tool retries on one case | raised out of `triage_batch_local`, discarding every finding already triaged | contain per-finding failures as `inconclusive`/`error` and continue |

Two of these were latent harness bugs rather than endpoint-compatibility issues, and both
were about **unbounded or uncontained failure**:

- `TemporalOps` scheduled its activities with no retry policy, so they inherited Temporal's
  *unlimited* retries. A deterministic error retried forever and the workflow hung instead of
  failing. `tests/test_workflow_integration.py` had a `run_probe` double with a stale
  signature, which is what that looks like from outside: the test did not flake in the cloud,
  it hangs forever anywhere. Both fixed; the test now passes locally in seconds.
- `--no-sandbox` reported `exit_code=0, precondition_reached=True` — *a probe that ran and
  found nothing*. `probe-diagnosis` reads the probe source next to those markers, concludes a
  known-vulnerable target producing no oracle means the probe is defective, and the graph
  repairs it — every case, to the repair limit. Those repair turns dominated the run: context
  grew 8.8k → 24k tokens over three turns with 6–7k-token outputs at ~100s each. The stub now
  reports what the real sandbox-unavailable path reports. The Python corpus went from stalling
  to finishing in 16 minutes.

## Where the agents do well, and where they do not

22 cases, four languages, `--no-sandbox`.

| language | n | accuracy |
| --- | --- | --- |
| python | 10 | 40% |
| javascript | 4 | 50% |
| java | 4 | 25% |
| perl | 4 | 25% |
| **all** | **22** | **36%** |

| expected | n | recall |
| --- | --- | --- |
| `likely_not_exploitable` | 12 | 67% |
| `potentially_exploitable` | 10 | **0%** |

**That 0% is an artifact of the run mode, not a judgment failure.** With no sandbox there is
no oracle signal, and the verdict contract forbids `potentially_exploitable` without one — so
the only correct answer on a truly-exploitable case is `inconclusive`, which is what all ten
produced. The number that matters here is the inverse: **no case in any run ever claimed
`potentially_exploitable` without oracle evidence.** The core safety property holds.

So the useful accuracy signal without a sandbox is the 67%: `context` deciding, from the code
alone, that a sanitizer makes the sink unreachable. Seven of the eight correct verdicts came
via the `unreachable_by_context` early exit; one was `test_or_vendored`.

### Tool and skill evocation

| agent | tools | skills |
| --- | --- | --- |
| `recon` | 100% | *not checked* |
| `env-planner` | 100% | *not checked* |
| `context` | 100% | 100% (was **19%**) |
| `probe-author` | 100% | 100% |

`recon` and `env-planner` previously reported "skills 100%" — but neither has any
`skill_prefixes`, so the check passed trivially and nothing was ever asserted. They now report
`n/a`. Giving them real expectations (`lang-`, `build-`) is the obvious next step; until then
their skill behaviour is unmeasured.

### The `context` skill-evocation gap

`context` was the only agent failing skill evocation — 19% across the corpus, and 0% on one
Python pass. The cause was prompt *mood*, not capability: it named the skills in a trailing
descriptive sentence, placed after "Be concise" —

> Cite only lines you actually read. Be concise. The cwe-\* skills describe, per weakness
> class, what a source and sink look like and which sanitizers neutralize the path.

— while every agent scoring 100% words it as an instruction ("Follow the
probe-oracle-protocol skill exactly", "using the matching cwe-\* skill"). Making it step zero,
one variable changed, both arms on the same commit:

| | context unchanged | imperative directive |
| --- | --- | --- |
| skill evocation | 44% (4/9) | **100% (9/9)** |
| accuracy | 40% | 50% |
| model calls | 167 | **148** |
| wall time | 1445s | **1094s** |

The evocation change is the result, and it held at 100% in all four languages on the
confirmation sweep. Loading the skill first made the run *cheaper*, not dearer — `context`
settles sooner with the sanitizer list in front of it. Treat the accuracy line as
directionally consistent only; see the variance note below.

This matters because the two fixed variants `context` most often misses — `cmdi-fixed` and
`xss-fixed` — are neutralized by exactly the constructs the `cwe-78` and `cwe-79` skills name
verbatim (`subprocess.run([...], shell=False)`, HTML-encoding).

### Two skills contradicted each other

`probe-oracle-protocol` is the contract every probe is written against, and one of its rules
is *"Reach the real sink. Call the smallest real callable that owns the sink. Do not mock the
sink."* `cwe-89` presented "capture the SQL handed to the driver via a fake/stub connection"
as its **preferred** oracle — the more specific skill telling the author to break the general
contract, so that is the advice that won.

Observed live: `probe-author` wrapped the sqlite cursor in a `_LogCursor`/`_LogConnection`
pair to read `cur.last_sql`, the wrapper was not the object `get_user` actually used, the
oracle could never fire, and `probe-diagnosis` correctly called the probe defective. **A
silent false negative dressed as a clean run** — the costliest failure this system can have.

`cwe-89` now prefers the result oracle (seed a row the intended `WHERE` excludes, call the
real callable, fire when it comes back) and keeps the structure oracle as a fallback via a
non-invasive hook on the real connection (`set_trace_callback`, a driver statement logger,
SQLAlchemy's `before_cursor_execute`). `cwe-918` keeps its fake transport — SSRF genuinely
cannot use the real sink, since the sandbox has no egress — but now names the same hazard and
says to verify the target actually uses the injected client.
`tests/test_skills_consistency.py` holds the invariant so the two cannot silently diverge.

Where no such conflict existed, `probe-author` was consistently good: its command-injection
probes call the real sink with an injected payload and check for the canary, which is exactly
what the protocol asks.

### Per-agent evals

| agent | cases | runs | accuracy |
| --- | --- | --- | --- |
| `verdict` | 3 | 27 | 96% (26/27) |
| `probe-diagnosis` | 7 | 21 | **100%** |

`probe-diagnosis`'s dataset previously sent only `probe_execution`, while the graph sends
`probe_plan` + `probe_source` + `probe_execution` — so the eval scored a prompt shape that
never runs, and the marker-only cases are easy in a way the real ones are not. Four cases now
carry the plan and source the graph really sends, including the one that matters most in
production: a clean negative on a vulnerable-looking target, where treating "the oracle did
not fire" as a defective probe would send the graph into a repair loop on the *common*
outcome. It scores 100% on all of them.

`verdict`'s single failure is `inconclusive_env`, where `environment_ready: false` forces
`inconclusive_reason = environment_unbuildable` and it picked something else.
`experiments/verdict_forced_reason.yaml` states that forcing rule explicitly; it and the
committed prompt both score 18/18 at `--repeat 6`, so it is **not promoted** — no measurable
benefit at a sample size that can resolve an ~11% failure, and the graph fallback covers the
residual.

## Read these numbers with the variance in mind

Running the *same* configuration twice moved `context`'s skill-evocation rate between **0%
and 44%**, and shuffled which cases were right while leaving accuracy identical at 40%. On 10
cases with a stochastic model, a single pass cannot separate a small effect from noise.
`eval corpus` now takes `--repeat` and `--language all` and prints `mean [min-max]`, matching
what `eval run` already had. Repeat both sides of any A/B; a one-case accuracy difference is
not a result.

## Still unverified

**The gVisor sandbox has never run.** This host has no Docker and no `runsc` — gVisor needs a
Linux host kernel, so it cannot run on macOS at all. Podman is present, but podman-remote
rejects the `--runtime` flag the hardening requires, and bending that would mean changing the
thing under test. So nothing below is confirmed at runtime: the gVisor build/probe path, the
buildx builder, the egress allowlist, read-only root, or a real probe firing a real oracle
inside a container. `HARNESS_ALLOW_INSECURE_RUNTIME=true` exists for dev, and weakens
isolation.

What *was* confirmed instead is the corpus's own ground truth, which was previously untested:
`test_corpus.py` only checked structural consistency, so a "vulnerable" variant accidentally
written safe would pass every test while silently invalidating the expected verdict all corpus
scoring is measured against. `tests/test_corpus_oracle.py` now drives each paired Python
variant with a reference probe written to the real marker protocol and reads the result
through the harness's own `oracle_signals`. All eight behave: the vulnerable variant fires the
oracle, the fixed one does not, and both reach the precondition. These run in-process, so they
assert the corpus is sound — not that the isolation is.

**The remaining gVisor pass to do on a Linux host with `runsc`:** run
`uv run harness eval corpus` with the sandbox on and confirm the Python vulnerable cases build
and fire their oracle while the fixed variants do not, then repeat for a Java/JS/Perl case to
exercise those toolchains through the buildx path. Only that run can produce a real
`potentially_exploitable` verdict, and therefore a real false-negative rate.

## Other things worth doing

- **Give `recon` and `env-planner` real skill expectations.** Their skill behaviour is
  currently unmeasured, and `recon`'s prompt has the same passive phrasing that cost `context`
  80 points of evocation ("The lang-\* skills describe conventions per ecosystem").
- **`eval run` loses completed work on a transport failure.** It catches only
  `UnexpectedModelBehavior`, and writes to the database after the loop, so an endpoint blip
  late in a `--repeat 6` run discards every case already scored. Persisting incrementally
  would have saved two runs during this exercise.
- **Only `verdict` and `probe-diagnosis` have eval adapters,** so `harness eval run <agent>
  --overlay` — the documented way to test one variable — does not work for the other nine.
  `context` is the one most worth adding, since it produces the only accuracy signal available
  without a sandbox.
- **Tier differences are not exercised here.** The test endpoint serves one model, so all
  three tiers map to it; `opus`/`sonnet`/`haiku` routing is still only tested against Bedrock
  ids that were never called.
