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

## With the sandbox on

gVisor now runs on a Mac (see [Sandbox](#the-sandbox-on-a-mac) below), so the pipeline has been
measured end to end for the first time. Python corpus, 10 cases, live Qwen3.6-35B:

| metric | `--no-sandbox` | **sandbox on** |
| --- | --- | --- |
| accuracy | 40% | **90%** (9/10) |
| false negatives on exploitable cases | 100% *(structural)* | **25%** (1/4) |
| `potentially_exploitable` verdicts | 0 — impossible | **3**, each oracle-backed |

The 100% was never a judgement: with no oracle, `inconclusive` is the *correct* answer for an
exploitable case, so that column could only ever read 100%. **25% is the first real
false-negative rate this project has measured.**

Getting there took three runs and fixed four defects, none of which a `--no-sandbox` run can
show, because in that mode no probe ever executes:

1. **A hardcoded test path.** env-planner emitted `pytest -q -s tests/test_app.py`. The harness
   writes the probe where its author chose and substitutes `{test_file}`, so a hardcoded path
   ran a file that did not exist: exit 4, no test, `inconclusive`. Now rejected by an output
   validator — scoped to path-taking runners, since Maven and Gradle select by class name.
2. **Markers captured away.** Without `-s`, pytest buffers the probe's stdout, so a correct
   probe reports `precondition_reached=false` while exiting 0. Also now rejected.
3. **Every output ceiling was below its own worst case.** A run's output is bounded by
   `max_requests` x the per-call cap, and that cap is the backend's `min_max_tokens` floor —
   added so a reasoning model's thinking could not exhaust its budget before answering. All 11
   agents' ceilings were set from *observed* output, i.e. under the *possible* maximum. That is
   not a brake but a coin flip, and it failed a healthy prepare.
4. **The smoke test tested the wrong thing.** It ran `echo`, so a build that omitted pytest
   passed preparation and the absence appeared at probe time as exit 127 — past build repair,
   the only stage that could fix it. It now asks the runner for its version.

The pattern in all four: **the failure was invisible to the agent that could have reported it.**
A probe whose markers are buffered away looks like a probe that found nothing; a missing runner
looks like a defective probe. Each is now a deterministic check at the point where it is
knowable.

## Per-language, with the sandbox on

Measured after the Maven and Perl fixes below. Live Qwen3.6-35B, gVisor, one repeat.

| language | n | accuracy | accuracy with evidence | FN on exploitable |
| --- | --- | --- | --- | --- |
| python | 10 | 90% | — | 25% |
| perl | 4 | 75% | 25% | 50% |
| java | 4 | **100%** | 50% | **0%** |

Java took four runs to get there, and each step is worth more than the final number:
25% (all four cases building for the first time) -> 50% (H2 driver declared) -> 75%
(probe-repair given an exit from environmental failures) -> 100% (the Maven exemplar made to
satisfy its own validator). Wall time fell from 1583s to 561s and model calls from 130 to 75
across the last three, because most of what was removed was thrash rather than work.

**Read the "with evidence" column, not the headline.** Java's 100% is four for four on
labels, but two of those four — both `fixed` cases — reached `likely_not_exploitable` through
an `unreachable_by_context` early exit, with no build, no probe and no oracle behind them. The
reasoning was sound in isolation (`PreparedStatement` parameter binding and
`ProcessBuilder(list)` genuinely are sanitizers) but it is unverified, and the same confident
reasoning applied to a vulnerable case is a false negative — the costliest error this system
makes. It also varies between runs rather than being systematic: in the immediately preceding
run both of those cases *did* probe. So the negative half of the corpus exercises the probe
path only sometimes, and a headline accuracy cannot show that.

**Perl's 75% is partly unearned in the same way.** Both `fixed` cases returned
`likely_not_exploitable` via an `unreachable_by_context` early exit: no build, no probe, no
oracle. Two of the three "correct" cases never tested anything. The manifest declares an
expected early exit for exactly one case (`testonly`, which is test/vendored code and should
not be probed), so for the other 29 an early exit is a finding. `score_corpus` now reports
`accuracy_with_evidence` and names undeclared exits, because the reasoning path that scores a
`fixed` case right without evidence is the same one that, on a vulnerable case, is a false
negative.

### Three ways a test that never ran was scored as a result

Every failure in this round reduced to one mistake in a different place: something reported
success or a negative finding while zero tests had executed.

1. **Maven's warm-up ran nothing and reported `BUILD SUCCESS`.** Surefire resolves its
   *provider* lazily, at test-execution time, from the JUnit version on the test classpath. The
   warm-up ran against a fixture whose `src/test/java` holds only a `.gitkeep`, so Surefire
   short-circuited before provider selection, downloaded the plugin, and went green — then the
   offline probe failed on `surefire-junit-platform:3.2.5`. The warm-up now compiles and runs a
   throwaway `@Test`, which is what forces the download. `dependency:get` and
   `dependency:resolve-plugins` are both dead ends: the first leaves
   `junit-platform-launcher` absent at a version Surefire derives from the project, the second
   resolves the effective pom's Surefire 2.12.4. `offline_warmup_violations()` now rejects a
   warm-up that cannot have run a test — no `-Dtest=` selector, or `-DfailIfNoTests=false`,
   which is exactly what let the old one pass while running nothing.
2. **A selector handed a file path matched no class.** The planner wrote `-Dtest={test_file}`;
   the harness substituted `src/test/java/com/example/UserDaoTest.java`; Surefire reported
   `No tests matching pattern "..." were executed!` and the case burned its whole repair budget
   to `inconclusive`. The old check only required the selector to be non-empty, which a path
   satisfies. It now rejects a path-shaped selector and names the class to use instead.
3. **`prove` reported a zero-test run with no diagnostic at all.** On `perl-cmdi-vulnerable`:
   `skipped: (no reason given)` (a bare `1..0` plan), exit 255, and an **empty stderr**. The
   diagnosis reached the right *kind* (`probe_defect`) for the wrong *reason* — it guessed "the
   file was not written correctly" — so the repair rewrote a file that was never the problem
   and a genuinely exploitable finding came back `inconclusive`. `no_tests_executed()` now
   recognises that phrasing for all four runners deterministically, and
   `_ground_zero_test_diagnosis` replaces the speculative fix hint with the real short list of
   causes. A zero-test run is never a negative result: nothing exercised the sink.

The through-line is the same as the earlier four defects: **the failure was invisible to the
agent that could have reported it.** A warm-up that ran no test looks like a successful build;
a selector that matched nothing looks like a broken probe.

### What the four Java rounds found

Each round's failure was a different instance of one pattern: **an exemplar, a warm-up, or a
runner reporting success while nothing had actually been exercised.**

- **The exemplar was a trap.** `MAVEN_TEST_COMMAND` is the string several `ModelRetry` messages
  name as the command to write, and the validators rejected it — it omitted
  `-Dmaven.repo.local=/work/home/.m2/repository`. An agent that fixed its selector by copying
  the exemplar verbatim was bounced for a *different* violation than the one it had just
  corrected, oscillated between the two, and exhausted its retries into
  `environment_unbuildable`. The `build-maven` and `test-junit5` skills carried the same
  omission in their worked examples, which matters more, since the skill is read first —
  build-maven's own two-path rule already *said* the test command needs the `/work/home` path;
  the example just didn't do it. An exemplar that fails the checker it exemplifies does not
  teach, it traps. The invariant is now general: every canonical command must satisfy every
  validator.
- **The corpus under-declared a driver, exactly as Perl did.**
  `UserDao.getUser(Connection, String)` takes a connection rather than opening one, so the
  class is driver-agnostic and the pom declared none — but any test exercising it must pick
  one. Both remaining failures were that single missing dependency; H2 is now declared at test
  scope, which is what a real repo's test suite does.
- **probe-repair had no exit from an environmental failure.** The new looping report caught it
  re-reading `pom.xml` five times in every run, at up to 14 of its 16 requests. It had
  correctly sensed that `No suitable driver found` was not a probe defect, but having sensed
  that it had nowhere to go and kept searching a manifest it could not act on. Told to say so
  once and stop, it disappeared from the report entirely.
- **Both probe-writing agents were told there were two markers.** `probe-author` and
  `probe-repair` said "the two markers" long after the protocol defined three. The
  sink-returned marker was added as the fix for a measured false negative, and the two agents
  that actually write probe source were still being told to emit the marker set that produced
  that bug. The skill was always right; the prompts had drifted.

### Earlier, before all four cases built

The remaining failures at that point were model-side and individually diagnosable:

- `probe-planner` consumed its entire 16,000-token output budget in 287s with zero tool calls
  and produced nothing (`finish=length`). This is the largest single blocker.
- `describe_callables` hit its retry ceiling three times and aborted a finding, because its
  `ModelRetry` messages named the problem without naming the correction — a model passing a
  fully-qualified class name (very likely on Java) got only `'com.example.UserDao' does not
  exist.` The messages now resolve the likely file and name the path to use.
- Token ceilings were calibrated as if `input_tokens_limit` were per-call when pydantic-ai
  defines it as cumulative across a run. A 19-request run on a 1.3 kB repository reaches ~246k
  against a 120k ceiling; the same run with zero tool calls stays under it, so the ceiling only
  ever survived short runs.

`request_limit of 16` was deliberately **not** raised: the instructed procedure derives to <=13
requests on a 1.3 kB repository, so exhausting 16 is not legitimate work and raising the limit
would hide the bug. It could not be diagnosed from the record either, because
`inspect_messages` de-duplicates tool names and discards arguments, making eight re-reads of
one file byte-identical to one read. Runs now record request counts and repeated identical
calls, and the corpus report prints a `LOOPING` marker naming the worst offender.

**That decision was vindicated on the next run.** The report named probe-repair immediately —
14 of 16 requests, `read_file(path='pom.xml')` five times, in 4 of 4 runs — while every other
agent sat well under its ceiling with zero repeats. The breach was a loop, not a tight limit,
and it is now gone: the worst remaining entry is a single tool called twice.

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

## The sandbox on a Mac {#the-sandbox-on-a-mac}

gVisor needs a Linux host kernel, so it cannot run on macOS directly. It can run *inside* a
Linux VM, which is how these numbers were obtained:

- `runsc` installed in a dedicated podman VM (Fedora CoreOS, aarch64), its sidecars beside the
  binary and registered as the VM's default OCI runtime.
- A `docker` -> podman translation shim. It reports `docker info`'s runtimes **truthfully**, so
  the harness's fail-closed check passes on the real thing rather than on an override:
  `HARNESS_ALLOW_INSECURE_RUNTIME` is not set for any of these runs.
- Probes execute under `Linux version 4.19.0-gvisor`, with no network.

Two limits to read with the numbers. **Builds run under crun, not gVisor**: under runsc, buildah
does not persist a directory created by one `RUN` into the next layer — isolated by building the
identical Dockerfile under both runtimes. So build-time containment is still unverified; probe
time, where untrusted model-authored code actually executes, is what these runs cover. And this
is podman-in-a-VM rather than Docker, so it validates the corpus and the isolation boundary, not
the production `docker` + `runsc` path.

## Still unverified

**Build-time gVisor containment.** Probes run under gVisor; image builds do not, because under
runsc buildah does not persist a directory created by one `RUN` into the next layer. The build
step is where a repository's own `setup.py`, Gradle task or postinstall hook executes, so that
is a real gap and the reason RISK-SEC-001 keeps `CTRL-SBX-001` at `implemented` rather than
`verified`. Also unexercised: the buildx builder, the egress allowlist, and the Kubernetes
probe namespace under `deploy/k8s/`.

**The production `docker` + `runsc` path.** These runs go through a podman translation shim
inside a Linux VM. That validates the corpus and the isolation boundary, not the deployment.

**Tier routing and prompt caching.** All 11 agents resolve to `sonnet`/`balanced-v1`, and the
test endpoint serves one model, so `fast-v1` and `reasoning-v1` have never executed. Cache-hit
is 0.0% in every run despite a prompt layout built for cache stability — unverified against a
backend that reports cached tokens at all.

**A second model.** Every accuracy number here is one mid-size open-weights model. The
*mechanisms* found generalise — a hardcoded test path, buffered markers, an output ceiling below
its own worst case, a smoke test that tests the wrong thing are all model-independent — but the
rates do not. Running the corpus against Bedrock would separate "our prompts are weak" from
"this model is weak", and would be the first real test of the caching claim.

The corpus's own ground truth *is* verified independently of all this: `test_corpus.py` only
checked structural consistency, so a "vulnerable" variant accidentally written safe would pass
every test while invalidating the expected verdict all scoring is measured against.
`tests/test_corpus_oracle.py` drives each paired Python variant with a reference probe and reads
the result through the harness's own `oracle_signals`. All eight behave.

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
