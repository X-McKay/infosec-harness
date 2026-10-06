---
name: cwe-1333-regex-denial-of-service
description: Regexes that backtrack catastrophically on untrusted input (ReDoS). Use this when the finding is CWE-1333 or a regex matches untrusted input.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-1333: Regular expression denial of service (ReDoS)

## Use this skill when

- The finding is CWE-1333, or names ReDoS or catastrophic backtracking.
- Untrusted input is matched against a regex containing nested/overlapping quantifiers
  (`(a+)+`, `(a|a)*`, `(.*)*`, `(\d+)*$`) or ambiguous alternation followed by a required tail.

## Do not use this skill when

- The cost is from input volume or allocation, not backtracking — use
  `cwe-400-uncontrolled-resource-consumption`.
- A plain loop fails to terminate — use `cwe-835-infinite-loop`.
- The engine is linear-time by construction (RE2, Rust `regex`, Go `regexp`) — note it and
  usually return `likely_not_exploitable`.

## When another skill also applies

- `cwe-400-uncontrolled-resource-consumption` is the general CPU/memory DoS class. **This skill
  wins** when the specific mechanism is regex backtracking; the oracle here is a timing-growth
  measurement on a vulnerable pattern.

## Procedure

**Sink.** A regex match/search/validate where the pattern has exponential or high-polynomial
backtracking and the input (or the pattern) is attacker-influenced: `re.match`/`re.search`,
`String.matches`, `RegExp.test`, validation of emails/URLs/paths with a hand-rolled pattern.

**Guard.** A linear-time engine, an input length cap applied before matching, a de-nested
(possessive/atomic or anchored) pattern, or a match timeout.

**Neutralized when.** The pattern cannot backtrack catastrophically, the input length is capped
small before matching, or a linear engine / timeout bounds the work.

## Oracle

Condition: **match time grows super-linearly as a crafted input lengthens, while a benign input
stays flat.** Use an adversarial string that maximizes backtracking (a run of the repeated class
plus a single breaking character, e.g. `"a"*n + "!"`), at two or three *small* lengths.

- Set a **strict wall-clock cap far below the command timeout** (e.g. 2 seconds) around each
  match, using a worker thread/`signal.alarm`/`AbortController`, so a single size can never run
  to the budget kill. Record the time or the cap-hit for each size.
- Keep the sizes small (e.g. n = 16, 24, 32). A pattern that jumps from milliseconds to the cap
  across a handful of extra characters is catastrophic backtracking.
- Compare against the same pattern on a benign input of the largest size, which must stay fast.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real validation/match callable ran with the crafted input, including when
  its length cap rejects it first.
- `oracle_valid`: at least two sizes were timed under the strict cap and the growth is computed;
  the measurement never relied on the command-budget kill.
- `positive_control`: the finding's pattern matched directly against the crafted inputs shows the
  steep time growth, proving the oracle discriminates.
- `negative_control`: the same pattern on benign input of the largest size stays fast and well
  under the cap.
- `vulnerability_observed`: the crafted input through the real target showed the super-linear
  growth (or hit the strict cap at a small size) with no input-length guard neutralizing it.

A target that caps input length or uses a linear engine is `target_reached: true,
vulnerability_observed: false`.

## Language notes

- **Python `re`:** backtracking engine — vulnerable patterns are real here; use a worker thread or
  `signal.setitimer` for the per-match cap (do not rely on `re`'s own timeout; there isn't one).
- **JS:** V8's engine backtracks; wrap the match in a worker or measure with a tight budget. Note
  if the code already uses a linear library.
- **Java:** `java.util.regex` backtracks; `Pattern` with possessive quantifiers/atomic groups is
  the guard.
- **Linear engines (RE2, Go `regexp`, Rust `regex`):** not vulnerable to this class; identify the
  engine before timing.

## Pitfalls

- A single slow run does not prove ReDoS — a large input is slow everywhere. The signal is the
  *growth ratio across small sizes*, with benign input flat.
- Never let a match run to the command budget to "prove" it: use the strict in-probe cap so the
  observation is a measured growth or a small-size cap breach, not an exit 137.
- Match the adversarial suffix to the pattern (the breaking character must force backtracking);
  the wrong suffix gives a silent false negative on a genuinely vulnerable pattern.
- Confirm the attacker controls the *input*; if only a fixed internal string is matched, the
  pattern cannot be driven and the finding may not apply.

## Verdict guidance

- `potentially_exploitable` needs a complete probe showing super-linear growth (or a small-size cap
  breach) through the real target, both controls green.
- `likely_not_exploitable` needs a linear engine or an input-length cap cited at its line, and a
  probe showing flat timing.
- `inconclusive` when timing is too noisy to separate growth from constant cost, or the input
  cannot be driven; say which.
