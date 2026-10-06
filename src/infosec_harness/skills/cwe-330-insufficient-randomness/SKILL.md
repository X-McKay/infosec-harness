---
name: cwe-330-insufficient-randomness
description: Security tokens, ids, keys or nonces from a predictable generator. Use this when the finding is CWE-330/338/340/1241.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-330: Insufficient randomness (also CWE-338, CWE-340, CWE-1241)

## Use this skill when

- The finding is classified CWE-330, CWE-338 (weak PRNG), CWE-340 (predictable numbers or
  identifiers) or CWE-1241 (predictable algorithm in a random number generator).
- Session ids, reset tokens, API keys, CSRF tokens, salts, IVs or one-time codes come from
  `random`, `Math.random`, `java.util.Random`, Perl `rand`, a time or counter value, or a
  generator seeded with a guessable value.

## Do not use this skill when

- The value has no security role (shuffling a UI list, sampling for metrics).
- The token is random but never checked — use `cwe-287-improper-authentication`.
- The salt or IV is constant — use `cwe-327-broken-crypto`.

## When another skill also applies

- `cwe-384-session-fixation` also fires on session ids. **That skill wins** if the id survives
  login unchanged; this skill wins when a fresh id is issued but predictable.
- `cwe-327-broken-crypto` wins for absent or constant salts; this skill wins for varying but
  predictable ones.

## Procedure

**Sink.** Use of the generated value as a secret: issuing a session or reset token, storing
an API key, setting a nonce or salt.

**Guard.** A cryptographically secure source: `secrets`, `os.urandom`,
`crypto.randomBytes`/`randomUUID`, `SecureRandom`, `/dev/urandom` or `Crypt::URandom` in Perl,
with enough output bits (128 or more for bearer tokens).

**Source.** The generator's state: seed, time of issue, counter, or previously observed
outputs the attacker can collect.

**Neutralized when.** Every security value on the path comes from a CSPRNG with adequate
length, and no code path reseeds it deterministically.

## Oracle

Condition: **the probe reproduced the target's token from information an attacker has.**
Never claim predictability from the API name alone; demonstrate it.

- **Seeded generator:** seed the language's PRNG with a known value the way the target or its
  runtime allows (`random.seed`, a fixed `Date.now` via a fake clock the target itself reads,
  `srand`), call the real token function, then regenerate the same sequence independently and
  compare.
- **Time or counter based:** fix the clock the target reads, or issue two tokens and derive
  the second from the first.
- **Engine state recovery** (V8 `Math.random`, Mersenne Twister): this needs many outputs and
  a solver; if the probe cannot do it simply, show the generator source instead and report
  `inconclusive` rather than a weakened claim.

Map the result onto `HARNESS_PROBE`:

- `target_reached`: the real token function ran under the controlled seed or clock.
- `oracle_valid`: the prediction uses only what an attacker has: the seed, the clock or earlier
  tokens.
- `vulnerability_observed`: the independently predicted value equals the target's output.
- `positive_control`: a probe-owned call to the same weak generator under the same seed is
  reproducible, proving the prediction method works.
- `negative_control`: a CSPRNG value (`secrets.token_hex`, `crypto.randomBytes`) is not
  reproduced by the same method.

## Language notes

- **Python:** `random.random/choice/getrandbits` versus `secrets`; `uuid1` embeds time and MAC;
  `uuid4` is fine.
- **JavaScript:** `Math.random().toString(36)` tokens. `node --random-seed=<n>` makes V8's
  `Math.random` deterministic: run the real token function in one child process and the same
  sequence of `Math.random` calls in another with the same seed, and compare. Replacing
  `Math.random` in the probe is a stand-in. `Date.now()`-based ids.
- **Java:** `new Random(System.currentTimeMillis())`, `Random` versus `SecureRandom`;
  `RandomStringUtils.random` (non-secure in older commons-lang).
- **Perl:** `rand`, `srand(time)`, `int(rand(1e6))` codes; `Data::UUID` time-based.

## Pitfalls

- Overriding the generator in the probe replaces the sink: it may explain which generator is
  called, but `vulnerability_observed` needs the real generator reproduced, or a source-cited
  argument plus `inconclusive`.
- Short codes from a secure RNG are a CWE-307 question, not this one.
- Distinguish token length (entropy) from generator quality; report both.

## Verdict guidance

- `potentially_exploitable`: the probe predicted the real token from attacker-available
  information.
- `likely_not_exploitable`: cite the CSPRNG call and the token length.
- `inconclusive` when the generator is weak but reproduction needs state recovery the probe did
  not perform; name the generator and line.
