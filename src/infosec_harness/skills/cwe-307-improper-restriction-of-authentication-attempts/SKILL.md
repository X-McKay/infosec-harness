---
name: cwe-307-improper-restriction-of-authentication-attempts
description: Recognize login, OTP and recovery checks without attempt limits, lockout or backoff, and define a bounded repeated-attempt oracle.
  Use this when the finding is CWE-307 or a credential check can be called repeatedly without throttling.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-307: Improper restriction of excessive authentication attempts

## Use this skill when

- The finding is classified CWE-307, or names brute force, credential stuffing, missing rate
  limiting or missing lockout on an authentication path.
- A password, PIN, OTP or recovery-code check has no per-account or per-client counter,
  lockout, delay or CAPTCHA step in the code path.

## Do not use this skill when

- The check can be passed without guessing — use `cwe-287-improper-authentication`.
- The secret space is small because the generator is weak — use
  `cwe-330-insufficient-randomness`.
- The finding is about weak passwords being allowed at registration — use
  `cwe-521-weak-password-requirements`.

## When another skill also applies

- `cwe-208-observable-timing-discrepancy` also fires when each attempt leaks partial
  information. **That skill wins** for the leak; this skill covers the number of attempts.
- `cwe-521-weak-password-requirements` compounds this one; report both, but this skill's
  oracle concerns the attempt limit only.

## Procedure

**Sink.** The credential comparison reached on each attempt: login, PIN or OTP verify,
recovery-code redeem, API key check.

**Guard.** An attempt counter keyed by account and/or client, lockout after N failures,
exponential backoff, a CAPTCHA requirement, or a rate limiter middleware in front of the
route. Note where state is kept: in-process counters reset on restart and per-worker.

**Source.** Repeated attempts by an attacker who controls the credential field.

**Neutralized when.** After a bounded number of failures the path refuses further attempts
(or the correct credential) for that account or client for a period, enforced before the
comparison runs, in code or configuration the repository contains.

## Oracle

Condition: **after N consecutive failures the correct credential still authenticates
immediately**, where N is a modest bound (for example 20) well above any reasonable lockout
threshold read from the source. Use a probe-created account with a nonce password. Keep N
small: the oracle is about the absence of a limit, not about guessing a real secret.

- `target_reached`: the real authentication entry point ran for each attempt, including
  attempts it rejected or throttled.
- `vulnerability_observed`: all N wrong attempts were evaluated (none refused as locked or
  throttled) and attempt N+1 with the correct password succeeded without delay.
- `positive_control`: the correct password on a fresh account succeeds, proving success is
  visible.
- `negative_control`: a wrong password is rejected, proving the comparison works.

Inject a fixed clock when the guard is time-based; never sleep through real lockout windows.
If a limiter exists only as middleware, drive the request through the stack that includes it.

## Language notes

- **Python:** Django `axes`/`ratelimit` decorators, Flask-Limiter configuration, counters in
  `dict` or cache backends.
- **JavaScript:** `express-rate-limit`, `rate-limiter-flexible`; limiter mounted on a
  different path than the login route.
- **Java:** Spring Security `AuthenticationFailureHandler`, Bucket4j filters.
- **Perl:** counters in a DBI table, `Plack::Middleware::Throttle`.

## Pitfalls

- A limiter keyed only by client IP is bypassed when the app trusts `X-Forwarded-For` from
  the caller; check how the key is derived.
- A lockout that returns the same response for the correct password is a guard; one that
  only adds a message is not.
- Infrastructure limits (WAF, gateway) are outside the repository; name them as limitations.

## Verdict guidance

- `potentially_exploitable`: N failures were evaluated and the correct credential still
  succeeded, with no repository-contained limit on the path.
- `likely_not_exploitable`: cite the counter or limiter line that refused attempts, with the
  positive control passing on a fresh account.
- `inconclusive` when limiting is delegated to infrastructure the repository does not define.
