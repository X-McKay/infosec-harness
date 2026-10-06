---
name: cwe-521-weak-password-requirements
description: Recognize registration and password-change paths that accept trivially weak passwords, and define a policy oracle against the real validator.
  Use this when the finding is CWE-521 or a password policy is missing, client-side only, or bypassable.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-521: Weak password requirements

## Use this skill when

- The finding is classified CWE-521, or names a missing or weak password policy.
- Registration, password change or reset stores a password without a length, breach-list or
  complexity check, or the check runs only in client-side code.

## Do not use this skill when

- The password is accepted without being checked at login — use
  `cwe-287-improper-authentication`.
- The issue is how the password is stored — use `cwe-327-broken-crypto`.
- The issue is unlimited guessing — use `cwe-307-improper-restriction-of-authentication-attempts`.

## When another skill also applies

- `cwe-307-improper-restriction-of-authentication-attempts` makes weak passwords
  exploitable online. **This skill wins** for whether the weak password is accepted; report
  the attempt limit through that skill.
- `cwe-620` (unverified password change) belongs to `cwe-287-improper-authentication`.

## Procedure

**Sink.** Persisting a new password: user creation, password change, reset completion.

**Guard.** The server-side validator called before persistence: minimum length (NIST SP
800-63B suggests at least 8, preferably more), maximum length high enough for passphrases,
breached or common password list, framework validators (`AUTH_PASSWORD_VALIDATORS`).

**Source.** The new password field supplied by the user.

**Neutralized when.** A server-side validator on every path that sets a password rejects
short and common passwords before persistence. Client-side checks alone are not a guard.

## Oracle

Condition: **the real server-side path accepted and stored a password that a reasonable
policy rejects.** Use a short, common test password such as `a` or `password`, never one
taken from real credential dumps.

- `target_reached`: the real registration or change entry point ran with the weak password,
  including when its validator rejects it.
- `vulnerability_observed`: the weak password was persisted, observed by logging in with it
  through the real login or by reading the probe's store.
- `positive_control`: a strong random password through the same path is accepted and can
  log in, proving persistence is visible.
- `negative_control`: an input the target must reject for structural reasons (empty
  password, missing username) is not persisted.

## Language notes

- **Python:** Django `validate_password` called or skipped; custom forms that bypass
  `set_password` validators; length checks with `<` versus `<=`.
- **JavaScript:** validation in the browser bundle only; `joi`/`zod` schemas applied to one
  route but not to the reset route.
- **Java:** Bean Validation `@Size` on DTOs not annotated `@Valid` at the controller.
- **Perl:** regex-only policies such as `/[A-Z]/ && /\d/` with no length test, so `A1` passes;
  `length` checks on bytes versus characters.

## Pitfalls

- Check every setter path: admin create, import, reset and change often differ.
- Policy strength is a judgement; cite the threshold you used and why.
- Weak passwords alone need an online guessing or offline cracking channel; say which the
  verdict assumes.

## Verdict guidance

- `potentially_exploitable`: the real path stored a trivially weak password; name the guessing
  channel assumed.
- `likely_not_exploitable`: cite the server-side validator line that rejected it, with the
  positive control passing.
- `inconclusive` when the policy is enforced by an external identity provider the repository
  delegates to.
