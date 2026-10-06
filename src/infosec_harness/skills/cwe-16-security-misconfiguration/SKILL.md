---
name: cwe-16-security-misconfiguration
description: Recognize insecure defaults and security-relevant configuration, route to a specific skill
  where one exists, and define a default-configuration oracle. Use this when the finding is CWE-16 or CWE-1188.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-16: Security misconfiguration

## Use this skill when

- The finding is classified CWE-16, CWE-1188 (insecure default initialization) or CWE-276
  (incorrect default permissions) and no more specific skill below matches.
- A shipped default — a configuration file, a constructor default, a framework setting —
  disables a protection (TLS verification, authentication, secure cookie flags, rate limits).

## Do not use this skill when

A specific skill owns the class; load it instead and use this one only for routing:

- Debug flag or debug endpoint — `cwe-489-active-debug-code`.
- Cross-origin settings — `cwe-942-permissive-cors`.
- Missing frame protections — `cwe-1021-clickjacking`.
- File, directory or socket modes — `cwe-732-incorrect-permission-assignment`.
- Files or listings served to the wrong audience — `cwe-668-exposure-of-resource-to-wrong-sphere`.
- XML parser entity settings — `cwe-611-xxe`.
- Verbose errors in production code — `cwe-200-information-exposure`.

## When another skill also applies

- Any skill listed above **wins** over this one: it carries the precise oracle. This skill is
  the fallback for a misconfiguration that has no dedicated skill, such as disabled
  certificate verification, a default admin credential, or cookies without `Secure`/`HttpOnly`.

## Procedure

**Sink.** The protection the setting controls: the TLS context, the session cookie writer,
the authentication middleware, the access check that the setting disables.

**Guard.** A safe default in code; a startup check that refuses the insecure value; a
production configuration file that overrides the default and is the one deployment loads.

**Neutralized when.** The configuration actually loaded by the production entry point sets
the secure value, or the insecure value cannot be selected by anyone but the operator. A
configured name in a sample file is not evidence of what deployment loads.

**Source.** Often not attacker input at all: the attacker benefits from a default. Name who
can then exploit the weakened protection and from where.

## Oracle

Condition: **the real component, built with its shipped defaults, exhibits the insecure
behaviour.** Construct the component through its real factory or entry point with no
overrides, then observe the behaviour directly:

- Cookies: start the app on `127.0.0.1`, request the login route, inspect `Set-Cookie` flags.
- TLS verification: inspect the constructed context (`ssl.SSLContext.verify_mode`,
  `check_hostname`), not a network call.
- Default credentials: call the real authentication function with the shipped default.

Map onto `HARNESS_PROBE`:

- `target_reached`: the real component was constructed and exercised with defaults.
- `vulnerability_observed`: the observed attribute or behaviour is the insecure one.
- `positive_control`: the component deliberately configured insecurely through its own
  options shows the insecure value, proving the check reads the right attribute.
- `negative_control`: the component deliberately configured securely shows the secure value.

## Language notes

- **Python**: `verify=False`, `ssl._create_unverified_context`, Django `SESSION_COOKIE_SECURE`,
  `ALLOWED_HOSTS = ['*']`, default secret keys in `settings.py`.
- **JavaScript**: `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`,
  `express-session` cookie options, `helmet` omitted.
- **Java**: trust-all `X509TrustManager`, `HostnameVerifier` returning true, Spring Security
  `permitAll()` defaults, Tomcat `server.xml` connectors.
- **Perl**: `SSL_verify_mode => SSL_VERIFY_NONE`, `PERL_LWP_SSL_VERIFY_HOSTNAME=0`,
  `CGI::Session` defaults.

## Pitfalls

- Reading a sample or test configuration and calling it production configuration.
- Observing the setting in a file without observing the component honour it.
- Severity depends on the deployment; do not overstate a default that every production
  manifest overrides.

## Verdict guidance

- `potentially_exploitable`: the real production entry point loads the insecure default and
  the oracle observed the weakened behaviour; name who benefits.
- `likely_not_exploitable`: the loaded configuration sets the secure value (cite it) or the
  default is secure, with both controls passing.
- `inconclusive`: the deployed configuration is outside the repository; say so.
