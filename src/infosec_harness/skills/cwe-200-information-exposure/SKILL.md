---
name: cwe-200-information-exposure
description: Recognize sensitive values or internals leaking into responses, errors and logs, and define
  a planted-marker oracle. Use this when the finding is CWE-200, 209, 215, 532, 201 or 359.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-200: Exposure of sensitive information

## Use this skill when

- The finding is classified CWE-200, CWE-201, CWE-209 (error messages), CWE-215 (debug
  information), CWE-532 (sensitive data in logs) or CWE-359 (private personal data).
- A response, error page, log line or exported record can carry a secret, credential, stack
  trace, internal path or another user's private data to someone who should not see it.

## Do not use this skill when

- The exposure exists because a debug mode or debug endpoint is switched on — use
  `cwe-489-active-debug-code`.
- A whole file or directory is served to the wrong audience — use
  `cwe-668-exposure-of-resource-to-wrong-sphere`.
- The data leaves only because an injection changed a query or path — use that injection skill.

## When another skill also applies

- `cwe-489-active-debug-code` also fires when a debug flag produces the verbose error. **That
  skill wins** when the fix is turning the debug feature off; keep this skill when the code
  itself formats internals into a production response or log line regardless of mode.
- `cwe-668-exposure-of-resource-to-wrong-sphere` **wins** when the leaked unit is a stored
  resource (a file, a directory listing) rather than a value the code formats.

## Procedure

**Sink.** A write that crosses to a less trusted audience: an HTTP response body or header,
an error message returned to the caller, a log or audit line, a serialized object sent to a
client. Typical lines: `traceback.format_exc()` written to the response, `str(exc)` with a
connection string, `logger.info("login %s %s", user, password)`, `res.json(user)` that
includes a hash or token field.

**Guard.** A generic error handler that logs details server-side and returns an opaque
message; field allow-lists or response schemas; log redaction filters; framework production
mode that suppresses tracebacks.

**Neutralized when.** The sensitive value never reaches the less trusted sink on any path the
caller can trigger: the error path returns a fixed message, the serializer omits the field, or
a redaction filter replaces the value before the log handler formats it.

**Source.** Untrusted input that triggers the leaking path (a malformed request, a failing
lookup, a login attempt), plus the secret itself, which comes from configuration or storage.

## Oracle

Condition: **a value planted as secret, or the target's internals, appears in output an
untrusted caller can read or a log line written while handling that caller's request.**

At run time, plant a unique nonce where the target keeps the secret (its own configuration
variable, environment variable or record field, set through its normal parameters), and drive
the real entry point. For HTTP code, start the target's own server on `127.0.0.1` with an
ephemeral port and use the standard-library client. For logs, attach a capturing handler to
the target's real logger rather than replacing the logger.

- `target_reached`: the real handler ran with the triggering input, whether it returned the
  details, a generic error or a success response.
- `vulnerability_observed`: the nonce, or a traceback marker (`Traceback (most recent call
  last)`, `at com.`, a source path from the repository), appears in the response body,
  headers or the captured log line from the target call.
- `positive_control`: the same check fires on a string the probe builds that contains the
  nonce (or a real traceback from a deliberate `raise` in the probe).
- `negative_control`: a benign request that does not hit the leaking path returns output the
  check stays silent on, and the nonce is still set, proving silence is not a missing plant.

## Language notes

- **Python**: `traceback.format_exc()`, `repr(exc)`, `http.server` `send_error(500, str(e))`,
  Flask/Django `DEBUG=True`, `logging` with `%s` of request bodies. Use
  `logging.Handler` subclasses to capture; `caplog` works under pytest.
- **JavaScript**: `res.send(err.stack)`, `res.json(err)`, Express default handler outside
  `NODE_ENV=production`, `console.log(req.body)`. Capture console output by wrapping the
  stream write, not the target function.
- **Java**: `e.printStackTrace(response.getWriter())`, `getMessage()` in a JSP, Spring
  `server.error.include-stacktrace=always`, Log4j/SLF4J with credentials in format arguments.
- **Perl**: `die` messages surfacing through CGI `CGI::Carp qw(fatalsToBrowser)`, `warn` of
  request data, `Data::Dumper` of a config hash in a response.

## Pitfalls

- A stack trace in a server-side log only is usually not exposure; check who can read it.
- Do not use real credentials or read real configuration files; plant your own nonce.
- A response that mentions an exception class name but no value is weak evidence; record it
  as such rather than as a leaked secret.
- CWE-359 needs the data to belong to someone other than the caller; plant two records.

## Verdict guidance

- `potentially_exploitable`: the nonce or internals reached a caller-readable sink through the
  real entry point, and you can name what the attacker learns.
- `likely_not_exploitable`: a cited generic handler, schema or redaction filter kept the nonce
  out, with both controls passing.
- `inconclusive`: the leaking path needs a deployment setting you cannot observe (log access,
  production flag); say which.
