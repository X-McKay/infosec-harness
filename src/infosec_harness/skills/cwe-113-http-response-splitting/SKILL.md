---
name: cwe-113-http-response-splitting
description: Recognize CRLF injection into HTTP headers and logs (response splitting, log forging)
  and define a deterministic CRLF oracle. Use this when the finding is CWE-113, CWE-93 or CWE-117.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-113 / CWE-93 / CWE-117: HTTP response splitting, CRLF and log injection

## Use this skill when

- The finding is classified CWE-113, CWE-93 or CWE-117, or names response splitting, CRLF
  injection or log forging.
- An untrusted value is written into an HTTP response header, a redirect `Location`, a `Set-Cookie`,
  or a log line, with its carriage-return / line-feed characters intact.

## Do not use this skill when

- The value is the redirect *destination* and the hazard is the target, not a header break —
  use `cwe-601-open-redirect`.
- The value lands in the response *body* as markup — use `cwe-79-xss`.

## When another skill also applies

- `cwe-601-open-redirect` often shares the same `Location` sink. **This skill wins** when the hazard
  is injecting CR/LF to add headers or split the message; that skill wins when a well-formed URL
  simply points off-site.
- `cwe-116-improper-output-encoding` is the general family. **This skill wins** for the specific
  CR/LF-into-headers/logs case.

## Procedure

**Sink.** Writing untrusted input into a header, status line or log record built by string
assembly: `response.headers["X-Thing"] = value`, `"Location: " + value`, `setHeader(name, value)`
on a server that does not reject CR/LF, `logger.info("user=" + value)`.

**Guard.** Rejecting or stripping CR (`\r`, `%0d`) and LF (`\n`, `%0a`) before the value is
written, a framework that raises on header values containing CR/LF, or structured logging that
encodes field boundaries.

**Neutralized when.** CR and LF (and their encoded forms, if the layer decodes them) are removed or
rejected before the value reaches the header/log writer, or the writer itself rejects them.

## Oracle

Condition: **a CR/LF in the value created a new header or log line.** Build the real header/log
assembly in the probe and feed a value containing `\r\n` plus an injected field, such as
`x\r\nX-Injected: <nonce>` (for logs, `x\r\nFORGED <nonce>`). Inspect the *raw bytes* the target
produced — never a parsed header dict, which hides the split. Map the result onto `HARNESS_PROBE`
(see `probe`):

- `target_reached`: the real writer ran with the CRLF-bearing value and emitted or rejected the
  header/log line.
- `vulnerability_observed`: the raw output contains `\r\n` followed by the injected header/line
  with the nonce as a separate record.
- `positive_control`: the same assembly performed directly with the CRLF payload yields the split,
  proving the check reads raw bytes.
- `negative_control`: a benign value (no CR/LF) produces a single well-formed header/line.

If the framework under test rejects CR/LF at the header API, that rejection is `target_reached:
true`, `vulnerability_observed: false` — cite the rejection.

## Language notes

- **Python:** `http.server` / WSGI code that assembles headers by hand splits; `http.client` and
  modern WSGI servers raise on CR/LF in header values. `logging` with a plain format string forges
  log lines.
- **JavaScript:** Node core `res.setHeader` throws on invalid characters since modern versions;
  hand-assembled raw socket writes or old frameworks split.
- **Java:** `HttpServletResponse.setHeader` on modern containers strips CR/LF; `addHeader` on older
  ones or manual `PrintWriter` assembly splits. `log4j`/`logback` plain patterns forge lines.
- **Perl:** CGI code doing `print "Location: $url\r\n"` splits; `CGI->header(-location => $url)`
  may still pass CR/LF depending on version — check.

## Pitfalls

- Inspecting a parsed header map hides the split; always read raw bytes.
- The value may be decoded at a layer above the sink (`%0d%0a` → CR/LF); trace where decoding
  happens and inject at the layer that reaches the writer.
- A single `\n` without `\r` may still split logs though not all HTTP parsers; scope the claim to
  the observed sink.

## Verdict guidance

- `potentially_exploitable`: untrusted CR/LF reaches a header/log writer that does not reject them
  and the probe observed a split record.
- `likely_not_exploitable`: cite the CR/LF stripping line or the writer's rejection, with a
  complete probe showing a single well-formed record for the CRLF payload.
- `inconclusive`: the writer could not be exercised, or where decoding occurs was unresolved.
