---
name: cwe-116-improper-output-encoding
description: Missing or wrong output encoding for a non-HTML context. Use this when the finding is CWE-116/838 and the output is not an HTML body.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-116 / CWE-838: Improper output encoding

## Use this skill when

- The finding is classified CWE-116 or CWE-838, or names improper, missing or wrong output encoding.
- An untrusted value is written into an output context whose special characters are not encoded for
  *that* context: a JSON/JS string, a CSV/TSV field, a shell-free serialized record, a URL component,
  an SQL identifier echoed back, or an HTML attribute/JS block where HTML-body encoding is wrong.

## Do not use this skill when

- The context is HTML body/markup and the finding is XSS — use `cwe-79-xss`.
- The special characters drive a downstream interpreter directly (SQL, shell, template) — use the
  matching injection skill; this skill is about *encoding of output for a consumer*.

## When another skill also applies

- `cwe-79-xss` is the HTML-context specialization. **That skill wins** for HTML output; this skill
  owns the other contexts (JSON, JS-string, CSV, URL, header value where not CRLF).
- `cwe-1236-formula-injection` is the spreadsheet-formula specialization of CSV output. **That skill
  wins** when the concern is a leading `= + - @` formula trigger; this skill owns field-delimiter and
  quote encoding.

## Procedure

**Sink.** Writing an untrusted value into a structured output without encoding for that context:
`'{"name":"' + value + '"}'` (hand-built JSON), a JS string literal built by concatenation, a CSV
row joined with commas, a URL built without percent-encoding.

**Guard.** The context's proper encoder: a real JSON serializer, `encodeURIComponent` / percent
encoding, CSV quoting that doubles embedded quotes, JS-string escaping of `\ " ' </`.

**Neutralized when.** The value passes through the context-correct encoder before output, so a
delimiter or quote in the value cannot break out of its field.

## Oracle

Condition: **a context-significant character in the value broke out of its field or changed the
output's structure.** Choose the payload for the context and inspect the structural result, not a
substring:

- JSON/JS string: payload `a","injected":"<nonce>` — parse the output; `vulnerability_observed` when
  the parsed object gains an `injected` key.
- CSV: payload `a,<nonce>,b` or `a"<nonce>` — parse with a real CSV reader; observed when the row
  gains fields or the quote breaks the record.
- URL component: payload `a&injected=<nonce>` — parse the query; observed when `injected` appears as
  a separate parameter.

Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real output function ran with the payload and produced or rejected output.
- `oracle_valid`: the output is parsed with a real parser for its context and the payload
  matches that context.
- `vulnerability_observed`: parsing the output shows the injected structure (extra key, extra field,
  extra parameter).
- `positive_control`: the same unencoded assembly yields the broken structure, proving the parser check works.
- `negative_control`: a benign value yields a single well-formed field/key/parameter.

## Language notes

- **Python:** hand-built JSON vs `json.dumps`; `csv.writer` (quotes correctly) vs `",".join`;
  `urllib.parse.quote` vs raw concatenation.
- **JavaScript:** `JSON.stringify` vs string building; `encodeURIComponent` for URL parts; a CSV
  library vs manual joins.
- **Java:** Jackson/Gson vs `StringBuilder` JSON; `URLEncoder.encode`; a CSV library (commons-csv).
- **Perl:** `JSON::PP->encode` vs interpolation; `URI::Escape::uri_escape`; `Text::CSV` vs `join ','`.

## Pitfalls

- Over-encoding (double-encoding) is a correctness bug, not this vulnerability; judge by whether a
  delimiter can break the field, not by cosmetic differences.
- Match the payload to the real consumer: a JSON payload tells nothing about CSV safety.
- Inspect the parsed structure; a raw-substring check misreads a correctly quoted field as a break.

## Verdict guidance

- `potentially_exploitable`: the value reaches the output context with no context-correct encoder
  and the probe observed a structural break on parse.
- `likely_not_exploitable`: cite the encoder call, with a complete probe showing the payload confined
  to a single field/key on parse.
- `inconclusive`: the output context or its consumer could not be exercised to parse the result.
