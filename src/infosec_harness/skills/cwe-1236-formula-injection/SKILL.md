---
name: cwe-1236-formula-injection
description: CSV or spreadsheet exports whose cells can begin with a formula trigger. Use this when the finding is CWE-1236 or CSV injection.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-1236: Formula injection (CSV injection)

## Use this skill when

- The finding is classified CWE-1236, or names formula injection, CSV injection or spreadsheet injection.
- An untrusted value is written into a CSV/TSV/spreadsheet export where a cell can begin with a
  formula trigger (`=`, `+`, `-`, `@`, and leading tab/CR) that a spreadsheet would evaluate.

## Do not use this skill when

- The concern is field-delimiter/quote breakout rather than a formula trigger — use
  `cwe-116-improper-output-encoding`.
- The value is rendered into HTML — use `cwe-79-xss`.

## When another skill also applies

- `cwe-116-improper-output-encoding` is the general output-encoding family for CSV. **This skill
  wins** when the specific hazard is a leading formula character a spreadsheet evaluates; that skill
  owns delimiter and quote encoding of the same file.
- Use `probe` for source integrity, controls and evidence rules.

## Procedure

**Sink.** Writing an untrusted value as a cell in an exported CSV/TSV/XLSX without neutralizing a
leading formula trigger: `csv.writer.writerow([value])`, `cells.add(value)`.

**Guard.** Prefixing a trigger value with a safe character (a leading apostrophe or a zero-width /
space that forces text), rejecting values starting with `= + - @`, or writing cells with an explicit
text type that the spreadsheet will not evaluate.

**Neutralized when.** A cell beginning with a trigger character is quoted-as-text or prefixed so the
spreadsheet treats it as a string, for every export path, or such values are rejected.

## Oracle

Condition: **an exported cell retained a leading formula trigger that a spreadsheet would evaluate.**
A probe has no spreadsheet application and must not run one; instead parse the exported file with a
real CSV reader and inspect the *cell value* the consumer would see. Payload: a value beginning with
a trigger, such as `=1+191` (or `@SUM(1+191)`, `+1+191`, `-1+191`), tagged with a nonce like
`=CONCAT("h","<nonce>")`. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real export function ran with the trigger-leading value and produced the file.
- `oracle_valid`: the export is parsed with a real CSV reader and the check reads each cell's
  leading character.
- `vulnerability_observed`: the parsed cell still begins with a trigger character (`=`, `+`, `-`, `@`,
  or a leading tab/CR before one) — i.e. a spreadsheet would evaluate it.
- `positive_control`: a raw export of the trigger value (no neutralization) yields a cell that still
  begins with the trigger, proving the parse/check reads the leading character correctly.
- `negative_control`: a benign value (`191`, `alice`) yields a cell with no leading trigger.

The oracle is "would a spreadsheet evaluate this cell", established by the leading character of the
parsed cell — not by running any spreadsheet engine.

## Language notes

- **Python:** `csv.writer`; guard by prefixing `"'" + value` or checking `value[:1] in "=+-@"`.
- **JavaScript:** manual CSV or a library; guard by prepending `'` or a tab-stripping sanitizer.
- **Java:** commons-csv / POI; POI can set a cell's type to string; a leading `'` forces text in many apps.
- **Perl:** `Text::CSV`; guard by prefixing the field before `print`.

## Pitfalls

- Delimiter-correct quoting (CWE-116) does *not* stop formula evaluation; a properly quoted
  `"=1+191"` still evaluates in a spreadsheet. The two defenses are separate.
- Neutralization must cover `+ - @` and leading whitespace/tab/CR, not only `=`.
- Do not launch a spreadsheet application; the leading-character rule on the parsed cell is the oracle.

## Verdict guidance

- `potentially_exploitable`: untrusted values are exported with no trigger neutralization and the
  probe observed a parsed cell still leading with a trigger.
- `likely_not_exploitable`: cite the prefixing / rejection line, with a complete probe showing the
  trigger value neutralized (text-forced or refused) in every export path.
- `inconclusive`: the export path could not be exercised, or whether all cells are neutralized was unresolved.
