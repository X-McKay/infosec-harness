---
name: cwe-89-sql-injection
description: Recognize SQL injection sources, sinks, and sanitizers, and define a deterministic oracle
  for one. Use this when the finding is CWE-89 or the code builds a query string from untrusted input.
metadata:
  owner: appsec
  version: 2.0.0
---

# CWE-89: SQL injection

## Use this skill when

- The finding is classified CWE-89, or names SQL injection.
- A query string reaches a database driver after being concatenated or formatted from a value the caller supplies.
- An ORM's raw/`text()` escape hatch takes an interpolated string.

## Do not use this skill when

- The untrusted value reaches a shell rather than a database — use `cwe-78-os-command-injection`.
- The value is interpolated into code that is then evaluated — use `cwe-94-code-injection`.
- The query is fully parameterized and the finding is about something else.

## When another skill also applies

- `cwe-78-os-command-injection` also fires when the query goes out through a command-line client (`psql -c`, `mysql -e`): one value, concatenated into SQL and handed to a shell, and each skill redirects to the other. **That skill wins** — classify by the first interpreter the value reaches. A payload that does not survive the shell's quoting never reaches the query at all.
- `probe` forbids mocking the sink. **That skill wins** wherever the two disagree, which is why the fallback below hooks the real connection instead of replacing it: a wrapper the target never used reports a silent false negative on an exploitable finding.

## Procedure

**Sink.** A call that sends a query string to a database driver where that string was built by
concatenating or formatting untrusted input: `cursor.execute(f"... {x}")`,
`Statement.executeQuery("..."+x)`, string-built queries in an ORM's raw/`text()` escape hatch.

**Source.** Any value the caller does not fully control: request params, headers, CLI args,
file contents, message fields.

**Neutralized when.** The value is passed as a bound parameter (`execute(sql, (x,))`,
`PreparedStatement.setString`), or goes through a strict allowlist/typed cast (e.g. coerced to
int) before reaching the query.

## Oracle

Condition: **the untrusted value changed the structure of the query rather than being
treated as a single literal.** Drive the real callable against a real driver; never substitute
a fake or stub connection, cursor or engine for the one the code uses (see `probe`).

- **Preferred (result oracle).** Stand up an in-memory database (SQLite `:memory:`, H2)
  seeded so that one row is visible to the intended query and one is not. Use a widening
  input such as `x' OR '1'='1`, matched to the quoting context on the sink line.
- **Fallback (structure oracle), when no database can be stood up.** Observe the SQL the
  real connection received through a *non-invasive* hook — SQLite's `set_trace_callback`,
  the driver's statement logger, SQLAlchemy's `before_cursor_execute`, or the ORM's
  query-compilation API — with input carrying a nonce token.

Map the result onto `HARNESS_PROBE`:

- `target_reached`: the real query function ran with the payload, including when it raises
  a validation or SQL error. A syntax error from a quoting mismatch is not a clean negative.
- `vulnerability_observed`: the row the intended `WHERE` excludes comes back, or the token
  appears in the traced statement as SQL syntax rather than a bound value.
- `positive_control`: the equivalent concatenated query, executed directly on the same
  connection with the payload, returns the excluded row (or shows the token as syntax).
- `negative_control`: a benign value through the target returns only the intended row, or
  the token stays bound.
