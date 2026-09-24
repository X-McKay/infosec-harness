---
name: cwe-89-sql-injection
description: "Recognize SQL injection sources, sinks, and sanitizers, and define a deterministic test oracle for it."
---

# CWE-89: SQL injection

**Sink.** A call that sends a query string to a database driver where that string was built by
concatenating or formatting untrusted input: `cursor.execute(f"... {x}")`,
`Statement.executeQuery("..."+x)`, string-built queries in an ORM's raw/`text()` escape hatch.

**Source.** Any value the caller does not fully control: request params, headers, CLI args,
file contents, message fields.

**Neutralized when.** The value is passed as a bound parameter (`execute(sql, (x,))`,
`PreparedStatement.setString`), or goes through a strict allowlist/typed cast (e.g. coerced to
int) before reaching the query.

## Oracle

The exploit condition is **"the untrusted value changed the structure of the query rather than
being treated as a single literal."** Prefer to observe this without a live database:

- **Preferred (structure oracle).** Have the test call the target callable with input carrying
  a unique token derived from the nonce (e.g. embedded in an identifier-like string). Capture
  the SQL actually handed to the driver — via a fake/stub connection or driver that records its
  argument, or the ORM's query-compilation API. Fire the oracle when the token appears in the
  SQL text as syntax (unquoted / breaking out of a literal) rather than as a bound parameter
  value. This is deterministic and needs no real DB.
- **Fallback (in-memory DB).** Against a sandbox SQLite/H2 seeded with a known row, feed input
  whose intended effect is to return rows it should not (or to change the row count). Fire the
  oracle when the observed result set differs from the parameterized baseline.

Reaching `cursor.execute` with a concatenated string is the precondition; a query that keeps
the token bound is a valid negative.
