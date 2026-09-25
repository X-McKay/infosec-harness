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
being treated as a single literal."**

Whichever oracle you use, the probe must drive the **real** callable against the **real**
driver. Never substitute a fake or stub connection, cursor, or engine for the one the code
under test uses: that replaces the sink instead of exercising it (see
`probe-oracle-protocol`), and a probe whose wrapper is not actually the object the target
uses reports a silent false negative rather than a clean one.

- **Preferred (result oracle).** Stand up an in-memory database (SQLite `:memory:`, H2) seeded
  so that one row is visible to the intended query and one row is not. Call the target
  callable with input designed to widen the query (classically `x' OR '1'='1`). Fire the
  oracle when a row the intended `WHERE` should have excluded comes back, or the row count
  changes versus the same call with a benign value. This observes what the code *did*, needs
  no instrumentation, and cannot be fooled by a wrapper that was never used.
- **Fallback (structure oracle), when no database can be stood up.** Observe the SQL the
  driver really received through a *non-invasive* hook on the real connection — SQLite's
  `Connection.set_trace_callback`, the driver's own statement logger, SQLAlchemy's
  `before_cursor_execute` event, or the ORM's query-compilation API. Pass input carrying a
  token derived from the nonce and fire the oracle when the token appears in the statement as
  syntax (unquoted, breaking out of the literal) rather than as a bound parameter value.

Reaching `cursor.execute` with a concatenated string is the precondition; a query that keeps
the token bound is a valid negative.
