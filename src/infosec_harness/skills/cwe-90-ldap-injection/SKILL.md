---
name: cwe-90-ldap-injection
description: Untrusted input built into an LDAP search filter or DN. Use this when the finding is CWE-90.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-90: LDAP injection

## Use this skill when

- The finding is classified CWE-90, or names LDAP injection or filter injection.
- An untrusted value is concatenated or formatted into an LDAP search filter
  (`(uid=<value>)`) or a distinguished name.

## Do not use this skill when

- The value reaches a SQL driver — use `cwe-89-sql-injection`.
- The value reaches an XPath expression — use `cwe-643-xpath-injection`.

## When another skill also applies

- `cwe-643-xpath-injection` and `cwe-943-nosql-injection` share the shape "untrusted value
  changes a query's structure". **This skill wins** only when the query language is LDAP (RFC 4515
  filters or DNs); classify by the directory the value actually reaches.
- Use `probe` for source integrity, controls and evidence rules.

## Procedure

**Sink.** A directory search or bind where the filter or DN string was built from untrusted
input: `search(base, "(uid=" + user + ")")`, a DN assembled as `"uid=" + user + ",ou=people,..."`.

**Guard.** RFC 4515 filter escaping of `* ( ) \ NUL` (and RFC 4514 DN escaping of
`, + " \ < > ;`), or a strict allowlist / typed cast applied before the value joins the filter.

**Neutralized when.** Every metacharacter in the value is escaped for its context, or the value
is validated against a strict pattern before use. Parameterized assertion values that the library
escapes also neutralize it.

## Oracle

Condition: **the untrusted value changed the filter's structure rather than being treated as a
single assertion value.** Stand up an in-memory or embedded directory the probe populates (a
small list of entries searched by a real filter parser, or an embedded LDAP server on
`127.0.0.1`); never substitute a stub that ignores the filter. Seed one entry the intended
filter should return and one it must not. Use a widening payload matched to the filter context,
such as `*` or `*)(uid=*` for `(uid=<value>)`. Map the result onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real search function ran with the payload and built or rejected the
  filter, including when escaping turns it into a literal that matches nothing.
- `oracle_valid`: a real filter parser searches the seeded entries and the payload matches the
  filter context.
- `vulnerability_observed`: the entry the intended filter excludes is returned, or the parsed
  filter tree shows extra assertions the value introduced.
- `positive_control`: the equivalent concatenated filter, parsed/searched directly with the
  payload, returns the excluded entry, proving the directory and check work.
- `negative_control`: a benign value through the target returns only the intended entry.

## Language notes

- **Python:** `ldap3` / `python-ldap` `search(...)`; escape with `ldap3.utils.conv.escape_filter_chars`.
- **JavaScript:** `ldapjs` client `search`; filters built by string concatenation are the sink.
- **Java:** `DirContext.search(name, filter, ...)`; parameterized `{0}` with a `filterArgs` array escapes, raw concatenation does not.
- **Perl:** `Net::LDAP` `search(filter => "(uid=$user)")`; `Net::LDAP::Filter` with escaped values is the safe form.

## Pitfalls

- A filter that errors on `(` imbalance looks like resistance but may still be injectable with a
  balanced payload (`*)(uid=*`); try a structurally valid widening input.
- DN injection and filter injection escape different character sets; match the escape list to
  where the value lands.
- An empty result set is not proof of safety if the payload was syntactically rejected; confirm
  the positive control fires first.

## Verdict guidance

- `potentially_exploitable`: the value reaches an unescaped filter or DN position and the probe
  observed a structural change or an excluded entry returned.
- `likely_not_exploitable`: cite the escape call or allowlist line, with a complete probe showing
  the payload treated as a literal assertion value.
- `inconclusive`: no directory could be stood up, or the escaping behaviour was not observed.
