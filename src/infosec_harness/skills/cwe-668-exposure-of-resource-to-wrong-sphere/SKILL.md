---
name: cwe-668-exposure-of-resource-to-wrong-sphere
description: Files, directories or listings served to an audience that should not reach them. Use this when the finding is CWE-668/552/538.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-668: Exposure of resource to wrong sphere

## Use this skill when

- The finding is classified CWE-668, CWE-552 (files accessible to external parties) or
  CWE-538 (insertion of sensitive information into externally accessible file or directory,
  including directory listings).
- A static file server, upload directory or export folder serves a document root that also
  holds private files (`.env`, `.git/`, backups, database files, other users' uploads), or
  enables directory listing.

## Do not use this skill when

- The caller escapes the served directory with `../` — use `cwe-22-path-traversal`.
- A value is formatted into a response or log — use `cwe-200-information-exposure`.
- The issue is a file mode on the local filesystem — use
  `cwe-732-incorrect-permission-assignment`.

## When another skill also applies

- `cwe-22-path-traversal` also fires when private files are reached by a crafted path.
  **That skill wins** when the request leaves the document root; **this skill wins** when the
  private file sits inside the root and an ordinary path serves it.
- `cwe-200-information-exposure` **wins** when the leak is a formatted value, not a stored
  resource.

## Procedure

**Sink.** The static handler and its root: `SimpleHTTPRequestHandler(directory=...)`,
`express.static(root)`, `serve-index`, Spring `addResourceLocations`, Apache/nginx
configuration in the repository, `send_file` of a user-chosen name inside the root.

**Guard.** A dedicated public directory holding only public assets; a deny-list for dotfiles
(`dotfiles: 'deny'`); disabled listing (`autoindex off`, no `serve-index`); per-object
authorization on uploads.

**Neutralized when.** Private files are outside the served root, or every request for them is
refused, and listing is off. Cite the root and the rule.

**Source.** Any unauthenticated request path.

## Oracle

Condition: **an ordinary unauthenticated request retrieves a private file or a listing.**
Create a probe directory laid out the way the target's root is (or use the target's own root
under `/workspace/repo` read-only), place a planted private file such as `.env` holding a
unique nonce, and start the target's real handler on `127.0.0.1` with an ephemeral port.

- `target_reached`: the real handler answered the request for the private file or directory
  (any status).
- `oracle_valid`: the planted file holds the nonce at the path the request names.
- `vulnerability_observed`: the response body contains the nonce, or the directory response
  lists the planted file name.
- `positive_control`: reading the planted file directly in the probe yields the nonce, and the
  check fires on that content.
- `negative_control`: a request for a public asset returns it, and the check stays silent.

Plant files only in a probe-created directory. Do not modify the original source tree; if the
target's root is part of the repository, add new files only and remove them in `finally`.

## Language notes

- **Python**: `http.server.SimpleHTTPRequestHandler` serving the working directory, Flask
  `static_folder` pointing at the project root, Django `MEDIA_ROOT` without access control.
- **JavaScript**: `express.static(__dirname)`, `serve-index`, `dotfiles: 'allow'`, Next.js
  `public/` holding secrets.
- **Java**: Spring `addResourceHandlers("/**").addResourceLocations("file:./")`, Tomcat
  `listings=true` in `web.xml`.
- **Perl**: `Plack::App::File`/`Plack::App::Directory` on the project root, Mojolicious
  `static->paths`.

## Pitfalls

- Serving the repository root during development is not production exposure; find the
  production entry point.
- A listing of public assets only is low impact; say what private item appears.
- Uploads served by guessable names need an authorization check, not only a hidden URL.

## Verdict guidance

- `potentially_exploitable`: the private file or listing was retrieved by an ordinary request
  to the real handler; name the item.
- `likely_not_exploitable`: the cited root or deny rule refused it, with both controls passing.
- `inconclusive`: the serving layer is configured outside the repository.
