---
name: cwe-434-unrestricted-file-upload
description: Uploads whose untrusted name or type lets a dangerous file be stored or served. Use this when the finding is CWE-434/73.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-434 / CWE-73: Unrestricted file upload

## Use this skill when

- The finding is classified CWE-434 or CWE-73, or names unrestricted upload or external control of
  a filename / path used for storage.
- Untrusted input decides an uploaded file's stored name, extension or type, with weak or no
  restriction on dangerous forms (an executable/script extension, a double extension, a content-type
  mismatch).

## Do not use this skill when

- The hazard is `../` escaping the upload directory — use `cwe-22-path-traversal`.
- The uploaded content is then evaluated/included as code at a chosen path — use `cwe-98-file-inclusion`
  or `cwe-94-code-injection`.

## When another skill also applies

- `cwe-22-path-traversal` also fires when the filename contains traversal. **That skill wins** for the
  traversal escape; this skill owns the *type/extension* restriction — whether a dangerous kind of
  file can be stored or served at all.
- Use `probe` for source integrity, controls and evidence rules.

## Procedure

**Sink.** Persisting an uploaded file under a name/extension derived from untrusted input:
`save(upload_dir + filename)`, writing the client-supplied name, deriving the type from a spoofable
`Content-Type` or extension.

**Guard.** An allowlist of permitted extensions/MIME types checked against *content* (magic bytes),
a server-generated random name with a fixed safe extension, storage outside any served/executable
directory, or stripping the extension.

**Neutralized when.** The stored file cannot take a dangerous extension/type: the name is
server-generated with a safe extension, or an allowlist verified against content rejects the upload,
so an attacker cannot store an executable/script form.

## Oracle

Condition: **a dangerous-typed file was stored under an attacker-influenced name the restriction
should have blocked.** The probe owns a temp upload directory. Submit an upload whose name/type is
dangerous for the app's stated rule, such as `shell.<ext>` with content carrying a nonce, where
`<ext>` is one the allowlist should reject (or a double extension `image.jpg.<ext>`, or a
content/extension mismatch). Inspect the stored file. Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real upload handler ran with the dangerous upload and stored or rejected it.
- `oracle_valid`: the upload's extension or type is one the application's own rule should
  reject.
- `vulnerability_observed`: a file with the dangerous extension/type and the nonce content exists in
  the storage directory after the call.
- `positive_control`: writing the dangerous file directly to the storage dir succeeds, proving the
  directory and nonce check work (confirms the oracle, not the target).
- `negative_control`: an allowed upload (an image with an allowed extension) is stored, proving the
  handler stores files, while the dangerous one is the discriminating case.

Never execute a stored file; existence of the dangerous-typed file under its name is the oracle. Do
not rely on the configured allowlist *name* as evidence — observe what the handler actually stored.

## Language notes

- **Python:** Flask `request.files[...].save(...)`; `werkzeug.utils.secure_filename` strips path and
  normalizes but does not enforce an extension allowlist by itself.
- **JavaScript:** `multer` with `dest`; the `fileFilter` / allowlist and a generated filename are the guard.
- **Java:** `Part.write(name)` / commons-fileupload; check `getSubmittedFileName` handling and the allowlist.
- **Perl:** CGI `upload` with the client filename used directly; a generated name is the guard.

## Pitfalls

- A content-type check trusts a spoofable header; content/magic-byte verification is stronger — note
  which the code does.
- Double extensions and case (`.PHP`, `.pHp`) and trailing dots/spaces bypass naive extension checks.
- Storing safely but serving from an executable directory is still a hazard; note where stored files
  are served from.

## Verdict guidance

- `potentially_exploitable`: a dangerous-typed file can be stored under attacker influence with no
  content-verified allowlist or safe generated name, and the probe observed it stored.
- `likely_not_exploitable`: cite the allowlist/generated-name line, with a complete probe showing the
  dangerous upload rejected or stored only under a safe name/type.
- `inconclusive`: the handler could not be exercised, or whether the stored form is dangerous was unresolved.
