---
name: cwe-98-file-inclusion
description: Recognize local and remote file inclusion where untrusted input chooses a module or file
  to load and execute, and define an inclusion oracle. Use this when the finding is CWE-98 or CWE-829.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-98 / CWE-829: File inclusion (LFI / RFI)

## Use this skill when

- The finding is classified CWE-98 or CWE-829, or names file inclusion, LFI, RFI or inclusion of
  functionality from an untrusted control sphere.
- An untrusted value chooses a module/template/file path that the program then *loads and executes*
  (imports, `require`, `include`, `do`), not merely reads as data.

## Do not use this skill when

- The value only names a file whose *contents* are read and returned — use `cwe-22-path-traversal`.
- The value is a string evaluated as inline program source — use `cwe-94-code-injection`.

## When another skill also applies

- `cwe-22-path-traversal` also fires when the include path contains `../`. **That skill wins** when the
  file is read as data; this skill wins when the chosen file is *executed/imported* — the hazard is
  loading code, not reading bytes.
- `cwe-94-code-injection` owns inline evaluation of a value. **That skill wins** there; this skill owns
  choosing *which file of code* gets loaded.

## Procedure

**Sink.** Loading a module/file selected by untrusted input: `importlib.import_module(name)`,
`__import__(name)`, `importlib.util.spec_from_file_location(path)`, `require(userPath)`,
`include $user`, Perl `do $file` / `require $file`.

**Guard.** An allowlist / fixed map from a key to a known module, confinement to a fixed package with
rejection of separators and dots, or loading only data (not code) for untrusted selectors.

**Neutralized when.** The caller can select only from a fixed allowlist of known modules, or the
resolved target is confined to a trusted directory/package and separators/traversal are rejected, so
an attacker-chosen file outside that set cannot be loaded.

## Oracle

Condition: **the program loaded and executed a file the attacker chose, from outside the intended
set.** The probe owns a temp directory. Create a module/file there, outside the intended base, whose
import/execution has a benign observable effect that touches only a probe path — for example on import
it writes `/tmp/harness_incl_<nonce>` or sets a module attribute to the nonce. Point the real loader at
that file through its untrusted selector (a path, or a name plus an attacker-influenced search path).
Map onto `HARNESS_PROBE` (see `probe`):

- `target_reached`: the real loader ran with the attacker selector and loaded or refused a target.
- `vulnerability_observed`: the planted file's effect occurred (the marker exists, or the loaded
  module exposes the nonce), proving an out-of-set file executed.
- `positive_control`: importing/executing the planted file directly produces the effect, proving the
  module and marker work.
- `negative_control`: an intended selector loads the legitimate module and the planted marker is absent.

No network is available, so RFI is exercised as a loopback/`file:` local analogue; if the finding needs
a real remote fetch, say so and scope the conclusion. Keep the planted module's effect to a marker;
never load real system modules for effect.

## Language notes

- **Python:** `importlib.import_module` / `__import__` with a user name resolve against `sys.path`;
  `spec_from_file_location` with a user path loads an arbitrary file. A key→module allowlist is the guard.
- **JavaScript:** `require(userPath)` / dynamic `import(userPath)`; resolution follows `node_modules`
  and relative paths. A fixed map is the guard.
- **Java:** `Class.forName(name)` / a URLClassLoader over an untrusted path loads classes; an allowlist
  of class names is the guard.
- **Perl:** `do $file` and `require $file` execute the file; `@INC` manipulation widens the search.
  A fixed dispatch table is the guard.

## Pitfalls

- Importing *data* (JSON/YAML) by a user path is path traversal, not inclusion; the distinction is
  whether code *runs* on load.
- Python caches imports in `sys.modules`; use a unique module name per run so a cached benign module
  does not mask or fake the result.
- Clean up planted modules and any `sys.path`/`@INC` changes in a `finally` block as `probe` requires.

## Verdict guidance

- `potentially_exploitable`: an untrusted selector can load an out-of-set code file with no allowlist
  or confinement, and the probe observed the planted file execute.
- `likely_not_exploitable`: cite the allowlist/confinement line, with a complete probe showing the
  attacker selector refused or confined to the intended module.
- `inconclusive`: the loader could not be exercised, or whether the target is code or data was unresolved.
