---
name: cwe-1104-vulnerable-third-party-component
description: A dependency flagged as vulnerable by version; exploitability needs a reachable call path. Use this when the finding is CWE-1104/937/1035.
metadata:
  owner: appsec
  version: 1.0.0
---

# CWE-1104: Use of unmaintained or vulnerable third-party component

## Use this skill when

- The finding is classified CWE-1104, CWE-937 or CWE-1035 (OWASP "components with known
  vulnerabilities"), or a dependency scanner flagged a package version.

## Do not use this skill when

- The finding names a weakness in the repository's own code; use that CWE's skill. A
  vulnerable library call reached with attacker data can also be judged with the skill for its
  weakness class (for example `cwe-1321-prototype-pollution` for an old merge helper).

## When another skill also applies

- The weakness-class skill **wins** for the oracle when the advisory's behaviour can be
  reproduced offline with the installed package. This skill supplies the version evidence,
  the reachability trace and the limitation statement.

## Limitation

The probe sandbox has no network and you cannot consult advisory databases. The finding's
advisory text is an untrusted claim, not evidence. You can establish only (1) which version is
actually installed or locked and (2) whether the repository's code calls the affected API with
attacker-influenced data. Without an offline reproduction of the advisory's behaviour,
neither establishes exploitability or safety, so **the default verdict is `inconclusive`**,
with this limitation stated in the summary.

## Procedure

**Sink.** The affected API of the package as the finding describes it, and every call site in
the repository that reaches it.

**Guard.** A locked version outside the stated affected range; the affected API never called;
input validation before the call; a configuration option that disables the affected feature.

**Neutralized when.** The installed version is outside the affected range the finding states
(observed from the lockfile and the installed package metadata, not from a declared range),
or no production path calls the affected API.

**Source.** Whatever reaches the affected API from untrusted input in this repository.

## Oracle

Version and reachability are recorded as evidence; the probe only reports a definitive
observation when it reproduces the behaviour offline.

1. Record the version: lockfile entry (`package-lock.json`, `poetry.lock`, `pom.xml`
   resolved tree, `cpanfile.snapshot`) and the installed metadata
   (`importlib.metadata.version`, `require('<pkg>/package.json').version`, `$Module::VERSION`).
   A declared range alone is not an installed version.
2. Trace call sites of the affected API from production entry points.
3. Only if the finding describes an observable behaviour that the weakness-class skill can
   test offline, run that oracle against the installed package through the repository's call
   site:

- `target_reached`: the repository's call site ran with attacker-shaped input and reached
  the installed package.
- `vulnerability_observed`: the weakness-class oracle fired.
- `oracle_valid`, `positive_control`, `negative_control`: as the weakness-class skill defines
  them.

If no offline reproduction is possible, do not fabricate one; report version and reachability
in the summary and return `inconclusive`.

## Language notes

- **Python**: `pip show` / `importlib.metadata`, `requirements.txt` pins vs `poetry.lock`;
  vendored copies under `_vendor/`.
- **JavaScript**: `package-lock.json` resolves nested copies; several versions can coexist.
  `npm ls <pkg>` works offline once installed.
- **Java**: `mvn dependency:tree` (offline with a populated `.m2`), shaded jars, Gradle
  `dependencies`.
- **Perl**: `cpanfile.snapshot`, `perl -MModule -e 'print $Module::VERSION'`.

## Pitfalls

- Trusting the version number in the finding instead of the installed metadata.
- Treating an unused transitive dependency as reachable.
- Treating "no call site found" in a dynamic language as proof; plugins and reflection can hide calls.
- Installing a different version to compare; that changes the target.

## Verdict guidance

- `potentially_exploitable`: only with an offline reproduction through the repository's own
  call site of the installed version.
- `likely_not_exploitable`: the installed version is observed outside the stated range, or
  no production path reaches the affected API, cited, with a complete probe of that boundary.
- `inconclusive` (default): version and reachability recorded but the advisory behaviour could
  not be reproduced offline; state that advisory data was unavailable.
