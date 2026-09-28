---
name: build-cpanm
description: Recipe for building a Perl test environment in the sandbox. Use this when planning or
  repairing a build for a cpanfile or Makefile.PL project.
metadata:
  owner: appsec
  version: 1.0.0
---

# Building Perl targets

<!-- generated: activation criteria (scripts/restructure_skills.py) -->

## Use this skill when

- You are producing or repairing an EnvironmentSpec for a Perl repository.
- The repository declares a cpanfile, Makefile.PL, or Build.PL.

## Do not use this skill when

- The repository is not Perl.

<!-- /generated: activation criteria -->

- **Base image:** `perl:5.40` (or the repo's pinned major).
- **Read the dependency declaration before planning.** A Perl repo declares its modules in
  `cpanfile`, `Makefile.PL` (`PREREQ_PM`) or `Build.PL`, and *nothing installs them for you* —
  there is no equivalent of a virtualenv that already has them. Open the file and check that
  your install commands cover every `requires`.
- **Install — this exact shape, verified against the corpus:**

  ```yaml
  system_packages: [gcc, make, libc6-dev]     # DBI and every other XS module is compiled here
  install_commands: ["cpanm --notest --local-lib=/opt/home/perl5 --installdeps ."]
  env: {PERL5LIB: "/work/home/perl5/lib/perl5"}
  test_command: "prove -v {test_file}"
  ```

  Three things about it are not optional:

  - **`--local-lib` is mandatory.** Install commands run as the non-root sandbox user, which
    cannot write perl's site directory. Without `--local-lib`, cpanm warns, *reports success*,
    installs nothing importable, and the build goes green with the dependency missing — the
    failure then surfaces inside the probe as `Can't locate DBI.pm`, where nothing can fix it.
  - **The install path is `/opt/home`, the `PERL5LIB` path is `/work/home`.** The image is built
    with `HOME=/opt/home`; at probe time that directory is copied to a writable `/work/home`
    tmpfs and the test runs from there. `--local-lib=/work/...` fails outright — /work does not
    exist yet — and a `PERL5LIB` under `/opt` finds nothing at probe time.
  - **XS modules need a compiler.** `DBI`, `DBD::SQLite`, `DBD::mysql`, `XML::LibXML` are C
    extensions; without `gcc`/`make`/`libc6-dev` cpanm reports `Building DBI ... FAIL`. Add the
    library's own `-dev` package too where one is needed (`libmysqlclient-dev`, `libxml2-dev`).

  `prove` ships with perl core as part of Test-Harness — do **not** try to install `App::prove`,
  which is not a distribution and fails the build. Add `--mirror <url>` only for a mirror the
  repo declares.
- **Never append `|| true` (or `|| :`, or `; true`) to an install command.** A swallowed cpanm
  failure builds an image the probe cannot even compile in: the build reports success, the smoke
  test (`prove --version`) passes, and the missing module first appears at *probe* time as
  `Can't locate DBI.pm in @INC`. That is the one place nothing can fix it — probe repair
  rewrites a probe that was already correct, and build repair, which could have installed the
  module, never sees a failure. Both Perl SQL-injection cases were lost exactly this way. An
  install that cannot satisfy the cpanfile must fail loudly so build repair gets the log.
- **A local lib needs `PERL5LIB`.** If you install with `-l`/`-L`/`--local-lib`, the modules land
  somewhere the stock `@INC` does not look, so set `env.PERL5LIB` to the matching
  `<dir>/lib/perl5` — otherwise you install the dependencies successfully and the probe still
  dies on them. Installing into the image's own site dirs (the default in `perl:5.40`) avoids
  the problem entirely.
- **test_command:** `prove -v -Ilib {test_file}`. Both flags are load-bearing: `prove` is a TAP
  consumer that parses its child's stream and discards everything that is not TAP, so without
  `-v` every `HARNESS_` marker is thrown away and a correct probe is recorded as having reached
  nothing — the Perl equivalent of running pytest without `-s`. `-Ilib` puts the repository's own
  modules on `@INC` (adjust to the repo's real layout: `-Ilib`, `-It/lib`, `-I.`).
- **Partial builds:** install deps for and test a single module directory.

<!-- generated: constraints (scripts/restructure_skills.py) -->

## Safety constraints

- Install as the non-root sandbox user with `HOME=/work/home`; never `sudo` or run as root.
- Use only the package indexes and registries the repository itself declares.
- Build-time network access is limited to the registry allowlist; probe time has none at all.

## Completion criteria

- The spec names a base image from the allowlisted registries.
- Install commands come from the repository's own manifests.
- The test runner itself is installed, not merely assumed present.
- No install command swallows its own failure (`|| true`, `|| :`, `; true`). A dependency install that reports success when it failed surfaces only at probe time, where probe repair cannot fix it and build repair never sees it.
- `test_command` contains the literal `{test_file}` placeholder — never a hardcoded test path. The harness writes the probe to the path its author chose and substitutes it here; a hardcoded path runs a file that does not exist and no test executes.
- The `prove` command is verbose (`prove -v {test_file}`). prove parses its child's TAP and discards every other line, so without `-v` the probe's markers are thrown away and a correct probe is recorded as having reached nothing — the Perl form of pytest's `-s`.
- Every module the repository's cpanfile/Makefile.PL declares is installed, and if the install used a local lib then `env.PERL5LIB` points at it.

<!-- /generated: constraints -->
