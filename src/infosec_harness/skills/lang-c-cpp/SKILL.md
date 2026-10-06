---
name: lang-c-cpp
description: 'Conventions for C and C++ repositories: Make/CMake layout, linking a probe against the
  target with gcc, and memory-safety oracles. Use this when the repository is primarily C or C++.'
metadata:
  owner: appsec
  version: 1.0.0
---

# C and C++ repositories

## Use this skill when

- The repository's primary language is C or C++, or the finding's sink is in a `.c`, `.cc`,
  `.cpp` or `.h` file (including a native extension inside another language's package).

## Do not use this skill when

- The native code is a vendored dependency no production entry point calls (see `investigate`).
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Build files:** `Makefile`, `CMakeLists.txt`, `configure.ac`/`configure`, `meson.build`,
  `*.vcxproj`. Sources in `src/`, headers in `include/`; `main()` marks a program entry point.
- **Entry points:** `main`, exported functions declared in public headers, parser entry
  points (`parse_*`, `*_decode`), handlers reading from a socket or file.
- **Sinks to note:** `memcpy`/`strcpy`/`strcat`/`sprintf`/`gets` into fixed buffers, length
  arithmetic before `malloc` (integer overflow), `free` paths (use-after-free, double free),
  `printf(user)` (format string), `system`/`popen`, `exec*` with `sh -c`.

## Inspect dependencies offline

Read the build file for `-l` libraries, `pkg-config` names and `find_package` calls; check
each header exists before planning a build: `echo '#include <zlib.h>' | gcc -x c -fsyntax-only -`.
`make -n` prints the commands a target would run without running them.

## Compile and run a probe

The image declares `gcc` and `make` only: no `g++`, `clang`, `cmake`, `gdb` or `valgrind`.
Do not run `./configure` or `make` in the source tree: they can rewrite tracked files. Compile
just the translation units the target needs, into `.harness-build/`, inside `run_probe`:

```bash
mkdir -p .harness-build && gcc -std=gnu11 -g -O0 -Iinclude -o .harness-build/probe \
  .harness-probe/probe.c src/parser.c && ./.harness-build/probe
```

- A target file with its own `main`: compile it with `-Dmain=harness_target_main`.
- A `static` function: `#include "../src/parser.c"` from the probe file instead of linking it.
- Run the target call in a `fork()`ed child and `waitpid` it in the parent, so a crash is an
  observation (`WIFSIGNALED`, `WTERMSIG`) and the parent still prints the final line. Run
  `ulimit -c 0` first. Never `-D` away a check or edit a header to make code compile.

## Memory-safety oracles

- `-fsanitize=address` needs the `libasan` runtime and a large shadow mapping; whether either
  works under the sandbox's runtime and memory limits is unverified, so **do not rely on it**.
  If you try it, set `ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:exitcode=86` and include a
  positive control (an overflow of a buffer the probe owns) that must report before a silent
  target run means anything.
- Runtime-free alternatives: `-fsanitize=undefined,bounds -fsanitize-undefined-trap-on-error`
  traps (`SIGILL` on x86-64, `SIGTRAP` on arm64) and needs no library; a guard page (an `mmap`ed buffer ending at a
  `PROT_NONE` page, passed as the target's output buffer) turns a one-byte overrun into a
  deterministic `SIGSEGV`; `MALLOC_CHECK_=3` makes glibc abort on many heap corruptions.
- A crash is evidence of memory corruption at that site, not of control-flow hijack. Keep the
  payload the minimum that crosses the boundary; never build a weaponized exploit.

## The HARNESS_PROBE line

Print it last, from the parent, after the child has been reaped, then `fflush(stdout)`:

```c
static const char *b(int v) { return v ? "true" : "false"; }
printf("HARNESS_PROBE {\"target_reached\":%s,\"oracle_valid\":%s,\"positive_control\":%s,"
       "\"negative_control\":%s,\"vulnerability_observed\":%s}\n", b(t), b(o), b(p), b(n), b(v));
```

C++ (only if `g++` exists): `std::cout << std::boolalpha` before streaming the `bool`s.
Never print `%d`: `1`/`0` are numbers and are rejected.

## Common failure modes

- Missing system headers or libraries: a build limitation, not a guard.
- Child output after the parent's line, or buffered output duplicated by `fork`: `fflush`
  before forking and print the line only in the parent.
- An optimizer that removed the overflowing store: use `-O0`.
- `make` producing symlinks (`libfoo.so -> libfoo.so.1`): the archive check rejects links.

## When the toolchain is absent

Verify before planning: `command -v gcc make` and, for C++, `command -v g++`; also confirm a
trivial `#include <stdio.h>` program compiles. If a needed compiler, header or library is
missing, stop: do not fetch toolchains or translate the code into another language (a rewrite
is a stand-in). Return `inconclusive` and name the exact missing tool (for example
`g++: not found`) as a limitation in the verdict summary, plus what you established by reading.
A build system named in a file is not evidence that the build ran here.

## Completion criteria

- You can name the build system, the translation units linked into the probe, the flags used,
  and how a crash is distinguished from a clean run.
