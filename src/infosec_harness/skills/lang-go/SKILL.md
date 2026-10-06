---
name: lang-go
description: 'Go repositories: modules, vendoring, in-package test probes. Use this when the repository is primarily Go; the image has no Go toolchain.'
metadata:
  owner: appsec
  version: 1.0.0
---

# Go repositories

## First: check the toolchain

The workspace image does **not** include Go. Before anything else run `command -v go` and,
if it prints a path, `go version`. If Go is absent, read the code to locate the sink and
guard, then follow "When the toolchain is absent" below. Do not plan a build first.

## Use this skill when

- The repository has a `go.mod` at its root or the finding's sink is in a `.go` file.

## Do not use this skill when

- The Go code is vendored under another project and no production entry point calls it.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Manifests:** `go.mod` (module path, `go` and `toolchain` directives, `replace`), `go.sum`,
  `vendor/modules.txt`, `go.work` for multi-module workspaces.
- **Layout:** package = directory; `cmd/<name>/main.go` for binaries; `internal/` packages are
  importable only from inside the same module; `_test.go` files are tests.
- **Entry points:** `net/http` handlers (`http.HandleFunc`, `ServeHTTP`), gin/echo/chi/fiber
  routes, gRPC service methods, cobra commands, `func main`.
- **Sinks to note:** `exec.Command("sh", "-c", ...)`, `db.Query(fmt.Sprintf(...))`,
  `filepath.Join` with untrusted segments (no containment), `template.HTML(...)` or
  `text/template` for HTML, `http.Get(userURL)`, `encoding/gob`/`yaml` into interfaces,
  `unsafe`, unchecked slice bounds that panic (a denial of service, not memory corruption).

## Inspect dependencies offline

Read `go.mod`, `go.sum` and `vendor/modules.txt`; with a toolchain, `go list -m all` and
`go list -deps ./pkg` work offline once modules are present. Keep the module cache inside the
repository so it transfers to the probe sandbox; the build cache can stay in `/tmp`:

```bash
export HOME=/workspace/repo/.harness-home GOPATH=/workspace/repo/.harness-deps/go \
  GOCACHE=/tmp/harness-gocache GOTOOLCHAIN=local GOPROXY=off GOFLAGS=-mod=vendor
```

Each `execute` and `run_probe` starts a fresh shell: repeat these in every command line.
Use `-mod=vendor` only when `vendor/` exists. Otherwise populate the module cache once in the
workspace, without `GOPROXY=off`, with `go mod download` (it fetches only what `go.sum` pins);
a policy denial is a limitation, not a reason to try another source. Then use `-mod=mod` with
`GOPROXY=off` in the probe. `GOTOOLCHAIN=local` stops a `toolchain`
directive from downloading another Go; a version mismatch is then a reported limitation.

## Compile and run a probe

Put the probe in the target's own package so unexported functions are reachable:
`pkg/parser/harness_probe_test.go` with the same `package` clause. Compile the test binary
and run it directly; `go test` prints `ok ...` after your output, which breaks the last line:

```bash
go test -c -vet=off -o .harness-build/probe.test ./pkg/parser && \
  ./.harness-build/probe.test -test.run '^TestHarnessProbe$'
```

Print the line from `TestMain` after `m.Run()` (which prints `PASS`) and before `os.Exit`.
For HTTP handlers, `httptest.NewServer(handler)` listens on loopback only; for a binary under
`cmd/`, build it and drive it with argv/stdin from the probe.

## The HARNESS_PROBE line

```go
out, _ := json.Marshal(map[string]bool{"target_reached": t, "oracle_valid": o,
	"positive_control": p, "negative_control": n, "vulnerability_observed": v})
fmt.Println("HARNESS_PROBE " + string(out))
```

`map[string]bool` guarantees JSON booleans; never format with `%d` or `%v` of an int.

## Common failure modes

- A `//go:build` constraint or file suffix (`_windows.go`) excludes the target file.
- A panic in a goroutine you did not start kills the process before the line: run that call in
  a subprocess or `recover` in the goroutine you own.
- cgo: a package that imports `"C"` needs `gcc` and the C headers (`CGO_ENABLED=1`); without
  them set `CGO_ENABLED=0` only if the target does not need cgo, and say so. `-race` needs cgo.
- Cached test results: run the compiled binary, or pass `-count=1`.

## When the toolchain is absent

Run `command -v go` first. If it prints nothing, Go is not installed in this image: do not
download a Go distribution, use `GOTOOLCHAIN=auto`, or rewrite the code in Python (a rewrite is
a stand-in, never the target). Return `inconclusive`, name `go: not found` as the limitation in
the verdict summary, and record what reading established (sink line, guard line, the oracle
you would run). A `go.mod` `toolchain` line or CI config naming Go is not execution evidence.

## Completion criteria

- You can name the module path, the package holding the sink, its entry points, and either the
  probe binary you ran or the exact missing tool.
