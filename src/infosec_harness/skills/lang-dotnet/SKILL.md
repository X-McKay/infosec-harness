---
name: lang-dotnet
description: 'Conventions for .NET repositories (C#, F#, VB): solutions, NuGet restore, console-project
  probes and ASP.NET Core. Use this when the repository is primarily .NET; the workspace image has no dotnet SDK by default.'
metadata:
  owner: appsec
  version: 1.0.0
---

# .NET repositories

## First: check the toolchain

The workspace image does **not** include the .NET SDK. Before anything else run
`command -v dotnet` and, if it prints a path, `dotnet --list-sdks` and `dotnet --list-runtimes`.
If it is absent, read the code to locate the sink and guard, then follow "When the toolchain
is absent". Mono is not installed either.

## Use this skill when

- The repository has `*.sln`, `*.csproj`, `*.fsproj` or `*.vbproj` files, or the sink is in
  `.cs`, `.fs` or `.vb` source.

## Do not use this skill when

- The code is a vendored package no production entry point calls.
- You are planning installs — use `environment`. This skill grants no permissions.

## Recognize the project

- **Manifests:** `*.sln`, project files (`TargetFramework`, `PackageReference`,
  `ProjectReference`), `Directory.Build.props`/`Directory.Packages.props`, `global.json`
  (pins an SDK version and roll-forward), `packages.lock.json`, `NuGet.config` (feeds).
- **Entry points:** `Program.cs` (`Main` or top-level statements), ASP.NET Core
  controllers (`[ApiController]`, `[HttpGet]`), minimal APIs (`app.MapGet`), Razor Pages,
  SignalR hubs, Azure Functions (`[Function]`).
- **Sinks to note:** `Process.Start` with `cmd.exe /c` or `/bin/sh -c`, `SqlCommand` /
  `FromSqlRaw` / `ExecuteSqlRaw` with interpolation (note `FromSqlInterpolated` binds),
  `Path.Combine` with a rooted untrusted segment (replaces the base), `BinaryFormatter`,
  `TypeNameHandling` other than `None` in Json.NET, `XmlDocument` with a resolver,
  `Html.Raw`, `HttpClient` with a user URL.

## Inspect dependencies offline

Read the project files, `packages.lock.json` and any committed `obj/project.assets.json`.
Keep every .NET path inside the repository and repeat these in every command line, because
each `execute` and `run_probe` starts a fresh shell and the sandbox user has no home:

```bash
export DOTNET_CLI_HOME=/workspace/repo/.harness-home NUGET_PACKAGES=/workspace/repo/.harness-deps/nuget \
  DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
```

Restore only in the workspace, once, with `dotnet restore` (`--locked-mode` when a lockfile
exists); a policy denial or private feed is a limitation. The probe sandbox is offline: build
and run there with `--no-restore`.

## Compile and run a probe

Create a separate console project, never edit the target's project files:

- `.harness-probe/Probe.csproj` with the target's `TargetFramework` and a
  `<ProjectReference Include="../src/App/App.csproj" />`; `Program.cs` calls the real API.
- Restore it in the workspace, then in `run_probe`:
  `dotnet build .harness-probe --no-restore -o .harness-build && dotnet .harness-build/Probe.dll`.
- `internal` members: call them through reflection (`BindingFlags.NonPublic`) on the real
  type; adding `InternalsVisibleTo` would edit source.
- An ASP.NET Core app: host it on `http://127.0.0.1:0` in-process and send requests with
  `HttpClient` to that loopback address.
- `dotnet test` prints a summary after your output; use the console project for evidence.

## The HARNESS_PROBE line

`bool.ToString()` gives `True`/`False`, which is not JSON. Serialize instead:

```csharp
Console.WriteLine("HARNESS_PROBE " + System.Text.Json.JsonSerializer.Serialize(new {
    target_reached = t, oracle_valid = o, positive_control = p,
    negative_control = n, vulnerability_observed = v }));
```

## Common failure modes

- `global.json` pins an SDK that is not installed: a limitation; do not delete or edit it.
- Target framework newer than the installed runtime; `DOTNET_ROLL_FORWARD=Major` changes
  behaviour (for example `BinaryFormatter` is disabled from .NET 8), so record it if used.
- Windows-only APIs or `net4x` frameworks do not run on Linux: a limitation.
- Restore needing a private feed from `NuGet.config`: a dependency limitation.

## When the toolchain is absent

Run `command -v dotnet` first. If it prints nothing, the .NET SDK is not installed in this
image: do not run `dotnet-install.sh`, download an SDK or packages, and do not port the code to
Java or Python (a port is a stand-in, never the target). Return `inconclusive`, name
`dotnet: not found` as the limitation in the verdict summary, and record what reading
established (sink line, guard line, the oracle you would run). A `global.json` or CI file
naming an SDK is not execution evidence.

## Completion criteria

- You can name the solution, the project and entry point reaching the sink, and either the
  probe you ran or the exact missing tool.
