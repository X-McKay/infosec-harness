# First live-model validation (2026-09-25 to 2026-09-27)

[`LIVE_VALIDATION.md`](LIVE_VALIDATION.md) records what changed when the harness first ran
against a real model (one self-hosted mid-size open-weights model serving every tier), including
the first gVisor-sandboxed corpus runs through a podman VM on macOS, per-language results,
tool and skill evocation, and the first release-gate measurements. Several regression cases,
budgets and skills cite it. It proves which defects stubs could not show and that the mechanisms
it describes occurred. It does not measure current agents, prompts or policies, it ran builds
under crun rather than gVisor and outside the production `docker` + `runsc` path, and its
accuracy numbers do not generalize beyond that one model.
