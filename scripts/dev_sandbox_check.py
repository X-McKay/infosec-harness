#!/usr/bin/env python3
"""Execute the managed runtime and build-egress acceptance fixtures."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse


class CheckFailed(RuntimeError):
    pass


def run(
    argv: list[str], *, timeout: int = 120, expect_success: bool | None = True
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CheckFailed(f"command failed: {' '.join(argv)}: {exc}") from exc
    if expect_success is True and result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise CheckFailed(f"command failed ({result.returncode}): {' '.join(argv)}\n{detail}")
    if expect_success is False and result.returncode == 0:
        raise CheckFailed(f"command unexpectedly succeeded: {' '.join(argv)}")
    return result


def docker_json(argv: list[str]) -> object:
    result = run(argv)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise CheckFailed(f"invalid JSON from {' '.join(argv)}: {result.stdout!r}") from exc


def check_runtime(runtime: str, image: str) -> None:
    info = run(["docker", "info", "--format", "{{json .Runtimes}} {{.DefaultRuntime}}"])
    inventory, _, default = info.stdout.rpartition(" ")
    try:
        runtimes = json.loads(inventory)
    except json.JSONDecodeError as exc:
        raise CheckFailed(f"could not parse Docker runtime inventory: {info.stdout!r}") from exc
    if runtime not in runtimes or default.strip() != runtime:
        raise CheckFailed(
            f"Docker must register and default to {runtime!r}; got default={default.strip()!r}, "
            f"runtimes={sorted(runtimes)}"
        )
    run(["docker", "pull", image], timeout=300)
    positive = run(
        [
            "docker", "run", "--rm", f"--runtime={runtime}", "--network=none",
            "--cap-drop=ALL", "--security-opt=no-new-privileges", image, "sh", "-eu", "-c",
            "printf harness-positive >/tmp/observation; "
            "test \"$(cat /tmp/observation)\" = harness-positive; "
            "test ! -e /proc/1/root/host; printf harness-positive",
        ]
    )
    if positive.stdout != "harness-positive":
        raise CheckFailed("positive runsc fixture did not return its independently checked marker")
    run(
        [
            "docker", "run", "--rm", f"--runtime={runtime}", "--network=none", image,
            "sh", "-c", "wget -q -T 3 -O /dev/null http://1.1.1.1",
        ],
        timeout=20,
        expect_success=False,
    )


def check_resource_limits(project: str, runtime: str, image: str) -> None:
    name = f"{project}-resource-fixture"
    run(["docker", "rm", "-f", name], expect_success=None)
    try:
        run(
            [
                "docker", "run", "-d", "--name", name, f"--runtime={runtime}",
                "--network=none", "--memory=128m", "--cpus=0.5", "--pids-limit=32",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", image,
                "sh", "-c", "echo harness-resource-bounded; sleep 60",
            ]
        )
        limits = docker_json(
            [
                "docker", "inspect", name, "--format",
                '{"memory":{{.HostConfig.Memory}},"nano_cpus":{{.HostConfig.NanoCpus}},'
                '"pids":{{.HostConfig.PidsLimit}},"runtime":{{json .HostConfig.Runtime}},'
                '"network":{{json .HostConfig.NetworkMode}}}',
            ]
        )
        expected = {
            "memory": 128 * 1024 * 1024,
            "nano_cpus": 500_000_000,
            "pids": 32,
            "runtime": runtime,
            "network": "none",
        }
        if limits != expected:
            raise CheckFailed(f"resource-bound runsc fixture has unexpected limits: {limits!r}")
        marker = ""
        for _attempt in range(20):
            marker = run(["docker", "logs", name]).stdout
            if marker.strip() == "harness-resource-bounded":
                break
            time.sleep(0.1)
        else:
            raise CheckFailed("resource-bound runsc fixture did not execute its marker")
    finally:
        run(["docker", "rm", "-f", name], expect_success=None)

    exhaustion_name = f"{project}-pids-exhaustion-fixture"
    run(["docker", "rm", "-f", exhaustion_name], expect_success=None)
    try:
        exhausted = run(
            [
                "docker", "run", "--name", exhaustion_name, f"--runtime={runtime}",
                "--network=none", "--memory=512m", "--cpus=0.5", "--pids-limit=32",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", image,
                "sh", "-c",
                'i=0; while [ "$i" -lt 64 ]; do sleep 1 & i=$((i+1)); done; wait',
            ],
            timeout=30,
            expect_success=None,
        )
        state = docker_json(
            [
                "docker", "inspect", exhaustion_name, "--format",
                '{"exit":{{.State.ExitCode}},"oom":{{.State.OOMKilled}},'
                '"pids":{{.HostConfig.PidsLimit}}}',
            ]
        )
        if (
            exhausted.returncode == 0
            or state.get("exit") == 0
            or state.get("oom") is not False
            or state.get("pids") != 32
        ):
            raise CheckFailed(
                "runsc PID-exhaustion fixture did not fail at the configured process bound: "
                f"returncode={exhausted.returncode}, state={state!r}"
            )
    finally:
        run(["docker", "rm", "-f", exhaustion_name], expect_success=None)

    memory_name = f"{project}-memory-exhaustion-fixture"
    run(["docker", "rm", "-f", memory_name], expect_success=None)
    try:
        exhausted = run(
            [
                "docker", "run", "--name", memory_name, f"--runtime={runtime}",
                "--network=none", "--memory=64m", "--cpus=0.5", "--pids-limit=128",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", image,
                "awk", 'BEGIN { s=sprintf("%100000000s", ""); print length(s) }',
            ],
            timeout=30,
            expect_success=None,
        )
        state = docker_json(
            [
                "docker", "inspect", memory_name, "--format",
                '{"exit":{{.State.ExitCode}},"oom":{{.State.OOMKilled}},'
                '"memory":{{.HostConfig.Memory}}}',
            ]
        )
        expected_state = {"exit": 137, "oom": True, "memory": 64 * 1024 * 1024}
        if exhausted.returncode == 0 or state != expected_state:
            raise CheckFailed(
                "runsc memory-exhaustion fixture did not terminate at the configured bound: "
                f"returncode={exhausted.returncode}, state={state!r}"
            )
    finally:
        run(["docker", "rm", "-f", memory_name], expect_success=None)


def check_proxy(network: str, project: str, runtime: str, image: str, proxy_url: str) -> None:
    internal = run(["docker", "network", "inspect", network, "--format", "{{.Internal}}"])
    if internal.stdout.strip().lower() != "true":
        raise CheckFailed(f"build network {network!r} is not Internal=true")
    proxy = run(
        [
            "docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
            "--filter", "label=com.docker.compose.service=egress-proxy", "--format", "{{.Names}}",
        ]
    ).stdout.splitlines()
    if len(proxy) != 1:
        raise CheckFailed(f"expected one running compose egress proxy, found {proxy!r}")
    attached = set(
        docker_json(["docker", "inspect", proxy[0], "--format", "{{json .NetworkSettings.Networks}}"])
    )
    if network not in attached or len(attached) < 2:
        raise CheckFailed(
            f"egress proxy must be dual-homed on {network!r} and an external network; got {sorted(attached)}"
        )
    parsed_proxy = urllib.parse.urlsplit(proxy_url)
    if parsed_proxy.scheme != "http" or not parsed_proxy.hostname or parsed_proxy.port != 3128:
        raise CheckFailed(f"invalid managed build proxy URL: {proxy_url!r}")
    common = ["docker", "run", "--rm", f"--runtime={runtime}", f"--network={network}", image]
    allowed = common + [
        "sh", "-c",
        f"http_proxy={proxy_url} wget -q -T 20 -O /dev/null "
        "http://deb.debian.org/debian/README",
    ]
    last_error = ""
    for _attempt in range(20):
        result = run(allowed, timeout=40, expect_success=None)
        if result.returncode == 0:
            break
        last_error = (result.stderr or result.stdout).strip()
        time.sleep(2)
    else:
        raise CheckFailed(f"allowlisted proxy request never succeeded: {last_error[-1200:]}")
    run(
        common + [
            "sh", "-c",
            f"http_proxy={proxy_url} wget -q -T 8 -O /dev/null http://example.com/",
        ],
        timeout=20,
        expect_success=False,
    )
    run(
        common + [
            "sh", "-c",
            f"http_proxy={proxy_url} wget -q -T 8 -O /dev/null "
            "http://169.254.169.254/latest/meta-data/",
        ],
        timeout=20,
        expect_success=False,
    )
    run(
        common + ["sh", "-c", "wget -q -T 5 -O /dev/null http://1.1.1.1"],
        timeout=20,
        expect_success=False,
    )


def check_builder(builder: str, network: str, runtime: str, proxy_url: str) -> None:
    container = f"buildx_buildkit_{builder}0"
    expected_env = {
        f"HTTP_PROXY={proxy_url}",
        f"HTTPS_PROXY={proxy_url}",
        f"http_proxy={proxy_url}",
        f"https_proxy={proxy_url}",
        "NO_PROXY=localhost,127.0.0.1",
        "no_proxy=localhost,127.0.0.1",
    }
    inspect = run(
        ["docker", "buildx", "inspect", builder, "--bootstrap"],
        timeout=180,
        expect_success=None,
    )
    if inspect.returncode == 0:
        container_state = run(
            [
                "docker", "inspect", container, "--format",
                "{{json .Config.Env}} {{.HostConfig.Runtime}} "
                "{{json .NetworkSettings.Networks}}",
            ],
            expect_success=None,
        )
        stale = container_state.returncode != 0
        if not stale:
            env_json, actual_runtime, networks_json = container_state.stdout.split(" ", 2)
            actual_env = set(json.loads(env_json))
            attached = set(json.loads(networks_json))
            stale = (
                not re.search(r"^Driver:\s+docker-container\s*$", inspect.stdout, re.MULTILINE)
                or actual_runtime != runtime
                or attached != {network}
                or not expected_env <= actual_env
            )
        if stale:
            print(f"builder: recreating stale checkout-managed builder {builder}")
            run(["docker", "buildx", "rm", builder], timeout=180)
            inspect = run(
                ["docker", "buildx", "inspect", builder], expect_success=None
            )
    if inspect.returncode:
        run(
            [
                "docker", "buildx", "create", "--name", builder, "--driver", "docker-container",
                "--driver-opt", f"network={network}",
                "--driver-opt", f"env.HTTP_PROXY={proxy_url}",
                "--driver-opt", f"env.HTTPS_PROXY={proxy_url}",
                "--driver-opt", f"env.http_proxy={proxy_url}",
                "--driver-opt", f"env.https_proxy={proxy_url}",
                "--driver-opt", '"env.NO_PROXY=localhost,127.0.0.1"',
                "--driver-opt", '"env.no_proxy=localhost,127.0.0.1"',
                "--bootstrap",
            ],
            timeout=300,
        )
        inspect = run(["docker", "buildx", "inspect", builder, "--bootstrap"], timeout=180)
    if not re.search(r"^Driver:\s+docker-container\s*$", inspect.stdout, re.MULTILINE):
        raise CheckFailed(f"builder {builder!r} does not use the docker-container driver")
    actual_runtime = run(
        ["docker", "inspect", container, "--format", "{{.HostConfig.Runtime}}"]
    ).stdout.strip()
    attached = set(
        docker_json(["docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}"])
    )
    actual_env = set(
        docker_json(["docker", "inspect", container, "--format", "{{json .Config.Env}}"])
    )
    if actual_runtime != runtime:
        raise CheckFailed(f"builder runtime is {actual_runtime!r}, expected {runtime!r}")
    if attached != {network}:
        raise CheckFailed(f"builder networks are {sorted(attached)!r}, expected only {network!r}")
    if not expected_env <= actual_env:
        raise CheckFailed("builder controller is missing the exact managed proxy environment")


def check_cleanup(project: str, runtime: str, image: str) -> None:
    name = f"{project}-forced-removal-fixture"
    run(["docker", "rm", "-f", name], expect_success=None)
    run(["docker", "run", "-d", "--name", name, f"--runtime={runtime}", "--network=none", image, "sleep", "60"])
    run(["docker", "rm", "-f", name])
    remaining = run(["docker", "inspect", name], expect_success=None)
    if remaining.returncode == 0:
        raise CheckFailed("cancelled fixture container remained after cleanup")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", default="runsc")
    parser.add_argument("--network", required=True)
    parser.add_argument("--proxy", required=True)
    parser.add_argument("--builder", required=True)
    parser.add_argument("--compose-project", required=True)
    parser.add_argument("--image", default="alpine:3.20")
    args = parser.parse_args()
    try:
        check_runtime(args.runtime, args.image)
        check_resource_limits(args.compose_project, args.runtime, args.image)
        check_proxy(args.network, args.compose_project, args.runtime, args.image, args.proxy)
        check_builder(args.builder, args.network, args.runtime, args.proxy)
        check_cleanup(args.compose_project, args.runtime, args.image)
    except CheckFailed as exc:
        print(f"sandbox acceptance failed: {exc}", file=sys.stderr)
        return 3
    print(
        "sandbox: runsc positive/negative, bounded execution, and PID/memory exhaustion fixtures; "
        "internal proxy "
        "allow/deny checks, isolated builder, and manual forced-removal cleanup passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
