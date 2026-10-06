"""Native protocol regression cases; fakes are not live isolation evidence."""

import asyncio
import copy
import hashlib
import io
import json
import tarfile
import threading
import uuid
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from google.protobuf.json_format import MessageToDict
from openshell._proto import datamodel_pb2 as data
from openshell._proto import openshell_pb2 as pb

from infosec_harness.sandbox import (
    ExecutionUnknown,
    OpenShell,
    OpenShellConfig,
    OpenShellError,
    Profile,
    UnsafeSnapshotMetadata,
)
from infosec_harness.sandbox.transfer import _path


class Stream:
    def __init__(self, events):
        self.events = events
        self.cancelled = False

    def __iter__(self):
        return iter(self.events)

    def cancel(self):
        self.cancelled = True


def output(text, code=0):
    events = [pb.ExecSandboxEvent(stdout=pb.ExecSandboxStdout(data=text.encode() if isinstance(text, str) else text))]
    if code is not None:
        events.append(pb.ExecSandboxEvent(exit=pb.ExecSandboxExit(exit_code=code)))
    return Stream(events)


PROOF = {"uid": 65532, "nnp": "1", "seccomp": "2", "caps": 0,
         "filesystem_denied": True, "network_denied": True, "memory": "536870912",
         "cpu": "100000 100000", "sockets_absent": True, "credentials_absent": True,
         "workspace_writable": True, "shared_tmp_mode": 0o1777,
         "shared_tmp_denied": True, "symlink_escape_denied": True,
         "null_sink_verified": True, "null_device_major": 1, "null_device_minor": 3}


class Native:
    def __init__(self):
        self.resources = {}
        self.execs = []
        self.request_ids = set()
        self.observations = []
        self.creates = []
        self.proof = PROOF.copy()
        self.next_output = "ok"
        self.next_code = 0
        self.last_stream = None
        self.deleted = []
        self.archive = b""

    def CreateSandbox(self, request, timeout):
        assert str(uuid.UUID(request.request_id)) == request.request_id
        assert len(request.name) <= 19 and all(len(v) <= 63 for v in request.labels.values())
        self.creates.append(request)
        sandbox = pb.Sandbox(metadata=data.ObjectMeta(id=str(uuid.uuid4()), name=request.name,
            labels=request.labels, resource_version=1), spec=request.spec,
            status=pb.SandboxStatus(phase=pb.SANDBOX_PHASE_READY, configuration_activated=True,
                main_process_instance_id="process-1",
                configuration_admission=pb.SandboxConfigurationAdmission(
                    state=pb.CONFIGURATION_ADMISSION_STATE_ACCEPTED, instance_id="instance-1",
                    config_revision=1, policy_hash="policy-1")))
        self.resources[request.name] = sandbox
        return pb.SandboxResponse(sandbox=sandbox)

    def GetSandbox(self, request, timeout):
        return pb.SandboxResponse(sandbox=self.resources[request.name])

    def ListSandboxProviders(self, request, timeout):
        assert request.sandbox in self.resources
        return pb.ListSandboxProvidersResponse()

    def ExecSandbox(self, request, timeout):
        assert request.sandbox in self.resources
        assert str(uuid.UUID(request.request_id)) == request.request_id
        assert request.no_login_shell and not request.tty and not request.environment
        assert request.execution_timeout.seconds > 0
        if request.request_id in self.request_ids:
            raise RuntimeError("execution terminated, but its output stream is not stored; "
                               "this request was not launched again")
        self.request_ids.add(request.request_id)
        if "NoNewPrivs" in request.command[-1]:
            self.observations.append(request)
        else:
            self.execs.append(request)
        text = json.dumps(self.proof) if "NoNewPrivs" in request.command[-1] else self.next_output
        if request.command[0] == "/usr/bin/tar":
            text = self.archive
        elif "extractall" in " ".join(request.command):
            text = ""
        self.last_stream = output(text, self.next_code)
        return self.last_stream

    def wait_ready(self, name, **kwargs):
        return SimpleNamespace(id=self.resources[name].metadata.id)

    def delete(self, name, **kwargs):
        self.deleted.append(name)
        del self.resources[name]

    def wait_deleted(self, name, **kwargs):
        assert name not in self.resources


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    import openshell

    native = Native()
    native._stub = native
    monkeypatch.setattr(openshell, "SandboxClient", lambda *args, **kwargs: native)
    policy = tmp_path / "policy.yaml"
    policy.write_text(json.dumps({"version": 1,
        "filesystem": {"include_workdir": False, "read_only": ["/usr", "/etc", "/proc", "/sys"],
                       "read_write": ["/workspace", "/tmp", "/dev/null"]},
        "landlock": {"compatibility": "hard_requirement"},
        "process": {"run_as_user": "65532", "run_as_group": "65532"},
        "network_policies": {}}))
    image = "sha256:" + "a" * 64
    profile = Profile(image=image, policy=policy)
    config = OpenShellConfig(endpoint="127.0.0.1:7777", state_dir=tmp_path / "state",
        inspection_socket="unix:///dedicated/docker.sock",
        inspection_command=("/usr/bin/docker", "--host", "unix:///dedicated/docker.sock"),
        supervisor_image=image,
        profiles={"workspace": profile, "probe": profile, "model": profile})
    boundary = OpenShell(config)

    async def inspection(args):
        if args[0] == "ps":
            ident = args[-1].split("=", 2)[-1]
            return ident.replace("-", "") + "\n" + "bb" if any(
                value.metadata.id == ident for value in native.resources.values()) else ""
        ident = next(value.metadata.id for value in native.resources.values()
                     if value.metadata.id.replace("-", "") == args[1])
        values = [{"Config": {"Labels": {"openshell.ai/sandbox-id": ident,
                    "openshell.ai/isolation-role": role}, "User": "65532:65532"},
                   "Id": ident.replace("-", "") if role == "sandbox" else "bb",
                   "State": {"Running": True, "StartedAt": "2026-10-05T00:00:00Z"}, "Image": image,
                   "HostConfig": {"Runtime": "runc", "NetworkMode": "none", "Privileged": False,
                    "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"],
                    "Memory": 536870912, "NanoCpus": 1000000000,
                    "ReadonlyRootfs": True, "PidsLimit": 1024}, "Mounts": []}
                  for role in ("sandbox", "supervisor")]
        return json.dumps(values)

    monkeypatch.setattr(boundary, "_inspection_call", inspection)
    return boundary, native


@pytest.mark.asyncio
async def test_native_create_and_exec_receipt_replay(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    again = await boundary.create("run")
    assert sandbox == again and len(native.creates) == 1
    result = await boundary.execute(sandbox, ["printf", "ok"], operation_id="activity-1", timeout=3)
    repeated = await boundary.execute(sandbox, ["printf", "ok"], operation_id="activity-1", timeout=3)
    assert result == repeated and len(native.execs) == 1
    receipt = boundary.receipts("run")[0]
    assert receipt.command == ["printf", "ok"] and receipt.sandbox.id == sandbox.id
    assert native.execs[0].sandbox == sandbox.name
    assert MessageToDict(native.creates[0].spec.template.resources) == {"limits": {"cpu": "1", "memory": "512Mi"}}
    # Live native sandboxes carry these exact labels; close() of a pending create requires them.
    assert dict(native.creates[0].labels) == {
        "ih.owner": "infosec-harness.v3",
        "ih.run": hashlib.sha256(b"run").hexdigest()[:32],
        "ih.profile": "workspace",
    }


@pytest.mark.asyncio
async def test_repeated_model_admission_reuses_qualification_without_replaying_commands(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run", profile="model")
    first = await boundary.execute(sandbox, "model request", operation_id="model:2", timeout=3)
    again = await boundary.create("run", profile="model")
    second = await boundary.execute(again, "next model request", operation_id="model:3", timeout=3)
    assert sandbox == again and len(native.creates) == 1
    assert len(native.observations) == 1
    qualification = json.loads(next((boundary.config.state_dir / "qualification").glob("*.json")).read_bytes())
    assert qualification["request_id"] == native.observations[0].request_id
    command_ids = [request.request_id for request in native.execs]
    assert await boundary.execute(again, "model request", operation_id="model:2", timeout=3) == first
    assert await boundary.execute(again, "next model request", operation_id="model:3", timeout=3) == second
    assert [request.request_id for request in native.execs] == command_ids


@pytest.mark.asyncio
async def test_unknown_admission_closes_instead_of_resending_observation(adapter):
    boundary, native = adapter
    native.next_code = None
    with pytest.raises(ExecutionUnknown, match="without an exit receipt"):
        await boundary.create("run", profile="model")
    with pytest.raises(OpenShellError, match="closed investigation"):
        await boundary.create("run", profile="model")
    assert len(native.observations) == 1 and len(native.creates) == 1
    assert not native.resources and not boundary.receipts("run")


@pytest.mark.asyncio
@pytest.mark.parametrize("exit_code", [None, 124])
async def test_exec_unknown_is_fenced_across_worker_restart(adapter, monkeypatch, exit_code):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    native.next_code = exit_code
    with pytest.raises(ExecutionUnknown, match="unknown"):
        await boundary.execute(sandbox, "touch file", operation_id="activity", timeout=3)
    assert len(native.execs) == 1 and native.deleted == [sandbox.name]
    assert native.last_stream.cancelled
    assert not boundary.receipts("run")
    # Inspect the persisted fence independently; no completed outcome was invented.
    saved = json.loads(next((boundary.config.state_dir / "operations").glob("*.json")).read_bytes())
    assert "result" not in saved
    # If this sandbox were still active after a crashed worker, prior unknown
    # operation receipt still refuses redispatch, even in a fresh adapter.
    restarted = OpenShell(boundary.config)
    monkeypatch.setattr(restarted, "_owned", lambda handle: None)
    with pytest.raises(ExecutionUnknown, match="prior dispatch"):
        await restarted.execute(sandbox, "touch file", operation_id="activity", timeout=3)
    assert len(native.execs) == 1


@pytest.mark.asyncio
async def test_operation_id_cannot_change_request(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    await boundary.execute(sandbox, "printf ok", operation_id="activity", timeout=3)
    with pytest.raises(OpenShellError, match="different request"):
        await boundary.execute(sandbox, "rm file", operation_id="activity", timeout=3)
    assert len(native.execs) == 1


@pytest.mark.asyncio
async def test_completed_receipt_replays_after_cleanup(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    result = await boundary.execute(sandbox, "true", operation_id="activity", timeout=3)
    await boundary.close_run("run")
    assert await boundary.execute(sandbox, "true", operation_id="activity", timeout=3) == result
    assert len(native.execs) == 1


@pytest.mark.asyncio
async def test_output_overflow_cancels_rpc_and_closes_sandbox(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    native.next_output = "x" * (boundary.config.max_output_bytes + 1)
    with pytest.raises(ExecutionUnknown):
        await boundary.execute(sandbox, "spam", operation_id="activity", timeout=3)
    assert native.last_stream.cancelled
    assert native.deleted == [sandbox.name]
    assert not boundary.receipts("run")


@pytest.mark.parametrize("field,value", [("uid", 0), ("caps", 1), ("nnp", "0"),
    ("seccomp", "0"), ("filesystem_denied", False), ("network_denied", False),
    ("workspace_writable", False),
    ("shared_tmp_mode", 0o755), ("shared_tmp_denied", False),
    ("shared_tmp_denied", "true"), ("symlink_escape_denied", False),
    ("null_sink_verified", False), ("null_sink_verified", "true"),
    ("null_device_major", 0), ("null_device_minor", 5),
    ("sockets_absent", False), ("credentials_absent", False), ("memory", "max"),
    ("cpu", "max 100000")])
@pytest.mark.asyncio
async def test_unconfined_workload_is_deleted_before_handle_return(adapter, field, value):
    boundary, native = adapter
    native.proof[field] = value
    with pytest.raises(OpenShellError, match="confinement"):
        await boundary.create("run")
    assert len(native.deleted) == 1
    assert not native.execs


@pytest.mark.asyncio
async def test_missing_discriminating_native_filesystem_proof_refuses_workload(adapter):
    boundary, native = adapter
    native.proof.pop("shared_tmp_denied")
    with pytest.raises(OpenShellError, match="confinement"):
        await boundary.create("run")
    assert len(native.deleted) == 1 and not native.execs


@pytest.mark.parametrize("writes", [["/workspace", "/tmp"],
    ["/workspace", "/tmp", "/dev"], ["/workspace", "/tmp", "/dev/null", "/dev/zero"]])
def test_only_explicit_null_sink_is_allowed_outside_workspace(adapter, writes):
    boundary, _ = adapter
    path = boundary.config.profiles["workspace"].policy
    document = json.loads(path.read_bytes())
    document["filesystem"]["read_write"] = writes
    path.write_text(json.dumps(document))
    with pytest.raises(OpenShellError, match="confined writes"):
        boundary._spec("workspace")


@pytest.mark.asyncio
async def test_cleanup_failure_does_not_skip_other_owned_sandboxes(adapter, monkeypatch):
    boundary, native = adapter
    first = await boundary.create("run")
    other = await boundary.create("run", profile="probe", slot="other")
    original = boundary.close

    async def close(sandbox):
        if sandbox.id == first.id:
            raise ExecutionUnknown("first cleanup unknown")
        await original(sandbox)

    monkeypatch.setattr(boundary, "close", close)
    with pytest.raises(ExecutionUnknown, match="first cleanup unknown"):
        await boundary.close_run("run")
    assert native.deleted == [other.name] and first.name in native.resources


@pytest.mark.asyncio
async def test_outer_mount_fence_requires_observation(adapter, monkeypatch):
    boundary, native = adapter
    original = boundary._inspection_call

    async def unsafe(args):
        raw = await original(args)
        if args[0] == "inspect":
            values = json.loads(raw)
            values[0]["Mounts"] = [{"Type": "bind", "Destination": "/workspace"}]
            return json.dumps(values)
        return raw

    monkeypatch.setattr(boundary, "_inspection_call", unsafe)
    with pytest.raises(OpenShellError, match="outer workload fence"):
        await boundary.create("run")
    assert len(native.deleted) == 1 and not native.execs


@pytest.mark.asyncio
async def test_close_idempotent_and_never_deletes_replacement(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    native.resources[sandbox.name].metadata.id = "replacement"
    with pytest.raises(OpenShellError, match="another native id"):
        await boundary.close(sandbox)
    assert not native.deleted
    native.resources[sandbox.name].metadata.id = sandbox.id
    await boundary.close(sandbox)
    await boundary.close(sandbox)
    assert native.deleted == [sandbox.name]


@pytest.mark.asyncio
async def test_closed_run_cannot_reacquire_or_execute(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    await boundary.close_run("run")
    with pytest.raises(OpenShellError, match="closed"):
        await boundary.create("run", profile="probe", slot="other")
    with pytest.raises(OpenShellError, match="owned"):
        await boundary.execute(sandbox, "true", operation_id="activity", timeout=3)


@pytest.mark.asyncio
async def test_cancelled_create_finishes_ownership_record_and_native_cleanup(adapter, monkeypatch):
    boundary, native = adapter
    original = native.CreateSandbox
    entered, release = threading.Event(), threading.Event()

    def delayed(request, timeout):
        entered.set()
        assert release.wait(3)
        return original(request, timeout)

    monkeypatch.setattr(native, "CreateSandbox", delayed)
    task = asyncio.create_task(boundary.create("run"))
    assert await asyncio.to_thread(entered.wait, 3)
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(native.deleted) == 1 and not native.resources
    saved = json.loads(next((boundary.config.state_dir / "sandboxes").glob("*.json")).read_bytes())
    assert saved["closed"] and saved["sandbox"]["id"]


async def cancel_repeatedly(task, times=3):
    """Deliver several cancellation requests, as a Temporal worker shutdown can."""
    for _ in range(times):
        task.cancel()
        await asyncio.sleep(0)


async def test_repeatedly_cancelled_create_still_finishes_native_cleanup(adapter, monkeypatch):
    boundary, native = adapter
    original, original_delete = native.CreateSandbox, native.delete
    entered, release, deleting, deleted = (threading.Event() for _ in range(4))

    def delayed(request, timeout):
        entered.set()
        assert release.wait(3)
        return original(request, timeout)

    def slow_delete(name, **kwargs):
        deleting.set()
        assert deleted.wait(3)
        original_delete(name, **kwargs)

    monkeypatch.setattr(native, "CreateSandbox", delayed)
    monkeypatch.setattr(native, "delete", slow_delete)
    task = asyncio.create_task(boundary.create("run"))
    assert await asyncio.to_thread(entered.wait, 3)
    await cancel_repeatedly(task)
    release.set()
    assert await asyncio.to_thread(deleting.wait, 3)
    await cancel_repeatedly(task)  # while the owned close is in flight
    deleted.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(native.deleted) == 1 and not native.resources
    saved = json.loads(next((boundary.config.state_dir / "sandboxes").glob("*.json")).read_bytes())
    assert saved["closed"] and saved["sandbox"]["id"]


async def test_repeatedly_cancelled_exec_still_closes_its_sandbox(adapter, monkeypatch):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    original, original_delete = native.ExecSandbox, native.delete
    entered, release, deleting, deleted = (threading.Event() for _ in range(4))

    def blocked(request, timeout):
        entered.set()
        assert release.wait(3)
        return original(request, timeout)

    def slow_delete(name, **kwargs):
        deleting.set()
        assert deleted.wait(3)
        original_delete(name, **kwargs)

    monkeypatch.setattr(native, "ExecSandbox", blocked)
    monkeypatch.setattr(native, "delete", slow_delete)
    task = asyncio.create_task(boundary.execute(sandbox, "true", operation_id="activity", timeout=3))
    assert await asyncio.to_thread(entered.wait, 3)
    await cancel_repeatedly(task)
    release.set()
    assert await asyncio.to_thread(deleting.wait, 3)
    await cancel_repeatedly(task)
    deleted.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert native.deleted == [sandbox.name]
    saved = json.loads(next((boundary.config.state_dir / "sandboxes").glob("*.json")).read_bytes())
    assert saved["closed"]


@pytest.mark.asyncio
async def test_unexpected_workspace_provider_is_rejected(adapter, monkeypatch):
    boundary, native = adapter

    def attached(request, timeout):
        return pb.ListSandboxProvidersResponse(providers=[data.Provider(
            metadata=data.ObjectMeta(id="unexpected", name="provider", workspace="default",
                                     resource_version=1), type="openai")])

    monkeypatch.setattr(native, "ListSandboxProviders", attached)
    with pytest.raises(OpenShellError, match="provider attachment"):
        await boundary.create("run")
    assert len(native.deleted) == 1 and not native.execs


@pytest.mark.asyncio
async def test_forged_handle_cannot_execute(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    with pytest.raises(OpenShellError, match="owned"):
        await boundary.execute(replace(sandbox, run_id="other"), "true", operation_id="x", timeout=3)
    assert not native.execs


@pytest.mark.parametrize("value", ["/etc/passwd", "/workspace/../etc/passwd", "/workspace//a", "a"])
def test_repository_path_confinement(value):
    with pytest.raises(OpenShellError):
        _path(value)


def test_provider_cannot_be_attached_to_repository_profile(adapter):
    boundary, _ = adapter
    values = boundary.config.model_dump()
    values["profiles"] = copy.deepcopy(values["profiles"])
    values["profiles"]["workspace"]["provider"] = "secret"
    with pytest.raises(ValueError, match="must not have providers"):
        OpenShellConfig.model_validate(values)


@pytest.mark.parametrize("tls,access,accepted", [(None, None, True), ("skip", None, False),
    ("passthrough", None, False), ("terminate", None, False), (None, "read_only", False)])
def test_native_package_policy_uses_automatic_tls_and_exclusive_l7_rules(adapter, tls, access, accepted):
    boundary, _ = adapter
    path = boundary.config.profiles["workspace"].policy
    document = json.loads(path.read_bytes())
    endpoint = {"host": "pypi.org", "port": 443, "protocol": "rest", "enforcement": "enforce",
        "rules": [{"allow": {"method": "GET", "path": "/**"}}]}
    if tls:
        endpoint["tls"] = tls
    if access:
        endpoint["access"] = access
    document["network_policies"] = {"packages": {"endpoints": [endpoint],
        "binaries": [{"path": "/usr/local/bin/python3.12"}]}}
    path.write_text(json.dumps(document))
    if accepted:
        spec = boundary._spec("workspace")
        observed = spec.policy.network_policies["packages"].endpoints[0]
        assert observed.enforcement == 1 and observed.tls == 0
    else:
        with pytest.raises(OpenShellError, match="package egress"):
            boundary._spec("workspace")


@pytest.mark.asyncio
async def test_model_cannot_receive_source_and_source_symlinks_rejected(adapter, tmp_path):
    boundary, _ = adapter
    model = await boundary.create("model-run", profile="model")
    with pytest.raises(OpenShellError, match="forbidden"):
        await boundary.upload(model, tmp_path, "/workspace/repo")
    sandbox = await boundary.create("run")
    source = tmp_path / "source"
    source.mkdir()
    (source / "secret").symlink_to("/etc/passwd")
    with pytest.raises(OpenShellError, match="symlinks"):
        await boundary.upload(sandbox, source, "/workspace/repo")


def archive(member):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        tar.addfile(member, io.BytesIO(b"x" * member.size) if member.isfile() else None)
    return stream.getvalue()


def original_of(tmp_path, member: tarfile.TarInfo) -> Path:
    """The original source directory that ``archive(member)`` captures unchanged."""
    original = tmp_path / "original"
    original.mkdir()
    if member.isfile() and not member.name.startswith(("/", "..")):
        (original / member.name).write_bytes(b"x" * member.size)
    return original


def source_archive(content, *, include_original=True, mode=0o644):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as tar:
        if include_original:
            member = tarfile.TarInfo("source.py")
            member.size = len(content)
            member.mode = mode
            tar.addfile(member, io.BytesIO(content))
        extra = tarfile.TarInfo("probe.py")
        extra.size = 1
        tar.addfile(extra, io.BytesIO(b"x"))
    return stream.getvalue()


@pytest.mark.asyncio
async def test_archive_over_one_gateway_message_is_restored_in_parts(adapter, tmp_path):
    """Live 2026-10-05: a 2.6 MB Java workspace restore failed because the pinned gateway
    decodes at most 1 MiB per gRPC message. Parts stay under that bound, each is its own
    receipt, and the final extraction runs inside the sandbox from the staged file."""
    from infosec_harness.sandbox.transfer import _PART_BYTES

    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    member = tarfile.TarInfo("vendor.jar")
    member.size = 2 * _PART_BYTES + 1
    native.archive = archive(member)
    original = original_of(tmp_path, member)
    await boundary.copy_workspace(source, probe, operation_id="copy-activity",
                                  expected_source=original)
    parts = [r for r in native.execs if "open('ab')" in " ".join(r.command)]
    unpack = [r for r in native.execs if "extractall" in " ".join(r.command)]
    assert len(parts) == 3 and all(len(r.stdin) <= _PART_BYTES for r in parts)
    assert b"".join(r.stdin for r in parts) == native.archive
    assert len(unpack) == 1 and unpack[0].stdin == b"" and "unlink" in " ".join(unpack[0].command)
    assert all(r.sandbox == probe.name for r in parts + unpack)
    before = len(native.execs)
    await boundary.copy_workspace(source, probe, operation_id="copy-activity",
                                  expected_source=original)
    assert len(native.execs) == before  # every part and the extraction replay from receipts


@pytest.mark.asyncio
async def test_large_native_snapshot_enters_probe_without_host_extraction(adapter, tmp_path):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    member = tarfile.TarInfo("package.py")
    member.size = 524288
    native.archive = archive(member)
    original = original_of(tmp_path, member)
    await boundary.copy_workspace(source, probe, operation_id="copy-activity",
                                  expected_source=original)
    capture = [request for request in native.execs if request.command[0] == "/usr/bin/tar"]
    restore = [request for request in native.execs if "extractall" in " ".join(request.command)]
    assert len(capture) == 1 and len(restore) == 1
    assert restore[0].stdin == native.archive and restore[0].sandbox == probe.name
    await boundary.copy_workspace(source, probe, operation_id="copy-activity",
                                  expected_source=original)
    assert len(native.execs) == 2
    assert not (boundary.config.state_dir / "package.py").exists()


@pytest.mark.parametrize("name,kind", [("../host.py", tarfile.REGTYPE),
    ("/etc/secret", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), ("hard", tarfile.LNKTYPE),
    ("pipe", tarfile.FIFOTYPE)])
@pytest.mark.asyncio
async def test_hostile_archive_is_not_restored_or_extracted_on_host(adapter, tmp_path, name, kind):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    member = tarfile.TarInfo(name)
    member.type = kind
    member.linkname = "/etc/passwd" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
    native.archive = archive(member)
    original = original_of(tmp_path, member)
    with pytest.raises(UnsafeSnapshotMetadata, match="unsafe archive"):
        await boundary.copy_workspace(source, probe, operation_id="copy-activity",
                                  expected_source=original)
    assert len(native.execs) == 1


@pytest.mark.parametrize("content,include_original", [(b"changed", True), (b"", False)])
@pytest.mark.asyncio
async def test_changed_or_deleted_original_source_prevents_probe_restore(adapter, tmp_path, content, include_original):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    original = tmp_path / "original"
    original.mkdir()
    (original / "source.py").write_bytes(b"original")
    native.archive = source_archive(content, include_original=include_original)
    with pytest.raises(OpenShellError, match="changed or deleted"):
        await boundary.copy_workspace(source, probe, operation_id="copy", expected_source=original)
    assert len(native.execs) == 1
    assert not boundary.receipts("run")


@pytest.mark.asyncio
async def test_original_source_verification_provenance_is_bound_to_completed_probe_operations(adapter, tmp_path):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    original = tmp_path / "original"
    original.mkdir()
    (original / "source.py").write_bytes(b"original")
    native.archive = source_archive(b"original")
    digest = await boundary.copy_workspace(source, probe, operation_id="copy", expected_source=original)
    await boundary.execute(probe, "test source.py", operation_id="probe:first", timeout=3)
    assert not next(r for r in boundary.receipts("run") if r.operation_id == "probe:first").source_verified
    await boundary.verify_source(probe, original, operation_id="verify:first")
    receipt = next(r for r in boundary.receipts("run") if r.operation_id == "probe:first")
    assert receipt.workspace_digest == digest and receipt.source_verified
    await boundary.execute(probe, "change source.py", operation_id="probe:later", timeout=3)
    # Replaying a prior integrity check cannot certify commands executed later.
    await boundary.verify_source(probe, original, operation_id="verify:first")
    assert not next(r for r in boundary.receipts("run") if r.operation_id == "probe:later").source_verified
    native.archive = source_archive(b"changed")
    with pytest.raises(OpenShellError, match="changed or deleted"):
        await boundary.verify_source(probe, original, operation_id="verify:later")
    assert not next(r for r in boundary.receipts("run") if r.operation_id == "probe:later").source_verified


@pytest.mark.asyncio
async def test_changed_original_executable_bit_prevents_probe_restore(adapter, tmp_path):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    original = tmp_path / "original"
    original.mkdir()
    (original / "source.py").write_bytes(b"original")
    (original / "source.py").chmod(0o755)
    native.archive = source_archive(b"original", mode=0o644)
    with pytest.raises(OpenShellError, match="changed or deleted"):
        await boundary.copy_workspace(source, probe, operation_id="copy", expected_source=original)
    assert len(native.execs) == 1


def provider_ready_adapter(adapter, monkeypatch):
    boundary, native = adapter
    boundary.config = boundary.config.model_copy(update={"profiles": {
        **boundary.config.profiles,
        "model": boundary.config.profiles["model"].model_copy(update={"provider": "selfhosted"})}})
    provider = data.Provider(metadata=data.ObjectMeta(id="provider-id", name="selfhosted",
        workspace="default", resource_version=1), type="openai")
    monkeypatch.setattr(native, "ListSandboxProviders", lambda request, timeout:
        pb.ListSandboxProvidersResponse(providers=[provider]))
    calls = []

    def ready(request, timeout):
        calls.append(copy.deepcopy(request))
        desired = pb.ProviderDesiredIdentity(sandbox_id=native.resources[request.sandbox].metadata.id,
            sandbox=request.sandbox, provider_id="provider-id", provider_resource_version=1,
            attachment_epoch="epoch", provider_env_revision=7, config_revision=8, policy_hash="hash")
        receipt = pb.ProviderMutationReceipt(receipt_id="receipt", mutation_id="mutation",
            provider="selfhosted", workspace="default", kind=pb.PROVIDER_MUTATION_KIND_OBSERVE,
            desired=desired)
        receipt.persisted_time.seconds = 1
        status = pb.ProviderReadinessStatus(receipt=receipt, state=pb.PROVIDER_READINESS_STATE_READY,
            network_instance_id="network", observed=pb.ProviderReadinessObservation(
                session_id="session", process_instance_id="process", attachment_epoch="epoch",
                provider_env_revision=7, config_revision=8, policy_hash="hash",
                credentials_installed=True, policy_active=True, launch_environment_installed=True))
        return pb.GetSandboxProviderStatusResponse(status=status)

    monkeypatch.setattr(native, "GetSandboxProviderStatus", ready, raising=False)
    return boundary, native, ready, calls


@pytest.mark.asyncio
async def test_provider_pending_to_exact_ready_precedes_exec(adapter, monkeypatch):
    boundary, native, ready, calls = provider_ready_adapter(adapter, monkeypatch)

    def status(request, timeout):
        response = ready(request, timeout)
        if len(calls) == 1:
            response.status.state = pb.PROVIDER_READINESS_STATE_PENDING
            response.status.ClearField("observed")
        assert not native.execs and not native.observations
        return response

    monkeypatch.setattr(native, "GetSandboxProviderStatus", status)
    sandbox = await boundary.create("provider-run", profile="model")
    assert len(calls) == 2 and calls[0].receipt_id == "" and calls[1].receipt_id == "receipt"
    assert boundary._record("provider-readiness", sandbox.id).exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("defect", ["superseded", "stale", "empty", "wrong-owner", "malformed",
    "failed", "withheld", "revoked", "unknown"])
async def test_provider_readiness_fails_closed(adapter, monkeypatch, defect):
    boundary, native, ready, calls = provider_ready_adapter(adapter, monkeypatch)

    def status(request, timeout):
        response = ready(request, timeout)
        s = response.status
        if defect == "superseded":
            if len(calls) == 1:
                s.state = pb.PROVIDER_READINESS_STATE_PENDING
            else:
                s.receipt.desired.config_revision += 1
        elif defect == "stale":
            s.observed.provider_env_revision -= 1
        elif defect == "empty":
            s.observed.process_instance_id = ""
        elif defect == "wrong-owner":
            s.receipt.desired.sandbox_id = "other"
        elif defect == "malformed":
            s.receipt.persisted_time.nanos = 1000000000
        else:
            s.state = {"failed": pb.PROVIDER_READINESS_STATE_FAILED,
                "withheld": pb.PROVIDER_READINESS_STATE_WITHHELD,
                "revoked": pb.PROVIDER_READINESS_STATE_REVOKED, "unknown": 99}[defect]
        return response

    monkeypatch.setattr(native, "GetSandboxProviderStatus", status)
    with pytest.raises(OpenShellError, match="provider readiness"):
        await boundary.create("provider-run", profile="model")
    assert native.deleted and not native.execs and not native.observations


@pytest.mark.asyncio
async def test_provider_readiness_cancellation_cleans_owned_sandbox(adapter, monkeypatch):
    boundary, native, ready, calls = provider_ready_adapter(adapter, monkeypatch)

    def pending(request, timeout):
        response = ready(request, timeout)
        response.status.state = pb.PROVIDER_READINESS_STATE_PENDING
        return response

    monkeypatch.setattr(native, "GetSandboxProviderStatus", pending)
    task = asyncio.create_task(boundary.create("provider-cancel", profile="model"))
    while not calls:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert native.deleted and not native.execs


@pytest.mark.asyncio
async def test_provider_readiness_timeout_is_bounded_and_cleans_up(adapter, monkeypatch):
    boundary, native, ready, calls = provider_ready_adapter(adapter, monkeypatch)
    boundary.config = boundary.config.model_copy(update={"ready_timeout_seconds": 1})

    def pending(request, timeout):
        response = ready(request, timeout)
        response.status.state = pb.PROVIDER_READINESS_STATE_PENDING
        return response

    monkeypatch.setattr(native, "GetSandboxProviderStatus", pending)
    with pytest.raises(OpenShellError, match="provider readiness timed out"):
        await boundary.create("provider-timeout", profile="model")
    assert native.deleted and not native.execs


@pytest.mark.asyncio
async def test_provider_status_not_requested_for_unattached_workspace(adapter, monkeypatch):
    boundary, native = adapter

    def unexpected(request, timeout):
        pytest.fail("workspace admission must not query a provider")

    monkeypatch.setattr(native, "GetSandboxProviderStatus", unexpected, raising=False)
    await boundary.create("workspace")


@pytest.mark.asyncio
async def test_provider_readiness_rpc_error_discloses_only_status_code(adapter, monkeypatch):
    import grpc

    boundary, native, _, _ = provider_ready_adapter(adapter, monkeypatch)
    sentinel = "SECRET-provider-credential-sentinel"

    class Failure(grpc.RpcError):
        def code(self):
            return grpc.StatusCode.UNAVAILABLE

        def details(self):
            return sentinel

        def __str__(self):
            return sentinel

    def failure(request, timeout):
        raise Failure()

    monkeypatch.setattr(native, "GetSandboxProviderStatus", failure)
    with pytest.raises(OpenShellError) as caught:
        await boundary.create("provider-rpc-failure", profile="model")
    assert str(caught.value) == "native provider readiness RPC failed: UNAVAILABLE"
    assert sentinel not in str(caught.value) and caught.value.__suppress_context__
    assert native.deleted and not native.execs


@pytest.mark.asyncio
async def test_ordinary_nonzero_exit_is_a_completed_replayable_receipt(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    native.next_code = 2
    result = await boundary.execute(sandbox, "exit 2", operation_id="activity", timeout=3)
    assert result.exit_code == 2
    assert boundary.receipts("run")[0].result == result
    assert native.last_stream.cancelled
    assert native.deleted == []
    assert await boundary.execute(sandbox, "exit 2", operation_id="activity", timeout=3) == result
    assert len(native.execs) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["missing", "admission", "process", "restart", "container"])
async def test_qualification_reuse_requires_unchanged_lifecycle(adapter, monkeypatch, change):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    if change == "missing":
        boundary._record("qualification", sandbox.id).unlink()
    elif change == "admission":
        native.resources[sandbox.name].status.configuration_admission.config_revision += 1
    elif change == "process":
        native.resources[sandbox.name].status.main_process_instance_id = "replacement"
    else:
        original = boundary._inspection_call

        async def altered(args):
            value = await original(args)
            if args[0] == "inspect":
                containers = json.loads(value)
                if change == "restart":
                    containers[0]["State"]["StartedAt"] = "2026-10-05T01:00:00Z"
                else:
                    containers[1]["Id"] = "cc"
                return json.dumps(containers)
            return value

        monkeypatch.setattr(boundary, "_inspection_call", altered)
    with pytest.raises(OpenShellError, match="qualification|ownership"):
        await boundary.create("run")
    assert len(native.observations) == 1
    assert native.deleted == [sandbox.name]


@pytest.mark.asyncio
async def test_qualification_reuse_tolerates_routine_resource_version_bump(adapter):
    """Native status writes bump resource_version between audit and reuse (observed live,
    2026-10-05, 9 -> 10 after one exec); the lifecycle proof must not treat that as drift."""
    boundary, native = adapter
    sandbox = await boundary.create("run")
    native.resources[sandbox.name].metadata.resource_version += 1
    assert await boundary.create("run") == sandbox
    assert len(native.observations) == 1
    assert native.deleted == []


@pytest.mark.asyncio
async def test_qualification_reuse_tolerates_mount_order_but_not_mount_changes(adapter, monkeypatch):
    """docker inspect lists Mounts in varying order (observed live, 2026-10-05: the fence
    digest of one running sandbox flipped between two values). Order must not count as
    drift, while a changed mount still must."""
    boundary, native = adapter
    original = boundary._inspection_call
    mounts = [{"Type": "volume", "Destination": "/workspace"},
              {"Type": "volume", "Destination": "/tmp"}]
    calls = {"inspect": 0}

    async def reordered(args):
        raw = await original(args)
        if args[0] == "inspect":
            calls["inspect"] += 1
            values = json.loads(raw)
            values[0]["Mounts"] = mounts if calls["inspect"] % 2 else mounts[::-1]
            return json.dumps(values)
        return raw

    monkeypatch.setattr(boundary, "_inspection_call", reordered)
    sandbox = await boundary.create("run")
    assert await boundary.create("run") == sandbox
    assert len(native.observations) == 1
    mounts[1] = {"Type": "volume", "Destination": "/var/tmp"}
    with pytest.raises(OpenShellError, match="binding changed.*outer"):
        await boundary.create("run")
    assert native.deleted == [sandbox.name]


@pytest.mark.asyncio
async def test_qualification_reuse_survives_adapter_restart(adapter, monkeypatch):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    restarted = OpenShell(boundary.config)
    monkeypatch.setattr(restarted, "_inspection_call", boundary._inspection_call)
    assert await restarted.create("run") == sandbox
    assert len(native.observations) == 1


@pytest.mark.asyncio
async def test_reused_qualification_still_rejects_new_provider_attachment(adapter, monkeypatch):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    monkeypatch.setattr(native, "ListSandboxProviders", lambda request, timeout:
        pb.ListSandboxProvidersResponse(providers=[data.Provider(
            metadata=data.ObjectMeta(id="provider-id", name="unexpected", workspace="default",
                                     resource_version=1), type="openai")]))
    with pytest.raises(OpenShellError, match="provider attachment"):
        await boundary.create("run")
    assert len(native.observations) == 1 and native.deleted == [sandbox.name]


@pytest.mark.asyncio
async def test_incomplete_qualification_is_never_audited_again(adapter):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    path = boundary._record("qualification", sandbox.id)
    saved = json.loads(path.read_bytes())
    saved.pop("workload")
    boundary._save(path, saved)
    with pytest.raises(OpenShellError, match="incomplete"):
        await boundary.create("run")
    assert len(native.observations) == 1 and native.deleted == [sandbox.name]


def test_profile_limits_are_parsed_once_and_never_dumped(tmp_path):
    image = "sha256:" + "a" * 64
    profile = Profile(image=image, policy=tmp_path / "policy.yaml", cpu="1500m", memory="2Gi")
    assert (profile.cpu_cores, profile.memory_bytes) == (1.5, 2 * 1024**3)
    default = Profile(image=image, policy=tmp_path / "policy.yaml")
    assert (default.cpu_cores, default.memory_bytes) == (1, 512 * 1024**2)
    # model_dump is part of every saved lifecycle binding; derived limits must not appear.
    assert set(profile.model_dump()) == {"image", "policy", "cpu", "memory", "provider"}


def inspector(tmp_path, body: str) -> OpenShell:
    """An adapter whose dedicated inspector is a real local script named ``docker``."""
    import openshell

    script = tmp_path / "bin" / "docker"
    script.parent.mkdir(exist_ok=True)
    script.write_text("#!/bin/sh\n" + body + "\n")
    script.chmod(0o755)
    image = "sha256:" + "a" * 64
    profile = Profile(image=image, policy=tmp_path / "policy.yaml")
    config = OpenShellConfig(endpoint="127.0.0.1:7777", state_dir=tmp_path / "state",
        inspection_socket="unix:///dedicated/docker.sock",
        inspection_command=(str(script), "--host", "unix:///dedicated/docker.sock"),
        inspection_lima_home=tmp_path / "lima", supervisor_image=image,
        profiles={"workspace": profile})
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(openshell, "SandboxClient",
                      lambda *args, **kwargs: SimpleNamespace(_stub=None))
        return OpenShell(config)


@pytest.mark.asyncio
async def test_inspector_gets_exact_arguments_and_explicit_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("IH_AMBIENT_SECRET", "must-not-leak")
    boundary = inspector(tmp_path, 'printf "%s|%s|%s" "$LIMA_HOME" "${IH_AMBIENT_SECRET:-}" "$*"')
    output = await boundary._inspection_call(["ps", "-a", "-q"])
    assert output == f"{tmp_path / 'lima'}||--host unix:///dedicated/docker.sock ps -a -q"


@pytest.mark.asyncio
@pytest.mark.parametrize(("body", "message"), [
    ("echo partial; exit 1", "inspection unavailable"),
    ("head -c 2097153 /dev/zero | tr '\\0' x", "output bound"),
    ("printf '\\377'", "undecodable"),
])
async def test_inspector_failure_modes_fail_closed(tmp_path, body, message):
    with pytest.raises(OpenShellError, match=message):
        await inspector(tmp_path, body)._inspection_call(["inspect", "x"])


@pytest.mark.asyncio
async def test_inspector_timeout_kills_its_whole_process_group(tmp_path, monkeypatch):
    """A slow inspector (limactl, then ssh, then docker) fails closed and leaves no descendant."""
    import os

    import infosec_harness.sandbox.openshell as module

    monkeypatch.setattr(module, "_INSPECTION_TIMEOUT_S", 0.5)
    pidfile = tmp_path / "grandchild"
    boundary = inspector(tmp_path, f"sleep 30 & echo $! > {pidfile}; wait")
    with pytest.raises(OpenShellError, match="timed out"):
        await boundary._inspection_call(["ps"])
    grandchild = int(pidfile.read_text())
    for _ in range(50):
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.1)
    else:
        os.kill(grandchild, 9)
        pytest.fail("inspector descendant survived the timeout")
