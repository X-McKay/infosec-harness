"""Native protocol regression cases; fakes are not live isolation evidence."""

import asyncio
import copy
import io
import json
import tarfile
import threading
import uuid
from dataclasses import replace
from types import SimpleNamespace

import pytest
from google.protobuf.json_format import MessageToDict
from openshell._proto import datamodel_pb2 as data
from openshell._proto import openshell_pb2 as pb

from infosec_harness.openshell import (
    ExecutionUnknown,
    OpenShell,
    OpenShellConfig,
    OpenShellError,
    Profile,
    _path,
)


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
         "workspace_writable": True}


class Native:
    def __init__(self):
        self.resources = {}
        self.execs = []
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
            labels=request.labels), spec=request.spec,
            status=pb.SandboxStatus(phase=pb.SANDBOX_PHASE_READY, configuration_activated=True,
                configuration_admission=pb.SandboxConfigurationAdmission(
                    state=pb.CONFIGURATION_ADMISSION_STATE_ACCEPTED)))
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
        if "boundary-observation" not in request.request_id and "NoNewPrivs" not in request.command[-1]:
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
                       "read_write": ["/workspace", "/tmp"]},
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
                   "State": {"Running": True}, "Image": image,
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


@pytest.mark.asyncio
async def test_exec_unknown_is_fenced_across_worker_restart(adapter, monkeypatch):
    boundary, native = adapter
    sandbox = await boundary.create("run")
    native.next_code = None
    with pytest.raises(ExecutionUnknown, match="unknown"):
        await boundary.execute(sandbox, "touch file", operation_id="activity", timeout=3)
    assert len(native.execs) == 1 and native.deleted == [sandbox.name]
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
async def test_large_native_snapshot_enters_probe_without_host_extraction(adapter):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    member = tarfile.TarInfo("package.py")
    member.size = 524288
    native.archive = archive(member)
    await boundary.copy_workspace(source, probe, operation_id="copy-activity")
    capture = [request for request in native.execs if request.command[0] == "/usr/bin/tar"]
    restore = [request for request in native.execs if "extractall" in " ".join(request.command)]
    assert len(capture) == 1 and len(restore) == 1
    assert restore[0].stdin == native.archive and restore[0].sandbox == probe.name
    await boundary.copy_workspace(source, probe, operation_id="copy-activity")
    assert len(native.execs) == 2
    assert not (boundary.config.state_dir / "package.py").exists()


@pytest.mark.parametrize("name,kind", [("../host.py", tarfile.REGTYPE),
    ("/etc/secret", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), ("hard", tarfile.LNKTYPE),
    ("pipe", tarfile.FIFOTYPE)])
@pytest.mark.asyncio
async def test_hostile_archive_is_not_restored_or_extracted_on_host(adapter, name, kind):
    boundary, native = adapter
    source = await boundary.create("run")
    probe = await boundary.create("run", profile="probe", slot="activity")
    member = tarfile.TarInfo(name)
    member.type = kind
    member.linkname = "/etc/passwd" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
    native.archive = archive(member)
    with pytest.raises(OpenShellError, match="unsafe archive"):
        await boundary.copy_workspace(source, probe, operation_id="copy-activity")
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
