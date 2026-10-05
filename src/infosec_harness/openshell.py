"""Pinned OpenShell workload boundary, with conservative durable exec recovery.

Only the trusted worker constructs profiles. Repository code runs in workspace/probe
sandboxes; the model sandbox is separate and is the only profile allowed a provider.
OpenShell's generated gRPC bindings are used for exec because the SDK convenience
iterator retains an unbounded copy of stdout and stderr.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import ipaddress
import json
import os
import tarfile
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Literal

import yaml
from google.protobuf.json_format import MessageToDict
from pydantic import BaseModel, ConfigDict, Field, model_validator

from infosec_harness._io import atomic_write_bytes

ProfileName = Literal["workspace", "probe", "model"]
_OWNER = "infosec-harness.v3"
_PYTHON = "/usr/local/bin/python"


class OpenShellError(RuntimeError):
    """A boundary could not be established or observed."""


class UnsafeSnapshotMetadata(OpenShellError):
    """A captured archive failed metadata admission; execution outcome is separate."""


class ExecutionUnknown(OpenShellError):
    """Dispatch may have happened. Never automatically resend this operation."""


def native_operation_accounting(state_dir: Path, run_id: str) -> dict:
    """Project trusted durable receipts without contacting native services.

    An intent can precede dispatch. Unknown counts therefore include possible,
    not proven, native operations. These records do not expose native ledger
    occupancy, retention, read RPCs or cleanup operations.
    """
    if not state_dir.is_dir():
        raise OpenShellError("native receipt directory is unavailable")
    categories = {}
    for folder, category in (("sandboxes", "create"), ("qualification", "admission_exec"),
                             ("operations", "exec"), ("transfers", "workspace_capture")):
        completed = unknown = 0
        for path in (state_dir / folder).glob("*.json"):
            saved = json.loads(path.read_bytes())
            sandbox = saved.get("sandbox", saved.get("source", saved.get("binding", {}).get("sandbox", {})))
            if sandbox.get("run_id") != run_id:
                continue
            acknowledged = {
                "sandboxes": bool(sandbox.get("id")),
                "qualification": "workload" in saved,
                "operations": "result" in saved,
                "transfers": "sha256" in saved,
            }[folder]
            completed += acknowledged
            unknown += not acknowledged
        categories[category] = {"completed": completed, "unknown": unknown}
    return {
        "status": "observed" if any(sum(row.values()) for row in categories.values()) else "not_checked",
        "source": "trusted local durable native-boundary receipts",
        "categories": categories,
        "total": {key: sum(row[key] for row in categories.values())
                  for key in ("completed", "unknown")},
        "native_ledger_occupancy": "not_checked",
        "limitations": ["Unknown intents may not have reached native dispatch.",
                        "Absent local receipts do not prove zero operations or visibility of a remote worker.",
                        "Read RPCs, cleanup, native ledger retention and occupancy are not counted.",
                        "Transfers count capture execs; restore/upload/download execs appear under exec.",
                        "Legacy qualification receipts can overwrite repeated audits; those counts are lower bounds."],
    }


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    image: str = Field(pattern=r"^(?:[^\s]+@)?sha256:[0-9a-f]{64}$")
    policy: Path
    cpu: str = Field(default="1", pattern=r"^[1-9][0-9]*(?:m)?$")
    memory: str = Field(default="512Mi", pattern=r"^[1-9][0-9]*(?:Mi|Gi)$")
    provider: str | None = None

    # Plain properties, never computed fields: model_dump is part of every saved
    # lifecycle binding, so a dumped field would invalidate existing proofs.
    @property
    def memory_bytes(self) -> int:
        return int(self.memory[:-2]) * 1024 ** (2 if self.memory.endswith("Mi") else 3)

    @property
    def cpu_cores(self) -> float:
        return int(self.cpu[:-1]) / 1000 if self.cpu.endswith("m") else int(self.cpu)


class OpenShellConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    endpoint: str
    workspace: str = "default"
    state_dir: Path
    tls_ca: Path | None = None
    tls_cert: Path | None = None
    tls_key: Path | None = None
    inspection_socket: str
    inspection_command: tuple[str, ...]
    inspection_lima_home: Path | None = None
    supervisor_image: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    profiles: dict[ProfileName, Profile]
    max_output_bytes: int = Field(default=262144, ge=1024, le=1048576)
    max_transfer_bytes: int = Field(default=16777216, ge=1024, le=67108864)
    max_timeout_seconds: int = Field(default=300, ge=1, le=3600)
    ready_timeout_seconds: int = Field(default=120, ge=1, le=600)

    @model_validator(mode="after")
    def validate_boundary(self) -> OpenShellConfig:
        if not self.endpoint or not self.workspace or not self.state_dir.is_absolute():
            raise ValueError("endpoint, workspace and absolute state_dir are required")
        if (self.tls_cert is None) != (self.tls_key is None):
            raise ValueError("TLS client certificate and key must be paired")
        if self.tls_ca is None:
            host, _, port = self.endpoint.rpartition(":")
            try:
                local = ipaddress.ip_address(host.strip("[]")).is_loopback
            except ValueError:
                local = host == "localhost"
            if not local or not port.isdigit():
                raise ValueError("plaintext gateway must use an explicit loopback endpoint")
        if (not self.inspection_socket.startswith("unix:///")
                or self.inspection_socket in ("unix:///var/run/docker.sock", "unix:///run/docker.sock")
                or len(self.inspection_command) < 3
                or self.inspection_command[-2:] != ("--host", self.inspection_socket)
                or Path(self.inspection_command[-3]).name != "docker"):
            raise ValueError("read-only inspection requires an explicit dedicated Docker socket")
        for name, profile in self.profiles.items():
            if not profile.policy.is_absolute():
                raise ValueError("policy paths must be absolute")
            if name != "model" and profile.provider:
                raise ValueError("repository and probe workloads must not have providers")
        return self

    @classmethod
    def load(cls, path: Path) -> OpenShellConfig:
        return cls.model_validate_json(path.read_bytes())


@dataclass(frozen=True)
class Sandbox:
    id: str
    run_id: str
    name: str
    profile: ProfileName
    slot: str = ""


@dataclass(frozen=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str
    output_truncated: bool = False


@dataclass(frozen=True)
class ExecutionReceipt:
    sandbox: Sandbox
    operation_id: str
    request_digest: str
    command: list[str]
    result: CommandResult
    workspace_digest: str | None = None
    source_verified: bool = False


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _sha256(stream: Any) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(65536):
        digest.update(chunk)
    return digest.hexdigest()


def _request_id(key: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "infosec-harness:" + key))


def _directory(path: Path) -> None:
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for child in reversed(missing):
        child.mkdir(exist_ok=True, mode=0o700)
        descriptor = os.open(child.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _path(path: str) -> str:
    value = PurePosixPath(path)
    if not value.is_absolute() or ".." in value.parts or str(value) != path:
        raise OpenShellError("sandbox path must be canonical and absolute")
    if value != PurePosixPath("/workspace") and PurePosixPath("/workspace") not in value.parents:
        raise OpenShellError("repository tools are confined to /workspace")
    return path


# Runs before any repository upload, through the same native exec endpoint. A named
# driver, ready status, or configured policy alone is insufficient execution evidence.
_PROBE = """
import errno,json,os,socket,pathlib,stat
s=dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l)
null_sink=False;null_major=None;null_minor=None
try:
 fd=os.open('/dev/null',os.O_WRONLY|os.O_NOFOLLOW)
 info=os.fstat(fd)
 null_major=os.major(info.st_rdev);null_minor=os.minor(info.st_rdev)
 valid=stat.S_ISCHR(info.st_mode) and null_major==1 and null_minor==3
 written=os.write(fd,b'ih-null-sink') if valid else 0;os.close(fd)
 fd=os.open('/dev/null',os.O_RDONLY|os.O_NOFOLLOW)
 null_sink=valid and written==12 and os.read(fd,1)==b'';os.close(fd)
except OSError: pass
workspace=False
control=pathlib.Path('/workspace')/('.ih-control-'+str(os.getpid()))
try:
 with control.open('x') as f: f.write('workspace-control')
 workspace=control.read_text()=='workspace-control'; control.unlink()
except OSError: pass
blocked=False
try:
 f=os.open('/etc/ih-boundary-deny',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 os.close(f);os.unlink('/etc/ih-boundary-deny')
except OSError as e: blocked=e.errno in (errno.EACCES,errno.EPERM,errno.EROFS)
shared_mode=0; shared_denied=False; escape_denied=False
target=pathlib.Path('/dev/shm')/('ih-boundary-deny-'+str(os.getpid()))
link=pathlib.Path('/workspace')/('ih-boundary-link-'+str(os.getpid()))
def denied(path,follow=False):
 try:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|(0 if follow else os.O_EXCL),0o600)
  os.close(fd);os.unlink(target if follow else path);return False
 except OSError as e: return e.errno in (errno.EACCES,errno.EPERM)
try:
 info=os.stat('/dev/shm')
 if stat.S_ISDIR(info.st_mode): shared_mode=stat.S_IMODE(info.st_mode)
 if shared_mode==0o1777:
  shared_denied=denied(target)
  os.symlink(target,link);escape_denied=denied(link,True);link.unlink()
except OSError: pass
n=False
sock=socket.socket();sock.settimeout(2)
try: sock.connect(('1.1.1.1',443))
except OSError as e: n=e.errno in (errno.EACCES,errno.EPERM,errno.ENETUNREACH)
finally: sock.close()
def read(p): return pathlib.Path(p).read_text().strip()
print(json.dumps({'uid':os.getuid(),'nnp':s['NoNewPrivs'].strip(),
 'seccomp':s['Seccomp'].strip(),'caps':int(s['CapEff'],16),
 'filesystem_denied':blocked,'network_denied':n,
 'shared_tmp_mode':shared_mode,'shared_tmp_denied':shared_denied,
 'null_sink_verified':null_sink,
 'null_device_major':null_major,'null_device_minor':null_minor,
 'symlink_escape_denied':escape_denied,
 'workspace_writable':workspace,
 'memory':read('/sys/fs/cgroup/memory.max'),'cpu':read('/sys/fs/cgroup/cpu.max'),
 'sockets_absent':not any(os.path.exists(p) for p in ('/var/run/docker.sock','/run/docker.sock','/run/containerd/containerd.sock')),
 'credentials_absent':not any(k.startswith(('HARNESS_','TEMPORAL_','AWS_')) or k == 'DATABASE_URL' for k in os.environ)}))
"""


class OpenShell:
    def __init__(self, config: OpenShellConfig) -> None:
        from importlib.metadata import version

        from openshell import SandboxClient, TlsConfig
        from openshell._proto import datamodel_pb2, openshell_pb2, sandbox_pb2

        if version("openshell") != "0.1.2":
            raise OpenShellError("OpenShell SDK version must be exactly 0.1.2")
        self.config = config
        self._pb = openshell_pb2
        self._policy_pb = sandbox_pb2
        self._scope = datamodel_pb2.WorkspaceSelector(workspace=config.workspace)
        tls = None
        if config.tls_ca is not None:
            tls = TlsConfig(ca_path=config.tls_ca, cert_path=config.tls_cert, key_path=config.tls_key)
        self._client = SandboxClient(config.endpoint, tls=tls, timeout=30)
        # Pinned generated binding, not the SDK's output-accumulating exec helper.
        self._stub = self._client._stub
        _directory(config.state_dir)
        self._locks: dict[str, asyncio.Lock] = {}

    def _record(self, kind: str, key: str) -> Path:
        folder = self.config.state_dir / kind
        _directory(folder)
        return folder / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    @staticmethod
    def _save(path: Path, value: Any, *, exclusive: bool = False) -> None:
        atomic_write_bytes(path, json.dumps(value, sort_keys=True).encode(),
                           exclusive=exclusive, sync_directory=True)

    def _spec(self, profile: ProfileName):
        from google.protobuf.json_format import ParseDict

        config = self.config.profiles.get(profile)
        if config is None:
            raise OpenShellError(f"profile {profile} is not configured")
        authored = yaml.safe_load(config.policy.read_bytes())
        # The CLI's YAML aliases differ from protobuf JSON enum names. Resolve
        # only the pinned declared enum values; unknown values fail validation.
        for rule in authored.get("network_policies", {}).values():
            for endpoint in rule.get("endpoints", []):
                for field, prefix in (("tls", "NETWORK_TLS_MODE_"),
                                      ("enforcement", "NETWORK_ENFORCEMENT_MODE_"),
                                      ("access", "NETWORK_ACCESS_PRESET_")):
                    value = endpoint.get(field)
                    if isinstance(value, str) and not value.startswith(prefix):
                        endpoint[field] = prefix + value.upper()
        policy = ParseDict(authored, self._policy_pb.SandboxPolicy())
        if (policy.landlock.compatibility != "hard_requirement"
                or policy.process.run_as_user != "65532"
                or policy.process.run_as_group != "65532"
                or policy.filesystem.include_workdir
                or set(policy.filesystem.read_write) != {"/workspace", "/tmp", "/dev/null"}
                or (profile != "workspace" and policy.network_policies)):
            raise OpenShellError("profile must require Landlock, nonroot, confined writes and deny egress")
        for rule in policy.network_policies.values():
            for endpoint in rule.endpoints:
                if (not endpoint.host or "*" in endpoint.host
                        or endpoint.protocol != "rest"
                        or endpoint.enforcement != self._policy_pb.NETWORK_ENFORCEMENT_MODE_ENFORCE
                        or endpoint.tls != self._policy_pb.NETWORK_TLS_MODE_UNSPECIFIED
                        or not endpoint.rules
                        or endpoint.access != self._policy_pb.NETWORK_ACCESS_PRESET_UNSPECIFIED
                        or any(r.allow.method not in ("GET", "HEAD") for r in endpoint.rules)):
                    raise OpenShellError("package egress must use exact hosts and enforced read-only REST")
        spec = self._pb.SandboxSpec(
            template=self._pb.SandboxTemplate(image=config.image,
                resources={"limits": {"cpu": config.cpu, "memory": config.memory}}),
            policy=policy, providers=[config.provider] if config.provider else [],
            command=[_PYTHON, "-c", "import time; time.sleep(2147483647)"], tty=False,
        )
        return spec

    async def _get(self, name: str):
        return await asyncio.to_thread(self._stub.GetSandbox,
            self._pb.GetSandboxRequest(workspace_scope=self._scope, name=name), timeout=30)

    async def _corroborate(self, sandbox: Sandbox, mismatch: str) -> None:
        """Recheck the exact native id and the outer fence immediately before dispatch."""
        if (await self._get(sandbox.name)).sandbox.metadata.id != sandbox.id:
            raise OpenShellError(mismatch)
        await self._inspect(sandbox)

    def _key(self, sandbox: Sandbox) -> str:
        return _digest([self.config.workspace, sandbox.run_id, sandbox.profile, sandbox.slot])

    def _fenced(self, run_id: str) -> bool:
        return self._record("closed-runs", run_id).exists()

    async def create(self, run_id: str, *, profile: ProfileName = "workspace", slot: str = "") -> Sandbox:
        if not run_id or len(run_id) > 512 or len(slot) > 1024:
            raise OpenShellError("invalid run id")
        if self._fenced(run_id):
            raise OpenShellError("investigation has been closed")
        key = _digest([self.config.workspace, run_id, profile, slot])
        name = "ih-" + hashlib.sha256(key.encode()).hexdigest()[:16]
        path = self._record("sandboxes", key)
        labels = {"ih.owner": _OWNER, "ih.run": hashlib.sha256(run_id.encode()).hexdigest()[:32],
                  "ih.profile": profile}
        async with self._locks.setdefault(key, asyncio.Lock()):
            initial = not path.exists()
            try:
                spec = self._spec(profile)
            except BaseException:
                if not initial:
                    saved = json.loads(path.read_bytes())
                    if not saved.get("closed"):
                        await asyncio.shield(self.close(Sandbox(**saved["sandbox"])))
                raise
            if path.exists():
                saved = json.loads(path.read_bytes())
                if saved.get("closed"):
                    raise OpenShellError("closed investigation cannot acquire a new sandbox")
                sandbox = Sandbox(**saved["sandbox"])
                if not sandbox.id:
                    # A prior create may have crossed the native boundary. Only
                    # corroborate by exact owned identity; never resend blindly.
                    current = (await self._get(name)).sandbox
                    if dict(current.metadata.labels) != labels or not current.metadata.id:
                        raise OpenShellError("pending create cannot be reconciled")
                    sandbox = Sandbox(current.metadata.id, run_id, name, profile, slot)
                    self._save(path, {"sandbox": asdict(sandbox), "closed": False})
            else:
                sandbox = Sandbox("", run_id, name, profile, slot)
                self._save(path, {"sandbox": asdict(sandbox), "closed": False}, exclusive=True)

                async def provision() -> Sandbox:
                    response = await asyncio.to_thread(self._stub.CreateSandbox,
                        self._pb.CreateSandboxRequest(workspace_scope=self._scope, spec=spec,
                            name=name, labels=labels, request_id=_request_id(key)),
                        timeout=self.config.ready_timeout_seconds)
                    owned = Sandbox(response.sandbox.metadata.id, run_id, name, profile, slot)
                    if not owned.id or dict(response.sandbox.metadata.labels) != labels:
                        raise OpenShellError("native create returned an invalid identity")
                    self._save(path, {"sandbox": asdict(owned), "closed": False})
                    if self._fenced(run_id):
                        await self.close(owned)
                        raise OpenShellError("investigation closed during native create")
                    return owned

                task = asyncio.create_task(provision())
                try:
                    sandbox = await asyncio.shield(task)
                except asyncio.CancelledError:
                    # Shield preserves the exact ownership record even when a
                    # Temporal cancellation interrupts the waiting activity.
                    await asyncio.shield(self.close(await task))
                    raise
            try:
                if self._fenced(run_id):
                    raise OpenShellError("investigation closed during native create")
                await asyncio.to_thread(self._client.wait_ready, name, workspace=self.config.workspace,
                                        timeout_seconds=self.config.ready_timeout_seconds)
                await self._verify(sandbox, spec, labels, initial=initial)
                if self._fenced(run_id):
                    raise OpenShellError("investigation closed during qualification")
            except BaseException:
                await asyncio.shield(self.close(sandbox))
                raise
            return sandbox

    async def _verify(self, sandbox: Sandbox, spec: Any, labels: dict[str, str],
                      *, initial: bool = False) -> None:
        observed = (await self._get(sandbox.name)).sandbox
        admission = observed.status.configuration_admission
        if (observed.metadata.id != sandbox.id or observed.metadata.resource_version <= 0
                or not admission.instance_id or admission.config_revision <= 0
                or not admission.policy_hash or not observed.status.main_process_instance_id
                or dict(observed.metadata.labels) != labels
                or observed.status.phase != self._pb.SANDBOX_PHASE_READY
                or admission.state != self._pb.CONFIGURATION_ADMISSION_STATE_ACCEPTED
                or not observed.status.configuration_activated
                or observed.spec.template.image != spec.template.image
                or observed.spec.policy != spec.policy
                or list(observed.spec.providers) != list(spec.providers)
                or observed.spec.template.resources != spec.template.resources):
            raise OpenShellError("native sandbox identity, policy or admission mismatch")
        attached = await asyncio.to_thread(self._stub.ListSandboxProviders,
            self._pb.ListSandboxProvidersRequest(workspace_scope=self._scope, sandbox=sandbox.name),
            timeout=30)
        providers = list(attached.providers)
        expected_provider = self.config.profiles[sandbox.profile].provider
        if (attached.next_page_token or len(providers) != (1 if expected_provider else 0)
                or any(not p.metadata.id or p.metadata.name != expected_provider
                       or p.metadata.workspace != self.config.workspace
                       or p.metadata.resource_version <= 0 or not p.type for p in providers)):
            raise OpenShellError("native credential provider attachment was not established")
        if expected_provider:
            await self._wait_provider_ready(sandbox, providers[0])
        outer = await self._inspect(sandbox)
        # Native status writes bump metadata.resource_version during routine activity
        # (observed 2026-10-05: 9 -> 10 after one exec), so it cannot bind the lifecycle.
        # Spec, admission revisions, policy hash, process instance and container identities
        # still change whenever the workload or its policy does.
        metadata = MessageToDict(observed.metadata, preserving_proto_field_name=True)
        metadata.pop("resource_version", None)
        binding = {
            "sandbox": asdict(sandbox),
            "config": self.config.model_dump(mode="json"),
            "tls": {key: hashlib.sha256(value.read_bytes()).hexdigest()
                    for key, value in (("ca", self.config.tls_ca), ("cert", self.config.tls_cert),
                                       ("key", self.config.tls_key)) if value is not None},
            "metadata": metadata,
            "spec": MessageToDict(observed.spec, preserving_proto_field_name=True),
            "admission": MessageToDict(admission, preserving_proto_field_name=True),
            "process_instance": observed.status.main_process_instance_id,
            "policy_version": observed.status.current_policy_version,
            "providers": [MessageToDict(p, preserving_proto_field_name=True) for p in providers],
            "outer": outer,
        }
        path = self._record("qualification", sandbox.id)
        if not initial:
            if not path.exists():
                raise OpenShellError("sandbox qualification proof is missing")
            saved = json.loads(path.read_bytes())
            if saved.get("binding") != binding or not saved.get("workload"):
                raise OpenShellError("sandbox qualification binding changed or is incomplete")
            return
        # Write intent before dispatch: a restart cannot blindly repeat an audit
        # whose native receipt does not retain its output stream.
        request_id = str(uuid.uuid4())
        self._save(path, {"binding": binding, "request_id": request_id}, exclusive=True)
        result = await asyncio.to_thread(self._stream, sandbox, [_PYTHON, "-I", "-c", _PROBE], 10, None,
                                        request_id,
                                        self.config.max_output_bytes)
        try:
            proof = json.loads(result[0].stdout)
        except (ValueError, TypeError):
            raise OpenShellError("confinement probe returned invalid evidence") from None
        config = self.config.profiles[sandbox.profile]
        try:
            quota, period = (int(v) for v in proof["cpu"].split())
            valid = (proof["uid"] == 65532 and proof["nnp"] == "1" and proof["seccomp"] == "2"
                     and proof["caps"] == 0 and proof["shared_tmp_mode"] == 0o1777
                     and type(proof["null_device_major"]) is int and proof["null_device_major"] == 1
                     and type(proof["null_device_minor"]) is int and proof["null_device_minor"] == 3
                     and all(proof[k] is True for k in ("filesystem_denied", "shared_tmp_denied",
                         "symlink_escape_denied", "workspace_writable", "network_denied",
                         "sockets_absent", "credentials_absent", "null_sink_verified"))
                     and 0 < int(proof["memory"]) <= config.memory_bytes
                     and 0 < quota / period <= config.cpu_cores)
        except (ValueError, KeyError, TypeError, AttributeError, ZeroDivisionError):
            valid = False
        if result[0].exit_code != 0 or result[0].output_truncated or not valid:
            raise OpenShellError("actual workload confinement was not established")
        self._save(path,
            {"binding": binding, "request_id": request_id,
             "sandbox": asdict(sandbox), "outer": outer, "workload": proof,
             "landlock_compatibility": observed.spec.policy.landlock.compatibility})

    async def _wait_provider_ready(self, sandbox: Sandbox, provider: Any) -> None:
        """Wait for the pinned native provider receipt's installation evidence.

        Mirrors OpenShell SDK provider_readiness validation; saved attachment
        intent and a ready sandbox phase do not prove credential installation.
        Only read-only status RPCs may repeat. No inference or exec is retried.
        """
        import grpc

        pb = self._pb
        request = pb.GetSandboxProviderStatusRequest(workspace_scope=self._scope,
            sandbox=sandbox.name, provider=provider.metadata.name)
        frozen = None
        status = None
        try:
            async with asyncio.timeout(self.config.ready_timeout_seconds):
                while True:
                    response = await asyncio.to_thread(self._stub.GetSandboxProviderStatus, request,
                        timeout=self.config.ready_timeout_seconds)
                    status = response.status
                    receipt = status.receipt
                    desired = receipt.desired
                    def valid_time(t: Any) -> bool:
                        return (-62135596800 <= t.seconds <= 253402300799
                                and 0 <= t.nanos <= 999999999)
                    if (not status.HasField("receipt") or not receipt.HasField("desired")
                            or not receipt.HasField("persisted_time")
                            or not valid_time(receipt.persisted_time)
                            or any(status.HasField(field) and not valid_time(getattr(status, field))
                                   for field in ("observed_time", "evaluated_time"))
                            or not receipt.receipt_id or not receipt.mutation_id
                            or receipt.workspace != self.config.workspace
                            or receipt.provider != provider.metadata.name
                            or desired.sandbox_id != sandbox.id or desired.sandbox != sandbox.name
                            or desired.provider_id != provider.metadata.id
                            or desired.provider_resource_version != provider.metadata.resource_version
                            or receipt.kind not in (pb.PROVIDER_MUTATION_KIND_ATTACH,
                                pb.PROVIDER_MUTATION_KIND_UPDATE, pb.PROVIDER_MUTATION_KIND_OBSERVE)
                            or status.state not in pb.ProviderReadinessState.values()
                            or status.state == pb.PROVIDER_READINESS_STATE_UNSPECIFIED
                            or status.reason not in pb.ProviderReadinessReason.values()):
                        raise OpenShellError("native provider readiness receipt is invalid")
                    identity = receipt.SerializeToString(deterministic=True)
                    if frozen is None:
                        frozen = identity
                        request.receipt_id = receipt.receipt_id
                    elif frozen != identity:
                        raise OpenShellError("native provider readiness receipt was superseded")
                    if status.state == pb.PROVIDER_READINESS_STATE_READY:
                        observed = status.observed
                        if (not status.HasField("observed") or not desired.policy_hash
                                or not status.network_instance_id or not observed.session_id
                                or not observed.process_instance_id or not observed.credentials_installed
                                or not observed.policy_active or not observed.launch_environment_installed
                                or observed.reason != pb.PROVIDER_READINESS_REASON_UNSPECIFIED
                                or status.reason != pb.PROVIDER_READINESS_REASON_UNSPECIFIED
                                or observed.attachment_epoch != desired.attachment_epoch
                                or observed.provider_env_revision != desired.provider_env_revision
                                or observed.config_revision != desired.config_revision
                                or observed.policy_hash != desired.policy_hash):
                            raise OpenShellError("native provider readiness lacks installation evidence")
                        self._save(self._record("provider-readiness", sandbox.id),
                            {"sandbox": asdict(sandbox), "status": MessageToDict(
                                status, preserving_proto_field_name=True)})
                        return
                    if status.state not in (pb.PROVIDER_READINESS_STATE_PENDING,
                                           pb.PROVIDER_READINESS_STATE_PERSISTED):
                        raise OpenShellError("native provider readiness failed or was superseded: "
                            f"{pb.ProviderReadinessState.Name(status.state)} "
                            f"{pb.ProviderReadinessReason.Name(status.reason)}")
                    await asyncio.sleep(0.25)
        except grpc.RpcError as error:
            raise OpenShellError("native provider readiness RPC failed: "
                                 + error.code().name) from None
        except TimeoutError:
            reason = (pb.ProviderReadinessReason.Name(status.reason) if status is not None
                      else "no native observation")
            raise OpenShellError(f"native provider readiness timed out: {reason}") from None

    def _owned(self, sandbox: Sandbox) -> None:
        key = self._key(sandbox)
        path = self._record("sandboxes", key)
        if not path.exists() or json.loads(path.read_bytes()) != {"sandbox": asdict(sandbox), "closed": False}:
            raise OpenShellError("sandbox is not owned by this active investigation")
        if self._fenced(sandbox.run_id):
            raise OpenShellError("investigation has been closed")

    async def _inspection_call(self, args: list[str]) -> str:
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home())}
        if self.config.inspection_lima_home:
            env["LIMA_HOME"] = str(self.config.inspection_lima_home)
        process = await asyncio.create_subprocess_exec(*self.config.inspection_command, *args,
            env=env, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        assert process.stdout is not None
        data = bytearray()
        try:
            async with asyncio.timeout(20):
                while chunk := await process.stdout.read(65536):
                    data.extend(chunk)
                    if len(data) > 2097152:
                        raise OpenShellError("container inspection exceeded its output bound")
                if await process.wait() != 0:
                    raise OpenShellError("dedicated container inspection unavailable")
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
        return data.decode()

    async def _inspect(self, sandbox: Sandbox, *, deleted: bool = False) -> dict[str, Any] | None:
        ids = (await self._inspection_call(["ps", "-a", "-q", "--no-trunc", "--filter",
               f"label=openshell.ai/sandbox-id={sandbox.id}"])).split()
        if deleted:
            if ids:
                raise OpenShellError("native deletion left workload resources behind")
            return
        if len(ids) != 2 or any(not all(c in "0123456789abcdef" for c in i) for i in ids):
            raise OpenShellError("exact native workload and supervisor were not observed")
        try:
            containers = json.loads(await self._inspection_call(["inspect", *ids]))
            by_role = {v["Config"]["Labels"]["openshell.ai/isolation-role"]: v for v in containers}
            if (set(by_role) != {"sandbox", "supervisor"} or len(containers) != 2
                    or {v["Id"] for v in containers} != set(ids)):
                raise OpenShellError("ambiguous native workload ownership")
            workload = by_role["sandbox"]
            host = workload["HostConfig"]
            config = self.config.profiles[sandbox.profile]
            observed_cpu = (host.get("NanoCpus", 0) / 1e9 or
                            host.get("CpuQuota", 0) / (host.get("CpuPeriod", 0) or 100000))
            valid = (all(v["Config"]["Labels"].get("openshell.ai/sandbox-id") == sandbox.id
                         and v["State"]["Running"]
                         and v["Id"] and v["State"]["StartedAt"]
                         and not v["State"]["StartedAt"].startswith("0001-") for v in containers)
                and workload["Image"] == config.image.split("@")[-1]
                and by_role["supervisor"]["Image"] == self.config.supervisor_image
                and host["Runtime"] == "runc" and host["NetworkMode"] == "none"
                and not host["Privileged"] and workload["Config"]["User"] == "65532:65532"
                and "ALL" in host.get("CapDrop", []) and not host.get("CapAdd")
                and "no-new-privileges:true" in host.get("SecurityOpt", [])
                and not host.get("Devices") and not host.get("DeviceRequests")
                and host.get("PidMode", "") != "host" and host.get("IpcMode", "") != "host"
                and 0 < host.get("PidsLimit", 0) <= 1024
                and 0 < host.get("Memory", 0) <= config.memory_bytes
                and 0 < observed_cpu <= config.cpu_cores
                and all(m["Type"] == "volume" and "docker.sock" not in m["Destination"]
                        for m in workload.get("Mounts", [])))
            if not valid:
                raise OpenShellError("observed outer workload fence failed")
            return {"containers": {role: {"id": v["Id"], "started_at": v["State"]["StartedAt"]}
                                   for role, v in by_role.items()},
                    "fence_digest": _digest({role: {key: v[key]
                        for key in ("Id", "Config", "HostConfig", "Mounts", "Image")}
                        for role, v in by_role.items()}),
                    "rootfs_readonly": bool(host.get("ReadonlyRootfs")),
                    "pids_limit": host["PidsLimit"], "image": workload["Image"],
                    "network_mode": host["NetworkMode"], "runtime": host["Runtime"]}
        except (ValueError, KeyError, TypeError, AttributeError, ZeroDivisionError):
            raise OpenShellError("container inspection was incomplete") from None

    def _stream(self, sandbox: Sandbox, command: Sequence[str], timeout: int,
                stdin: bytes | None, request_id: str, limit: int, binary: bool = False) -> tuple[CommandResult, bytes]:
        # Pinned native RPC selectors are names, not immutable IDs. The trusted
        # worker corroborates exact ID/ownership before every dispatch.
        request = self._pb.ExecSandboxRequest(workspace_scope=self._scope, sandbox=sandbox.name,
            command=list(command), workdir="/workspace", stdin=stdin or b"",
            no_login_shell=True, request_id=request_id)
        request.execution_timeout.seconds = timeout
        stream = self._stub.ExecSandbox(request, timeout=timeout + 10)
        stdout, stderr = bytearray(), bytearray()
        code = None
        truncated = False
        try:
            for event in stream:
                payload = event.WhichOneof("payload")
                if payload in ("stdout", "stderr"):
                    target = stdout if payload == "stdout" else stderr
                    chunk = getattr(event, payload).data
                    available = limit - len(stdout) - len(stderr)
                    target.extend(chunk[:available])
                    if len(chunk) > available:
                        truncated = True
                        # Cancel the native RPC on overflow; the caller closes the
                        # workload rather than assuming cancellation killed the process.
                        stream.cancel()
                        raise ExecutionUnknown("command output exceeded the boundary limit")
                elif payload == "exit":
                    code = int(event.exit.exit_code)
            if code is None:
                raise ExecutionUnknown("native exec ended without an exit receipt")
            if code == 124:
                # Pinned OpenShell also synthesizes 124 on timeout without native
                # terminal finalization. An explicit process exit 124 is ambiguous.
                raise ExecutionUnknown("native exit 124 cannot establish terminal execution")
            return CommandResult(code, "" if binary else stdout.decode(errors="replace"), stderr.decode(errors="replace"),
                                 truncated), bytes(stdout)
        finally:
            stream.cancel()

    async def execute(self, sandbox: Sandbox, command: Sequence[str] | str, *,
                      operation_id: str, timeout: int, stdin: bytes | None = None) -> CommandResult:
        if not operation_id or len(operation_id) > 1024:
            raise OpenShellError("stable operation_id is required")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 0 < timeout <= self.config.max_timeout_seconds:
            raise OpenShellError("execution timeout exceeds the configured bound")
        args = ["/bin/sh", "-c", command] if isinstance(command, str) else list(command)
        if not args or any(not isinstance(a, str) or "\x00" in a for a in args):
            raise OpenShellError("invalid command")
        if len(args) > 256 or sum(len(a.encode()) for a in args) > 65536:
            raise OpenShellError("command exceeds its input bound")
        if stdin is not None and len(stdin) > self.config.max_transfer_bytes:
            raise OpenShellError("stdin exceeds the transfer bound")
        request_digest = _digest([asdict(sandbox), args, timeout,
                                  hashlib.sha256(stdin or b"").hexdigest()])
        key = _digest([sandbox.run_id, operation_id])
        path = self._record("operations", key)
        receipt = {"sandbox": asdict(sandbox), "operation_id": operation_id,
                   "request_digest": request_digest, "command": args}

        def replay() -> CommandResult:
            saved = json.loads(path.read_bytes())
            if saved.get("request_digest") != request_digest:
                raise OpenShellError("operation_id was reused with a different request")
            if "result" not in saved:
                raise ExecutionUnknown("prior dispatch has no completed receipt; do not resend")
            return CommandResult(**saved["result"])

        async with self._locks.setdefault(key, asyncio.Lock()):
            if path.exists():
                return replay()
            self._owned(sandbox)
            try:
                self._save(path, receipt, exclusive=True)
            except FileExistsError:
                return replay()
            try:
                await self._corroborate(sandbox, "native workload identity changed")
                result, _ = await asyncio.to_thread(self._stream, sandbox, args, timeout, stdin,
                    _request_id(key), self.config.max_output_bytes)
            except asyncio.CancelledError:
                await asyncio.shield(self.close(sandbox))
                raise
            except Exception as exc:
                await self.close(sandbox)
                raise ExecutionUnknown("native execution outcome unknown; sandbox closed") from exc
            self._save(path, {**receipt, "result": asdict(result)})
            return result

    def receipts(self, run_id: str) -> list[ExecutionReceipt]:
        values = []
        snapshots = {}
        verified = set()
        for path in (self.config.state_dir / "transfers").glob("*.json"):
            saved = json.loads(path.read_bytes())
            if saved.get("restored") and saved.get("expected_source_digest"):
                snapshots[saved["probe"]["id"]] = saved["sha256"]
            if saved.get("source_verified"):
                verified.update((saved["source"]["id"], operation)
                                for operation in saved["verified_operations"])
        for path in (self.config.state_dir / "operations").glob("*.json"):
            saved = json.loads(path.read_bytes())
            if saved["sandbox"]["run_id"] == run_id and "result" in saved:
                values.append(ExecutionReceipt(Sandbox(**saved["sandbox"]), saved["operation_id"],
                    saved["request_digest"], saved["command"], CommandResult(**saved["result"]),
                    snapshots.get(saved["sandbox"]["id"]),
                    (saved["sandbox"]["id"], saved["operation_id"]) in verified))
        return values

    async def upload(self, sandbox: Sandbox, source: Path, destination: str) -> None:
        self._owned(sandbox)
        _path(destination)
        if sandbox.profile == "model":
            raise OpenShellError("repository upload is forbidden in model sandboxes")
        if not source.is_dir() or source.is_symlink():
            raise OpenShellError("source must be a regular directory")
        archive = io.BytesIO()
        total = 0
        with tarfile.open(fileobj=archive, mode="w") as tar:
            for path in sorted(source.rglob("*")):
                if path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise OpenShellError("source archive cannot contain symlinks or special files")
                total += path.stat().st_size if path.is_file() else 0
                if total > self.config.max_transfer_bytes:
                    raise OpenShellError("source archive exceeds the transfer bound")
                tar.add(path, arcname=str(path.relative_to(source)), recursive=False)
                if archive.tell() > self.config.max_transfer_bytes:
                    raise OpenShellError("source archive exceeds the transfer bound")
        data = archive.getvalue()
        script = "import io,pathlib,sys,tarfile; p=pathlib.Path(sys.argv[1]); p.mkdir(parents=True,exist_ok=True); t=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())); t.extractall(p,filter='data')"
        result = await self.execute(sandbox, [_PYTHON, "-I", "-c", script, destination],
            operation_id="upload:" + _digest([destination, hashlib.sha256(data).hexdigest()]),
            timeout=60, stdin=data)
        if result.exit_code:
            raise OpenShellError("source upload failed")

    async def _snapshot(self, source: Sandbox, *, operation_id: str,
                        expected_source: Path | None) -> tuple[bytes, Path, str | None]:
        """Capture and compare source bytes; never extract repository code on the worker."""
        self._owned(source)
        if source.profile not in ("workspace", "probe"):
            raise OpenShellError("model workload cannot provide a repository snapshot")
        if not operation_id or len(operation_id) > 1024:
            raise OpenShellError("stable copy operation_id is required")
        key = _digest([source.id, operation_id])
        record = self._record("transfers", key)
        archive = record.with_suffix(".tar")
        async with self._locks.setdefault(key, asyncio.Lock()):
            if record.exists():
                saved = json.loads(record.read_bytes())
                if "sha256" not in saved:
                    raise ExecutionUnknown("source snapshot has an unknown prior outcome")
                raw = archive.read_bytes()
                if len(raw) != saved["size"] or hashlib.sha256(raw).hexdigest() != saved["sha256"]:
                    raise OpenShellError("persisted source snapshot integrity failed")
            else:
                self._save(record, {"source": asdict(source), "operation_id": operation_id}, exclusive=True)
                try:
                    await self._corroborate(source, "source native identity changed")
                    result, raw = await asyncio.to_thread(self._stream, source,
                        ["/usr/bin/tar", "-C", "/workspace/repo", "-cf", "-", "."],
                        60, None, _request_id(key), self.config.max_transfer_bytes, True)
                    if result.exit_code or result.output_truncated:
                        raise OpenShellError("source snapshot capture failed")
                    atomic_write_bytes(archive, raw, sync_directory=True)
                    self._save(record, {"source": asdict(source), "operation_id": operation_id,
                        "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
                except BaseException:
                    await asyncio.shield(self.close(source))
                    raise
            # Parse metadata only. No archive member is ever extracted on the
            # worker; hardlinks, symlinks, devices and traversal are refused.
            try:
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
                    size = 0
                    seen = set()
                    archived_files = {}
                    for count, member in enumerate(tar, 1):
                        path = PurePosixPath(member.name)
                        size += member.size
                        if (path.is_absolute() or ".." in path.parts or path in seen
                                or not (member.isfile() or member.isdir())
                                or count > 65536 or size > self.config.max_transfer_bytes):
                            raise UnsafeSnapshotMetadata("source snapshot contains unsafe archive metadata")
                        seen.add(path)
                        if member.isfile():
                            stream = tar.extractfile(member)
                            assert stream is not None
                            archived_files[path] = (_sha256(stream), member.mode & 0o111)
            except tarfile.TarError:
                raise OpenShellError("source snapshot is not a valid archive") from None
            original_files = {}
            if expected_source is not None:
                if not expected_source.is_dir() or expected_source.is_symlink():
                    raise OpenShellError("original source snapshot must be a regular directory")
                total = 0
                for original in sorted(expected_source.rglob("*")):
                    if original.is_symlink() or not (original.is_file() or original.is_dir()):
                        raise OpenShellError("original source snapshot contains unsafe file types")
                    if original.is_file():
                        total += original.stat().st_size
                        if total > self.config.max_transfer_bytes or len(original_files) >= 65536:
                            raise OpenShellError("original source snapshot exceeds bound")
                        with original.open("rb") as stream:
                            content_digest = _sha256(stream)
                        name = PurePosixPath(original.relative_to(expected_source).as_posix())
                        identity = (content_digest, original.stat().st_mode & 0o111)
                        original_files[str(name)] = identity
                        if archived_files.get(name) != identity:
                            raise OpenShellError("workspace changed or deleted original source")
            return raw, record, _digest(original_files) if expected_source is not None else None

    async def copy_workspace(self, source: Sandbox, probe: Sandbox, *, operation_id: str,
                             expected_source: Path | None = None) -> str:
        self._owned(probe)
        if source.profile != "workspace" or probe.profile != "probe" or source.run_id != probe.run_id:
            raise OpenShellError("source snapshots may only enter this investigation's offline probe")
        raw, record, original_digest = await self._snapshot(source, operation_id=operation_id,
                                                          expected_source=expected_source)
        script = "import io,pathlib,sys,tarfile; p=pathlib.Path('/workspace/repo'); p.mkdir(exist_ok=True); t=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())); t.extractall(p,filter='data')"
        result = await self.execute(probe, [_PYTHON, "-I", "-c", script],
            operation_id=operation_id + ":restore", timeout=60, stdin=raw)
        if result.exit_code:
            raise OpenShellError("offline probe source restore failed")
        archive_digest = hashlib.sha256(raw).hexdigest()
        self._save(record, {"source": asdict(source), "probe": asdict(probe),
            "operation_id": operation_id, "sha256": archive_digest, "size": len(raw),
            "expected_source_digest": original_digest, "restored": True})
        return archive_digest

    async def verify_source(self, probe: Sandbox, expected_source: Path, *, operation_id: str) -> None:
        if probe.profile != "probe":
            raise OpenShellError("post-execution integrity checks require an offline probe")
        raw, record, original_digest = await self._snapshot(probe, operation_id=operation_id,
                                                          expected_source=expected_source)
        if json.loads(record.read_bytes()).get("source_verified"):
            return
        operations = []
        for path in (self.config.state_dir / "operations").glob("*.json"):
            saved = json.loads(path.read_bytes())
            if saved["sandbox"]["id"] == probe.id and "result" in saved:
                operations.append(saved["operation_id"])
        self._save(record, {"source": asdict(probe), "operation_id": operation_id,
            "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            "expected_source_digest": original_digest, "source_verified": True,
            "verified_operations": operations})

    async def close(self, sandbox: Sandbox) -> None:
        key = self._key(sandbox)
        path = self._record("sandboxes", key)
        if not path.exists():
            raise OpenShellError("cannot delete an unowned sandbox")
        saved = json.loads(path.read_bytes())
        if saved["sandbox"] != asdict(sandbox):
            raise OpenShellError("sandbox deletion ownership mismatch")
        if saved.get("closed"):
            return
        # Check the exact native ID before name-based deletion. A replacement
        # under the same name must never be stopped or deleted by this run.
        import grpc
        try:
            current = (await self._get(sandbox.name)).sandbox
        except grpc.RpcError as exc:
            if exc.code() != grpc.StatusCode.NOT_FOUND:
                raise
        else:
            if not sandbox.id:
                expected = {"ih.owner": _OWNER,
                    "ih.run": hashlib.sha256(sandbox.run_id.encode()).hexdigest()[:32],
                    "ih.profile": sandbox.profile}
                if dict(current.metadata.labels) != expected or not current.metadata.id:
                    raise OpenShellError("pending creation ownership mismatch")
                sandbox = Sandbox(current.metadata.id, sandbox.run_id, sandbox.name,
                                  sandbox.profile, sandbox.slot)
                self._save(path, {"sandbox": asdict(sandbox), "closed": False})
            if current.metadata.id != sandbox.id:
                raise OpenShellError("sandbox name now belongs to another native id")
            await asyncio.to_thread(self._client.delete, sandbox.name,
                                    workspace=self.config.workspace, allow_missing=True)
            await asyncio.to_thread(self._client.wait_deleted, sandbox.name,
                workspace=self.config.workspace, timeout_seconds=60, expected_sandbox_id=sandbox.id)
        if not sandbox.id:
            raise ExecutionUnknown("pending native create cannot yet be confirmed absent")
        await self._inspect(sandbox, deleted=True)
        self._save(path, {"sandbox": asdict(sandbox), "closed": True})

    async def close_run(self, run_id: str) -> None:
        self._save(self._record("closed-runs", run_id), {"run_id": run_id})
        # Persist the fence first; a create racing the scan observes it and
        # cleans up its own exact native ID before it can return a handle.
        failures = []
        for path in (self.config.state_dir / "sandboxes").glob("*.json"):
            saved = json.loads(path.read_bytes())
            if saved["sandbox"]["run_id"] == run_id and not saved["closed"]:
                try:
                    await self.close(Sandbox(**saved["sandbox"]))
                except Exception as exc:
                    failures.append(exc)
        if failures:
            failures[0].add_note(f"{len(failures)} owned sandbox cleanup operation(s) failed")
            raise failures[0]
