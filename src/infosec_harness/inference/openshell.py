"""Pinned native OpenShell lifecycle adapter; configured identities are not evidence."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import Field

from infosec_harness.sandbox.process import MINIMAL_PATH, ProcessResult, run_bounded

from .executor import ExecutorSettings
from .http_service import https_origin
from .policy import canonical_policy, policy_digest
from .protocol import (
    DIGEST_PATTERN,
    MAX_BODY_BYTES,
    OPENSHELL_VERSION,
    BrokerError,
    ExecutorContract,
    StrictModel,
    canonical_bytes,
    digest,
)

_LOG = logging.getLogger(__name__)
# Acknowledgement wait leaves cleanup authority/time for exact-owned destruction.
_DETACH_ACK_TIMEOUT_S = 30.0
_ABSENCE_TIMEOUT_S = 30.0
_LEDGER_CREDENTIAL_KEYS = ["IH_LEDGER_TOKEN"]
_ROLE_LABEL = "openshell.ai/isolation-role"


def _identity_failure(boundary: str, category: str, **observations: bool) -> BrokerError:
    """Log one fixed identity marker and return the sanitized error for the caller to raise."""
    detail = "".join(f" {name}={value}" for name, value in observations.items())
    _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=%s category=%s%s", boundary, category, detail)
    return BrokerError("identity")


def _atomic_write(directory: Path, path: Path, data: bytes) -> None:
    """Owner-only write that is either absent or complete after a crash."""
    if path.is_symlink():
        raise BrokerError("identity")
    fd, temporary = tempfile.mkstemp(dir=directory)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _private_directory(directory: Path) -> Path:
    if directory.is_symlink():
        raise BrokerError("identity")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    status = directory.stat()
    if status.st_uid != os.getuid() or status.st_mode & 0o077:
        raise BrokerError("identity", "Lease store must be private and controller-owned")
    return directory


def _matches_provider(
    item: dict,
    *,
    profile: str,
    workspace: str,
    native_id: str | None = None,
    resource_version: int | None = None,
    credential_keys: list[str] | None = None,
) -> bool:
    """Exact native provider identity; an empty expected native ID never matches."""
    return (
        bool(item.get("id"))
        and item.get("type") == profile
        and item.get("workspace") == workspace
        and (native_id is None or (bool(native_id) and item.get("id") == native_id))
        and (resource_version is None or item.get("resource_version") == resource_version)
        and (credential_keys is None or item.get("credential_keys") == credential_keys)
    )


@dataclass(frozen=True)
class NativeSpec:
    approved_policy: dict
    ledger_origin: str
    ledger_profile: str
    provider_profile: str
    provider_env: str
    credential_revision: str
    max_input_tokens: int
    max_output_tokens: int
    provider_resource_version: int
    provider_profile_digest: str
    ledger_profile_digest: str
    provider_native_id: str


class NativeDeploymentConfig(StrictModel):
    """Operator-only configuration: no wire-provided lifecycle or endpoint authority."""

    deployment: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    binary: Path
    binary_sha256: str = Field(pattern=DIGEST_PATTERN)
    gateway: str
    service_domain: str = Field(default="openshell.localhost", pattern=r"^[a-z0-9][a-z0-9.-]+$")
    workspace: str
    config_home: Path
    tls_directory: Path
    docker_socket: str
    docker_binary: str = "/usr/local/bin/docker"
    lease_directory: Path
    gateway_ca: Path
    gateway_client_certificate: Path
    gateway_client_key: Path
    specs: dict[str, dict]

    def build(self) -> OpenShellAdapter:
        cli = NativeCLI(
            self.binary,
            sha256=self.binary_sha256,
            gateway=self.gateway,
            service_domain=self.service_domain,
            workspace=self.workspace,
            config_home=self.config_home,
            tls_directory=self.tls_directory,
            docker_socket=self.docker_socket,
            docker_binary=self.docker_binary,
        )
        try:
            specs = {identity: NativeSpec(**spec) for identity, spec in self.specs.items()}
        except TypeError:
            raise BrokerError("policy") from None
        return OpenShellAdapter(
            cli, store=LeaseStore(self.lease_directory), deployment=self.deployment, specs=specs
        )


class LeaseState(StrEnum):
    """Persisted lease lifecycle. Values are the stored strings; never rename them."""

    CREATING = "creating"
    READY = "ready"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    SANDBOX_DELETED = "sandbox_deleted"
    DELETED = "deleted"


# Revocation may restart from REVOKED after a partial failure; nothing leaves DELETED.
_TRANSITIONS: dict[LeaseState, frozenset[LeaseState]] = {
    LeaseState.CREATING: frozenset(
        {LeaseState.READY, LeaseState.QUARANTINED, LeaseState.REVOKED}
    ),
    LeaseState.READY: frozenset({LeaseState.REVOKED}),
    LeaseState.QUARANTINED: frozenset({LeaseState.REVOKED}),
    LeaseState.REVOKED: frozenset({LeaseState.REVOKED, LeaseState.SANDBOX_DELETED}),
    LeaseState.SANDBOX_DELETED: frozenset({LeaseState.DELETED}),
    LeaseState.DELETED: frozenset(),
}


@dataclass
class Lease:
    lease_id: str
    deployment: str
    run_id: str
    contract: ExecutorContract
    credential_revision: str
    name: str
    ingress_key_hex: str = field(repr=False)
    ledger_key: str = field(repr=False)
    native_id: str = ""
    status: LeaseState = LeaseState.CREATING
    service_endpoint: str = ""
    ledger_native_id: str = ""
    # Revocation input persisted at creation: cleanup must not depend on current operator
    # configuration, which may have dropped or changed this contract's native spec.
    ledger_profile: str = ""

    def __setattr__(self, name: str, value: Any) -> None:
        # Persisted and test-supplied strings always become the closed state enum.
        super().__setattr__(name, LeaseState(value) if name == "status" else value)

    def labels(self) -> dict[str, str]:
        def identity(value: str) -> str:
            return (
                base64.b32encode(hashlib.sha256(value.encode()).digest())
                .decode()
                .rstrip("=")
                .lower()
            )

        return {
            "ih.deployment": self.deployment,
            "ih.run": identity(self.run_id),
            "ih.contract": identity(self.contract.digest),
            "ih.lease": self.lease_id,
            "ih.credential-revision": identity(self.credential_revision),
        }

    @property
    def ledger_name(self) -> str:
        return f"ih-ledger-{self.lease_id}"

    def owns(self, observed: dict) -> bool:
        """Exact persisted native ID, name and labels; a selector match alone is not ownership."""
        return (
            bool(self.native_id)
            and observed.get("id") == self.native_id
            and observed.get("name") == self.name
            and observed.get("labels") == self.labels()
        )


class LeaseStore:
    """Controller-owned recovery identity. Secret records are never evidence artifacts."""

    def __init__(self, directory: Path):
        self.directory = _private_directory(directory)

    @property
    def archive(self) -> Path:
        return _private_directory(self.directory / "archive")

    def save(self, lease: Lease) -> None:
        values = {**vars(lease), "contract": lease.contract.model_dump(mode="json")}
        _atomic_write(
            self.directory, self.directory / f"{lease.lease_id}.json", canonical_bytes(values)
        )

    def retire(self, lease: Lease) -> None:
        """Replace a deleted lease's secret record with a secret-free archive entry."""
        if lease.status is not LeaseState.DELETED:
            raise BrokerError("identity")
        record = {
            "lease_id": lease.lease_id,
            "deployment": lease.deployment,
            "run_id": lease.run_id,
            "contract_digest": lease.contract.digest,
            "name": lease.name,
            "native_id": lease.native_id,
            "ledger_native_id": lease.ledger_native_id,
            "status": str(lease.status),
        }
        archive = self.archive
        _atomic_write(archive, archive / f"{lease.lease_id}.json", canonical_bytes(record))
        (self.directory / f"{lease.lease_id}.json").unlink(missing_ok=True)

    def is_retired(self, lease_id: str) -> bool:
        path = self.archive / f"{lease_id}.json"
        return path.is_file() and not path.is_symlink()

    def _run_tombstone(self, run_id: str) -> Path:
        if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
            raise BrokerError("identity")
        return self.directory / ("closed-" + hashlib.sha256(run_id.encode()).hexdigest())

    def is_run_revoked(self, run_id: str) -> bool:
        path = self._run_tombstone(run_id)
        if not path.exists() and not path.is_symlink():
            return False
        if path.is_symlink() or path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
            raise BrokerError("identity")
        if path.read_bytes() != run_id.encode():
            raise BrokerError("identity")
        return True

    def revoke_run(self, run_id: str) -> None:
        if not self.is_run_revoked(run_id):
            _atomic_write(self.directory, self._run_tombstone(run_id), run_id.encode())

    def load(self) -> list[Lease]:
        leases = []
        for path in sorted(self.directory.glob("*.json")):
            if (
                path.is_symlink()
                or path.stat().st_mode & 0o077
                or path.stat().st_uid != os.getuid()
            ):
                raise BrokerError("identity")
            try:
                values = json.loads(path.read_bytes())
                values["contract"] = ExecutorContract.model_validate(values["contract"])
                lease = Lease(**values)
                if str(uuid.UUID(lease.lease_id)) != path.stem:
                    raise ValueError
                leases.append(lease)
            except Exception:
                raise BrokerError("identity", "Lease recovery record is invalid") from None
        return leases


class NativeOperations(Protocol):
    """The native control surface the adapter needs; tests substitute fakes."""

    gateway: str
    workspace: str
    service_domain: str

    async def preflight(self) -> None: ...

    async def run(
        self, args: list[str], *, extra_env: dict[str, str] | None = None, timeout: float = 90
    ) -> str: ...

    async def containers(self, native_id: str) -> list[dict]: ...


class NativeCLI:
    def __init__(
        self,
        binary: Path,
        *,
        sha256: str,
        gateway: str,
        workspace: str,
        config_home: Path,
        tls_directory: Path,
        docker_socket: str,
        docker_binary: str = "/usr/local/bin/docker",
        service_domain: str = "openshell.localhost",
    ):
        https_origin(gateway)
        if not docker_socket.startswith("unix:///") or docker_socket in {
            "unix:///var/run/docker.sock",
            "unix:///run/docker.sock",
        }:
            raise BrokerError("policy", "A dedicated native Docker socket is required")
        self.binary, self.sha256 = binary, sha256
        self.gateway, self.workspace = gateway.rstrip("/"), workspace
        self.service_domain = service_domain
        self.docker_socket, self.docker_binary = docker_socket, docker_binary
        self.environment = {
            "PATH": MINIMAL_PATH,
            "XDG_CONFIG_HOME": str(config_home),
            "OPENSHELL_LOCAL_TLS_DIR": str(tls_directory),
            "OPENSHELL_COLOR": "never",
        }
        self._verified_binary: tuple[int, ...] | None = None

    def _verify_binary(self) -> None:
        """Hash the pinned CLI again whenever its file identity or metadata changes."""
        try:
            status = self.binary.stat()
            key = (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns,
                   status.st_ctime_ns)
            if key == self._verified_binary:
                return
            self._verified_binary = None
            observed = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        except OSError:
            raise BrokerError("unavailable") from None
        if observed != self.sha256:
            raise BrokerError("identity", "Pinned OpenShell CLI checksum mismatch")
        self._verified_binary = key

    async def _execute(
        self, argv: list[str], *, env: dict[str, str], timeout: float
    ) -> ProcessResult:
        try:
            result = await run_bounded(argv, env=env, timeout=timeout,
                                       capture_limit=MAX_BODY_BYTES)
        except OSError:
            raise BrokerError("unavailable") from None
        # Native errors may contain credential material. Never echo stderr or argv.
        if result.timed_out or result.truncated or result.returncode:
            raise BrokerError("unavailable")
        return result

    async def preflight(self) -> None:
        ssh = shutil.which("ssh", path=self.environment["PATH"])
        if ssh is None:
            raise BrokerError("unavailable", "Native file upload requires an SSH client")
        try:
            await self._execute([ssh, "-V"], env=self.environment, timeout=5)
        except BrokerError:
            raise BrokerError("unavailable", "Native SSH client is unavailable") from None

    async def run(
        self, args: list[str], *, extra_env: dict[str, str] | None = None, timeout: float = 90
    ) -> str:
        self._verify_binary()
        if args == ["--version"]:
            argv = [str(self.binary), "--version"]
        else:
            argv = [str(self.binary), "--gateway-endpoint", self.gateway,
                    "--workspace", self.workspace, *args]
        result = await self._execute(
            argv, env={**self.environment, **(extra_env or {})}, timeout=timeout
        )
        return result.stdout.decode()

    async def containers(self, native_id: str) -> list[dict]:
        docker = [self.docker_binary, "--host", self.docker_socket]
        listed = await self._execute(
            [*docker, "ps", "-a", "-q", "--filter", f"label=openshell.ai/sandbox-id={native_id}"],
            env=self.environment,
            timeout=15,
        )
        ids = listed.stdout.decode().split()
        if not ids:
            return []
        inspected = await self._execute([*docker, "inspect", *ids], env=self.environment,
                                        timeout=15)
        try:
            value = json.loads(inspected.stdout)
        except ValueError:
            raise BrokerError("unavailable") from None
        if not isinstance(value, list):
            raise BrokerError("unavailable")
        return value


def _incomplete() -> BrokerError:
    return BrokerError("policy", "Native observations are incomplete")


class OpenShellAdapter:
    def __init__(
        self,
        cli: NativeOperations,
        *,
        store: LeaseStore,
        deployment: str,
        specs: dict[str, NativeSpec],
    ):
        self.cli, self.store, self.deployment, self.specs = cli, store, deployment, specs
        self.leases: dict[str, Lease] = {}
        for lease in store.load():
            if lease.status is LeaseState.DELETED:
                store.retire(lease)
            else:
                self.leases[lease.lease_id] = lease
        # Startup reconciliation only touches what an earlier process left behind.
        self._recovered = tuple(self.leases)
        # Global lock: lease table, provisioning and run closure. Lease locks: every
        # revocation and readiness check of one lease. Order is always global, then lease.
        self.lock = asyncio.Lock()
        self._lease_locks: dict[str, asyncio.Lock] = {}

    def _lease_lock(self, lease_id: str) -> asyncio.Lock:
        return self._lease_locks.setdefault(lease_id, asyncio.Lock())

    def _transition(self, lease: Lease, state: LeaseState) -> None:
        if state not in _TRANSITIONS[lease.status]:
            raise _identity_failure("lease_state", "transition")
        lease.status = state
        self.store.save(lease)

    async def _json(self, args: list[str], **kwargs: Any) -> dict:
        try:
            value = json.loads(await self.cli.run(args, **kwargs))
        except ValueError:
            raise _incomplete() from None
        if not isinstance(value, dict):
            raise _incomplete()
        return value

    async def _inventory(
        self, args: list[str], key: str, *, boundary: str, category: str,
        failure: str = "identity",
    ) -> list[dict]:
        """One complete native page; pagination is never followed or silently truncated."""
        value = await self._json([*args, "-o", "json"])
        if value.get("next_page_token"):
            if failure == "identity":
                raise _identity_failure(boundary, category)
            raise BrokerError(failure)
        items = value.get(key)
        if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
            raise _incomplete()
        return items

    async def _owned_sandboxes(self, lease: Lease, *, category: str) -> list[dict]:
        """At most one sandbox may carry this lease's selector label."""
        matches = await self._inventory(
            ["sandbox", "list", "--selector", f"ih.lease={lease.lease_id}"], "sandboxes",
            boundary="native_revoke", category=category,
        )
        if len(matches) > 1:
            raise _identity_failure("native_revoke", category)
        return matches

    def _check_fence(self, run_id: str) -> None:
        if self.store.is_run_revoked(run_id):
            raise _identity_failure("native_ensure", "run_fence")

    def spec(self, contract: ExecutorContract) -> NativeSpec:
        spec = self.specs.get(contract.digest)
        if spec is None or policy_digest(spec.approved_policy) != contract.policy_digest:
            raise BrokerError("policy")
        https_origin(spec.ledger_origin)
        if spec.approved_policy.get("landlock", {}).get("compatibility") != "hard_requirement":
            raise BrokerError("policy")
        if spec.provider_resource_version <= 0 or not spec.provider_native_id:
            raise BrokerError("identity")
        for network in spec.approved_policy.get("network_policies", {}).values():
            for endpoint in network.get("endpoints", []):
                if (
                    endpoint.get("protocol") != "rest"
                    or endpoint.get("enforcement") != "enforce"
                    or endpoint.get("tls", "terminate") != "terminate"
                    or not endpoint.get("allowed_ips")
                    or not endpoint.get("rules")
                ):
                    raise BrokerError("policy")
        return spec

    def service_url(self, lease: Lease) -> str:
        if not lease.service_endpoint:
            raise BrokerError("unavailable")
        return lease.service_endpoint + "v1/infer"

    def is_deleted(self, lease_id: str) -> bool:
        """A lease absent from the active table is deleted only if its retirement is recorded."""
        return lease_id not in self.leases and self.store.is_retired(lease_id)

    async def ensure(self, run_id: str, contract: ExecutorContract) -> Lease:
        spec = self.spec(contract)
        async with self.lock:
            self._check_fence(run_id)
            current, stale = None, []
            for lease in self.leases.values():
                if (
                    lease.deployment != self.deployment
                    or lease.run_id != run_id
                    or lease.contract != contract
                    or lease.status is not LeaseState.READY
                ):
                    continue
                if lease.credential_revision != spec.credential_revision:
                    stale.append(lease)
                elif current is None:
                    current = lease
            for lease in stale:
                await self.revoke(lease)
            if current is None:
                return await self._provision(run_id, contract, spec)
        # Re-verifying a ready lease must not block provisioning or closure of other runs.
        async with self._lease_lock(current.lease_id):
            self._check_fence(run_id)
            if current.status is not LeaseState.READY:
                raise BrokerError("unavailable")
            await self.verify(current)
        self._check_fence(run_id)
        return current

    async def _provision(self, run_id: str, contract: ExecutorContract, spec: NativeSpec) -> Lease:
        """Create one lease; the caller holds the global lock so closure waits for it."""
        await self.cli.preflight()
        version = await self.cli.run(["--version"])
        if version.strip() != f"openshell {OPENSHELL_VERSION}":
            raise _identity_failure("native_ensure", "cli_version")
        self._check_fence(run_id)
        identity = str(uuid.uuid4())
        lease = Lease(
            identity,
            self.deployment,
            run_id,
            contract,
            spec.credential_revision,
            f"ih-{identity.replace('-', '')[:16]}",
            secrets.token_hex(32),
            secrets.token_hex(32),
            ledger_profile=spec.ledger_profile,
        )
        self.leases[identity] = lease
        self.store.save(lease)  # Persist ownership before the first native mutation.
        try:
            await self._create(lease, spec)
            await self.verify(lease)
            if self.store.is_run_revoked(run_id):
                await self.revoke(lease)
                raise _identity_failure("native_ensure", "run_fence")
            self._transition(lease, LeaseState.READY)
            return lease
        except BaseException:
            # An interrupted creation stays quarantined for corroborated reconciliation; a
            # revocation that already started keeps its own resumable state.
            if lease.status is LeaseState.CREATING:
                self._transition(lease, LeaseState.QUARANTINED)
            raise

    async def _observe_created(self, lease: Lease, category: str) -> None:
        detail = await self._json(["sandbox", "get", lease.name, "-o", "json"])
        labels_match = detail.get("labels") == lease.labels()
        if not labels_match or not detail.get("id"):
            raise _identity_failure("native_create", category, labels_match=labels_match,
                                    id_present=bool(detail.get("id")))
        if lease.native_id and detail["id"] != lease.native_id:
            raise _identity_failure("native_create", category)
        lease.native_id = detail["id"]
        self.store.save(lease)

    async def _create(self, lease: Lease, spec: NativeSpec) -> None:
        # Native credential create resolves the profile's declared env var, never secret argv.
        await self.cli.run(
            ["provider", "create", "--name", lease.ledger_name, "--type", spec.ledger_profile,
             "--credential", "IH_LEDGER_TOKEN"],
            extra_env={"IH_LEDGER_TOKEN": lease.ledger_key},
        )
        inventory = await self._inventory(
            ["provider", "list"], "providers", boundary="native_create",
            category="provider_inventory",
        )
        matches = [item for item in inventory if item.get("name") == lease.ledger_name]
        if len(matches) != 1:
            raise _identity_failure("native_create", "provider_inventory")
        if not _matches_provider(matches[0], profile=spec.ledger_profile,
                                 workspace=self.cli.workspace,
                                 credential_keys=_LEDGER_CREDENTIAL_KEYS):
            raise _identity_failure("native_create", "provider_identity")
        lease.ledger_native_id = matches[0]["id"]
        self.store.save(lease)
        settings = ExecutorSettings(
            run_id=lease.run_id,
            lease_id=lease.lease_id,
            contract=lease.contract,
            controller_origin=spec.ledger_origin,
            ingress_key_hex=lease.ingress_key_hex,
            provider_env=spec.provider_env,
            max_input_tokens=spec.max_input_tokens,
            max_output_tokens=spec.max_output_tokens,
        )
        with tempfile.TemporaryDirectory(dir=self.store.directory) as directory:
            configuration, policy = Path(directory) / "lease.json", Path(directory) / "policy.json"
            configuration.write_bytes(canonical_bytes(settings.model_dump(mode="json")))
            configuration.chmod(0o600)
            # Native provider profiles compose their own generated rules. Reapplying
            # an observed composed rule would duplicate permissions and fail identity.
            authored = {
                **spec.approved_policy,
                "network_policies": {
                    name: rule
                    for name, rule in spec.approved_policy["network_policies"].items()
                    if not name.startswith("_provider_")
                },
            }
            policy.write_bytes(canonical_bytes(authored))
            policy.chmod(0o600)
            args = [
                "sandbox", "create", "--name", lease.name,
                "--from", lease.contract.executor_image,
                "--provider", lease.contract.provider_binding,
                "--provider", lease.ledger_name,
                "--policy", str(policy),
                "--approval-mode", "manual",
                "--no-auto-providers", "--detach", "--no-tty",
                "--cpu", "1", "--memory", "512Mi",
            ]
            for key, value in lease.labels().items():
                args.extend(["--label", f"{key}={value}"])
            args.extend(["--", "python", "-m", "infosec_harness.inference.executor",
                         "--config", "/tmp/ih-lease.json"])
            await self.cli.run(args, timeout=120)
            await self._observe_created(lease, "sandbox_creation_identity")
            await self.cli.run(
                ["sandbox", "upload", lease.name, str(configuration), "/tmp/ih-lease.json",
                 "--no-git-ignore"],
                timeout=25,
            )
        await self._observe_created(lease, "sandbox_upload_identity")
        await self.cli.run(["service", "expose", lease.name, "8765", "infer"])

    async def verify(self, lease: Lease) -> dict:
        spec = self.spec(lease.contract)
        try:
            return await self._verify(lease, spec)
        except BrokerError:
            raise
        except (KeyError, ValueError, TypeError, AttributeError):
            raise _incomplete() from None

    async def _verify(self, lease: Lease, spec: NativeSpec) -> dict:
        detail = await self._json(["sandbox", "get", lease.name, "-o", "json"])
        admission = detail.get("configuration_admission") or {}
        if (
            detail.get("id") != lease.native_id
            or detail.get("labels") != lease.labels()
            or detail.get("phase") != "Ready"
            or detail.get("policy_source") != "sandbox"
            or admission.get("state") != "accepted"
        ):
            raise BrokerError("policy")
        if lease.credential_revision != spec.credential_revision:
            raise _identity_failure("native_verify", "credential_revision")
        for profile, approved in (
            (spec.provider_profile, spec.provider_profile_digest),
            (spec.ledger_profile, spec.ledger_profile_digest),
        ):
            exported = await self._json(["provider", "profile", "export", profile, "-o", "json"])
            if digest(exported) != approved:
                raise BrokerError("policy")
        inventory = await self._inventory(
            ["provider", "list"], "providers", boundary="native_verify",
            category="provider_inventory",
        )
        named = {}
        for item in inventory:
            named.setdefault(item.get("name"), item)
        provider = named.get(lease.contract.provider_binding)
        if provider is None or not _matches_provider(
            provider, profile=spec.provider_profile, workspace=self.cli.workspace,
            native_id=spec.provider_native_id, resource_version=spec.provider_resource_version,
        ):
            raise _identity_failure("native_verify", "provider_identity")
        ledger_provider = named.get(lease.ledger_name)
        if ledger_provider is None or not _matches_provider(
            ledger_provider, profile=spec.ledger_profile, workspace=self.cli.workspace,
            native_id=lease.ledger_native_id, resource_version=1,
            credential_keys=_LEDGER_CREDENTIAL_KEYS,
        ):
            raise _identity_failure("native_verify", "ledger_provider_identity")
        attached = await self._inventory(
            ["sandbox", "provider", "list", lease.name], "providers",
            boundary="native_verify", category="attachment_inventory", failure="policy",
        )
        if {item["name"]: item["type"] for item in attached} != {
            lease.contract.provider_binding: spec.provider_profile,
            lease.ledger_name: spec.ledger_profile,
        }:
            raise BrokerError("policy")
        if canonical_policy(detail["policy"]) != canonical_policy(spec.approved_policy):
            raise BrokerError("policy")
        services = await self._inventory(
            ["service", "list", lease.name], "services",
            boundary="native_verify", category="service_inventory", failure="policy",
        )
        port = urlsplit(self.cli.gateway).port or 443
        expected_url = (
            f"https://{self.cli.workspace}--{lease.name}--infer.{self.cli.service_domain}:{port}/"
        )
        if services != [{
            "sandbox": lease.name,
            "service": "infer",
            "target_port": 8765,
            "url": expected_url,
            "workspace": self.cli.workspace,
        }]:
            raise BrokerError("policy")
        lease.service_endpoint = expected_url
        containers = await self.cli.containers(lease.native_id)
        roles = [item["Config"]["Labels"].get(_ROLE_LABEL) for item in containers]
        # Exactly one workload and one supervisor: an extra or duplicate container is unverified.
        if sorted(roles, key=str) != ["sandbox", "supervisor"]:
            raise BrokerError("policy")
        by_role = dict(zip(roles, containers, strict=True))
        workload, supervisor = by_role["sandbox"], by_role["supervisor"]
        host = workload["HostConfig"]
        if (
            workload["Image"] != lease.contract.executor_image
            or supervisor["Image"] != lease.contract.supervisor_image
            or not workload["State"]["Running"]
            or not supervisor["State"]["Running"]
            or host["Runtime"] != "runc"
            or host["NetworkMode"] != "none"
            or host["Privileged"]
            or workload["Config"]["User"] != "65532:65532"
            or "ALL" not in host.get("CapDrop", [])
            or "no-new-privileges:true" not in host.get("SecurityOpt", [])
            or any(
                m["Type"] != "volume" or "docker.sock" in m["Destination"]
                for m in workload.get("Mounts", [])
            )
        ):
            raise BrokerError("policy")
        proof = await self._json(
            [
                "sandbox", "exec", "--name", lease.name, "--no-login-shell", "--no-tty",
                "--timeout", "10", "--", "python", "-c",
                "import json,os; s=dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l); "
                "print(json.dumps({'uid':os.getuid(),'nnp':s['NoNewPrivs'].strip(),'seccomp':s['Seccomp'].strip()}))",
            ]
        )
        if proof != {"uid": 65532, "nnp": "1", "seccomp": "2"}:
            raise BrokerError("policy", "Native process confinement proof failed")
        return {
            "native_id": lease.native_id,
            "policy_digest": policy_digest(detail["policy"]),
            "executor_image": workload["Image"],
            "supervisor_image": supervisor["Image"],
            "profile": lease.contract.profile,
            "credential_revision": lease.credential_revision,
        }

    async def revoke(self, lease: Lease) -> None:
        """Idempotent exact-owned cleanup; every caller serializes on the lease lock."""
        if lease.status is LeaseState.DELETED and self.is_deleted(lease.lease_id):
            return
        if self.leases.get(lease.lease_id) is not lease or lease.deployment != self.deployment:
            raise _identity_failure("native_revoke", "lease_ownership")
        async with self._lease_lock(lease.lease_id):
            if lease.status is LeaseState.DELETED:
                return
            try:
                if lease.status is not LeaseState.SANDBOX_DELETED:
                    await self._remove_sandbox(lease)
                await self._remove_ledger_provider(lease)
            except BrokerError:
                raise
            except (KeyError, ValueError, TypeError, AttributeError):
                raise _incomplete() from None
            self._transition(lease, LeaseState.DELETED)
            self.store.retire(lease)
            del self.leases[lease.lease_id]
        self._lease_locks.pop(lease.lease_id, None)

    async def _remove_sandbox(self, lease: Lease) -> None:
        matches = await self._owned_sandboxes(lease, category="sandbox_inventory")
        if matches and not lease.owns(matches[0]):
            raise _identity_failure("native_revoke", "sandbox_identity")
        self._transition(lease, LeaseState.REVOKED)
        if matches:
            attached = await self._inventory(
                ["sandbox", "provider", "list", lease.name], "providers",
                boundary="native_revoke", category="attachment_inventory",
            )
            if any(item.get("name") == lease.contract.provider_binding for item in attached):
                try:
                    await self.cli.run(
                        ["sandbox", "provider", "detach", lease.name,
                         lease.contract.provider_binding, "--wait"],
                        timeout=_DETACH_ACK_TIMEOUT_S,
                    )
                except BrokerError as error:
                    if error.code != "unavailable":
                        raise
                    _LOG.warning("IH_NATIVE_CLEANUP_FAILURE stage=provider_detach "
                                 "category=unavailable action=destroy_owned_sandbox")
                    # An unacknowledged detach can outlast the original ownership
                    # observation. Recheck before deleting anything by name.
                    matches = await self._owned_sandboxes(lease, category="recheck_inventory")
                    if matches and not lease.owns(matches[0]):
                        raise _identity_failure("native_revoke", "recheck_identity") from None
            if matches:
                await self.cli.run(["sandbox", "delete", lease.name])
        until = time.monotonic() + _ABSENCE_TIMEOUT_S
        while True:
            listed = await self._inventory(
                ["sandbox", "list", "--selector", f"ih.lease={lease.lease_id}"], "sandboxes",
                boundary="native_revoke", category="absence_inventory",
            )
            containers = await self.cli.containers(lease.native_id) if lease.native_id else []
            if not listed and not containers:
                break
            if time.monotonic() >= until:
                raise BrokerError("unavailable", "Owned cleanup requires reconciliation")
            await asyncio.sleep(0.2)
        self._transition(lease, LeaseState.SANDBOX_DELETED)

    async def _remove_ledger_provider(self, lease: Lease) -> None:
        inventory = await self._inventory(
            ["provider", "list"], "providers", boundary="native_revoke",
            category="provider_inventory",
        )
        providers = [item for item in inventory if item.get("name") == lease.ledger_name]
        if len(providers) > 1:
            raise _identity_failure("native_revoke", "provider_duplicates")
        if not providers:
            return
        if not lease.ledger_profile or not _matches_provider(
            providers[0], profile=lease.ledger_profile, workspace=self.cli.workspace,
            native_id=lease.ledger_native_id, credential_keys=_LEDGER_CREDENTIAL_KEYS,
        ):
            _identity_failure("native_revoke", "ledger_provider_identity")
            raise BrokerError(
                "identity", "Unconfirmed credential creation requires operator reconciliation"
            )
        await self.cli.run(["provider", "delete", lease.ledger_name])
        remaining = await self._inventory(
            ["provider", "list"], "providers", boundary="native_revoke",
            category="provider_absence", failure="unavailable",
        )
        if any(item.get("name") == lease.ledger_name for item in remaining):
            raise BrokerError("unavailable")

    async def reconcile_recovered(self) -> None:
        """Startup: drive leases an earlier process left non-terminal toward deletion.

        Only persisted creation intent is used. Exact native ownership is still required by
        ``revoke``; anything uncorroborated stays quarantined for operator reconciliation.
        Ready leases of open runs remain usable and are re-verified before each use.
        """
        for lease_id in self._recovered:
            lease = self.leases.get(lease_id)
            if lease is None or lease.deployment != self.deployment:
                continue
            if lease.status is LeaseState.READY and not self.store.is_run_revoked(lease.run_id):
                continue
            if lease.status is LeaseState.CREATING:
                self._transition(lease, LeaseState.QUARANTINED)
            try:
                await self.revoke(lease)
            except BrokerError as error:
                _LOG.warning("IH_NATIVE_RECONCILIATION_FAILURE state=%s category=%s",
                             lease.status, error.code)
