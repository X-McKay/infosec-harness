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
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field

from .executor import ExecutorSettings
from .http_service import https_origin
from .policy import canonical_policy, policy_digest
from .protocol import BrokerError, ExecutorContract, StrictModel, canonical_bytes, digest

_LOG = logging.getLogger(__name__)
# Acknowledgement wait leaves cleanup authority/time for exact-owned destruction.
_DETACH_ACK_TIMEOUT_S = 30.0


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
    binary_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
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
    status: str = "creating"
    service_endpoint: str = ""
    ledger_native_id: str = ""

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


class LeaseStore:
    """Controller-owned recovery identity. Secret records are never evidence artifacts."""

    def __init__(self, directory: Path):
        if directory.is_symlink():
            raise BrokerError("identity")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
            raise BrokerError("identity", "Lease store must be private and controller-owned")
        self.directory = directory

    def save(self, lease: Lease) -> None:
        values = {**vars(lease), "contract": lease.contract.model_dump(mode="json")}
        path = self.directory / f"{lease.lease_id}.json"
        if path.is_symlink():
            raise BrokerError("identity")
        fd, temporary = tempfile.mkstemp(dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(canonical_bytes(values))
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            dir_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

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
        if self.is_run_revoked(run_id):
            return
        path = self._run_tombstone(run_id)
        fd, temporary = tempfile.mkstemp(dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(run_id.encode())
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

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
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "XDG_CONFIG_HOME": str(config_home),
            "OPENSHELL_LOCAL_TLS_DIR": str(tls_directory),
            "OPENSHELL_COLOR": "never",
        }

    async def preflight(self) -> None:
        ssh = shutil.which("ssh", path=self.environment["PATH"])
        if ssh is None:
            raise BrokerError("unavailable", "Native file upload requires an SSH client")
        try:
            await asyncio.to_thread(
                subprocess.run,
                [ssh, "-V"],
                env=self.environment,
                capture_output=True,
                timeout=5,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise BrokerError("unavailable", "Native SSH client is unavailable") from None

    async def run(
        self, args: list[str], *, extra_env: dict[str, str] | None = None, timeout: float = 90
    ) -> str:
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.sha256:
            raise BrokerError("identity", "Pinned OpenShell CLI checksum mismatch")
        argv = [
            str(self.binary),
            "--gateway-endpoint",
            self.gateway,
            "--workspace",
            self.workspace,
            *args,
        ]
        if args == ["--version"]:
            argv = [str(self.binary), "--version"]
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                argv,
                capture_output=True,
                text=True,
                env={**self.environment, **(extra_env or {})},
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise BrokerError("unavailable") from None
        if result.returncode:
            # Native errors may contain credential material. Never echo stderr or argv.
            raise BrokerError("unavailable")
        return result.stdout

    async def containers(self, native_id: str) -> list[dict]:
        argv = [
            self.docker_binary,
            "--host",
            self.docker_socket,
            "ps",
            "-a",
            "-q",
            "--filter",
            f"label=openshell.ai/sandbox-id={native_id}",
        ]
        try:
            listed = await asyncio.to_thread(
                subprocess.run,
                argv,
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
                env=self.environment,
            )
            ids = listed.stdout.split()
            if not ids:
                return []
            result = await asyncio.to_thread(
                subprocess.run,
                [self.docker_binary, "--host", self.docker_socket, "inspect", *ids],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
                env=self.environment,
            )
            return json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            raise BrokerError("unavailable") from None


class OpenShellAdapter:
    def __init__(self, cli, *, store: LeaseStore, deployment: str, specs: dict[str, NativeSpec]):
        self.cli, self.store, self.deployment, self.specs = cli, store, deployment, specs
        self.leases = {lease.lease_id: lease for lease in store.load()}
        self.lock = asyncio.Lock()

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

    async def ensure(self, run_id: str, contract: ExecutorContract) -> Lease:
        spec = self.spec(contract)
        async with self.lock:
            if self.store.is_run_revoked(run_id):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_ensure category=run_fence")
                raise BrokerError("identity")
            for lease in list(self.leases.values()):
                if (
                    lease.deployment == self.deployment
                    and lease.run_id == run_id
                    and lease.contract == contract
                    and lease.status == "ready"
                    and lease.credential_revision != spec.credential_revision
                ):
                    await self.revoke(lease)
            for lease in self.leases.values():
                if (
                    lease.deployment == self.deployment
                    and lease.run_id == run_id
                    and lease.contract == contract
                    and lease.credential_revision == spec.credential_revision
                    and lease.status == "ready"
                ):
                    await self.verify(lease)
                    if self.store.is_run_revoked(run_id):
                        _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_ensure category=run_fence")
                        raise BrokerError("identity")
                    return lease
            await self.cli.preflight()
            version = await self.cli.run(["--version"])
            if version.strip() != "openshell 0.1.2":
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_ensure category=cli_version")
                raise BrokerError("identity")
            if self.store.is_run_revoked(run_id):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_ensure category=run_fence")
                raise BrokerError("identity")
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
            )
            self.leases[identity] = lease
            self.store.save(lease)  # Persist ownership before the first native mutation.
            try:
                await self._create(lease, spec)
                await self.verify(lease)
                if self.store.is_run_revoked(run_id):
                    await self.revoke(lease)
                    _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_ensure category=run_fence")
                    raise BrokerError("identity")
                lease.status = "ready"
                self.store.save(lease)
                return lease
            except BaseException:
                if lease.status != "deleted":
                    lease.status = "quarantined"
                    self.store.save(lease)
                raise

    async def _create(self, lease: Lease, spec: NativeSpec) -> None:
        # Native credential create resolves the profile's declared env var, never secret argv.
        ledger_name = f"ih-ledger-{lease.lease_id}"
        await self.cli.run(
            [
                "provider",
                "create",
                "--name",
                ledger_name,
                "--type",
                spec.ledger_profile,
                "--credential",
                "IH_LEDGER_TOKEN",
            ],
            extra_env={"IH_LEDGER_TOKEN": lease.ledger_key},
        )
        inventory = json.loads(await self.cli.run(["provider", "list", "-o", "json"]))
        matches = [
            item for item in inventory.get("providers", []) if item.get("name") == ledger_name
        ]
        if inventory.get("next_page_token") or len(matches) != 1:
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_create category=provider_inventory")
            raise BrokerError("identity")
        provider = matches[0]
        if (
            provider.get("type") != spec.ledger_profile
            or provider.get("workspace") != self.cli.workspace
            or provider.get("credential_keys") != ["IH_LEDGER_TOKEN"]
            or not provider.get("id")
        ):
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_create category=provider_identity")
            raise BrokerError("identity")
        lease.ledger_native_id = provider["id"]
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
                "sandbox",
                "create",
                "--name",
                lease.name,
                "--from",
                lease.contract.executor_image,
                "--provider",
                lease.contract.provider_binding,
                "--provider",
                ledger_name,
                "--policy",
                str(policy),
                "--approval-mode",
                "manual",
                "--no-auto-providers",
                "--detach",
                "--no-tty",
                "--cpu",
                "1",
                "--memory",
                "512Mi",
            ]
            for key, value in lease.labels().items():
                args.extend(["--label", f"{key}={value}"])
            args.extend(
                [
                    "--",
                    "python",
                    "-m",
                    "infosec_harness.inference.executor",
                    "--config",
                    "/tmp/ih-lease.json",
                ]
            )
            await self.cli.run(args, timeout=120)
            created = json.loads(await self.cli.run(["sandbox", "get", lease.name, "-o", "json"]))
            if created.get("labels") != lease.labels() or not created.get("id"):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_create category=sandbox_creation_identity labels_match=%s id_present=%s",
                             created.get("labels") == lease.labels(), bool(created.get("id")))
                raise BrokerError("identity")
            lease.native_id = created["id"]
            self.store.save(lease)
            await self.cli.run(
                [
                    "sandbox",
                    "upload",
                    lease.name,
                    str(configuration),
                    "/tmp/ih-lease.json",
                    "--no-git-ignore",
                ],
                timeout=25,
            )
        detail = json.loads(await self.cli.run(["sandbox", "get", lease.name, "-o", "json"]))
        if detail.get("labels") != lease.labels() or not detail.get("id"):
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_create category=sandbox_upload_identity labels_match=%s id_present=%s",
                             detail.get("labels") == lease.labels(), bool(detail.get("id")))
            raise BrokerError("identity")
        lease.native_id = detail["id"]
        self.store.save(lease)
        await self.cli.run(["service", "expose", lease.name, "8765", "infer"])

    async def verify(self, lease: Lease) -> dict:
        spec = self.spec(lease.contract)
        try:
            detail = json.loads(await self.cli.run(["sandbox", "get", lease.name, "-o", "json"]))
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
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_verify category=credential_revision")
                raise BrokerError("identity")
            for profile, approved in (
                (spec.provider_profile, spec.provider_profile_digest),
                (spec.ledger_profile, spec.ledger_profile_digest),
            ):
                exported = json.loads(
                    await self.cli.run(["provider", "profile", "export", profile, "-o", "json"])
                )
                if digest(exported) != approved:
                    raise BrokerError("policy")
            provider_inventory = json.loads(await self.cli.run(["provider", "list", "-o", "json"]))
            if provider_inventory.get("next_page_token"):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_verify category=provider_inventory")
                raise BrokerError("identity")
            provider = next(
                (
                    item
                    for item in provider_inventory["providers"]
                    if item["name"] == lease.contract.provider_binding
                ),
                None,
            )
            if (
                provider is None
                or provider.get("id") != spec.provider_native_id
                or provider.get("resource_version") != spec.provider_resource_version
                or provider.get("type") != spec.provider_profile
                or provider.get("workspace") != self.cli.workspace
            ):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_verify category=provider_identity")
                raise BrokerError("identity")
            ledger_provider = next(
                (
                    item
                    for item in provider_inventory["providers"]
                    if item.get("name") == f"ih-ledger-{lease.lease_id}"
                ),
                None,
            )
            if (
                ledger_provider is None
                or not lease.ledger_native_id
                or ledger_provider.get("id") != lease.ledger_native_id
                or ledger_provider.get("type") != spec.ledger_profile
                or ledger_provider.get("workspace") != self.cli.workspace
                or ledger_provider.get("resource_version") != 1
                or ledger_provider.get("credential_keys") != ["IH_LEDGER_TOKEN"]
            ):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_verify category=ledger_provider_identity")
                raise BrokerError("identity")
            providers = json.loads(
                await self.cli.run(["sandbox", "provider", "list", lease.name, "-o", "json"])
            )
            if providers.get("next_page_token"):
                raise BrokerError("policy")
            attached = {item["name"]: item["type"] for item in providers["providers"]}
            if attached != {
                lease.contract.provider_binding: spec.provider_profile,
                f"ih-ledger-{lease.lease_id}": spec.ledger_profile,
            }:
                raise BrokerError("policy")
            if canonical_policy(detail["policy"]) != canonical_policy(spec.approved_policy):
                raise BrokerError("policy")
            services = json.loads(await self.cli.run(["service", "list", lease.name, "-o", "json"]))
            gateway = urlsplit(self.cli.gateway)
            port = gateway.port or 443
            expected_url = f"https://{self.cli.workspace}--{lease.name}--infer.{self.cli.service_domain}:{port}/"
            expected_service = {
                "sandbox": lease.name,
                "service": "infer",
                "target_port": 8765,
                "url": expected_url,
                "workspace": self.cli.workspace,
            }
            if services.get("next_page_token") or services.get("services") != [expected_service]:
                raise BrokerError("policy")
            lease.service_endpoint = expected_url
            containers = await self.cli.containers(lease.native_id)
            by_role = {
                item["Config"]["Labels"].get("openshell.ai/isolation-role"): item
                for item in containers
            }
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
            proof = json.loads(
                await self.cli.run(
                    [
                        "sandbox",
                        "exec",
                        "--name",
                        lease.name,
                        "--no-login-shell",
                        "--no-tty",
                        "--timeout",
                        "10",
                        "--",
                        "python",
                        "-c",
                        "import json,os; s=dict(l.split(':',1) for l in open('/proc/self/status') if ':' in l); "
                        "print(json.dumps({'uid':os.getuid(),'nnp':s['NoNewPrivs'].strip(),'seccomp':s['Seccomp'].strip()}))",
                    ]
                )
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
        except BrokerError:
            raise
        except (KeyError, ValueError, TypeError):
            raise BrokerError("policy", "Native observations are incomplete") from None

    async def reconcile(self) -> None:
        # Persisted ownership is necessary; never adopt foreign resources by similar name.
        for lease in self.leases.values():
            if lease.deployment != self.deployment or lease.status != "ready":
                continue
            await self.verify(lease)

    async def revoke(self, lease: Lease) -> None:
        if self.leases.get(lease.lease_id) is not lease or lease.deployment != self.deployment:
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=lease_ownership")
            raise BrokerError("identity")
        spec = self.spec(lease.contract)
        listing = json.loads(
            await self.cli.run(
                ["sandbox", "list", "--selector", f"ih.lease={lease.lease_id}", "-o", "json"]
            )
        )
        if listing.get("next_page_token") or len(listing.get("sandboxes", [])) > 1:
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=sandbox_inventory")
            raise BrokerError("identity")
        matches = listing.get("sandboxes", [])
        if matches:
            detail = matches[0]
            if (
                not lease.native_id
                or detail.get("id") != lease.native_id
                or detail.get("name") != lease.name
                or detail.get("labels") != lease.labels()
            ):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=sandbox_identity")
                raise BrokerError("identity")
        lease.status = "revoked"
        self.store.save(lease)
        if matches:
            attached = json.loads(
                await self.cli.run(["sandbox", "provider", "list", lease.name, "-o", "json"])
            )
            if attached.get("next_page_token"):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=attachment_inventory")
                raise BrokerError("identity")
            if any(
                item.get("name") == lease.contract.provider_binding
                for item in attached.get("providers", [])
            ):
                try:
                    await self.cli.run(
                        [
                            "sandbox", "provider", "detach", lease.name,
                            lease.contract.provider_binding, "--wait",
                        ],
                        timeout=_DETACH_ACK_TIMEOUT_S,
                    )
                except BrokerError as error:
                    if error.code != "unavailable":
                        raise
                    _LOG.warning("IH_NATIVE_CLEANUP_FAILURE stage=provider_detach category=unavailable action=destroy_owned_sandbox")
                    # An unacknowledged detach can outlast the original ownership
                    # observation. Recheck before deleting anything by name.
                    current = json.loads(await self.cli.run(
                        ["sandbox", "list", "--selector", f"ih.lease={lease.lease_id}", "-o", "json"]
                    ))
                    if current.get("next_page_token") or len(current.get("sandboxes", [])) > 1:
                        _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=recheck_inventory")
                        raise BrokerError("identity") from None
                    matches = current.get("sandboxes", [])
                    if matches and (
                        matches[0].get("id") != lease.native_id
                        or matches[0].get("name") != lease.name
                        or matches[0].get("labels") != lease.labels()
                    ):
                        _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=recheck_identity")
                        raise BrokerError("identity") from None
            if matches:
                await self.cli.run(["sandbox", "delete", lease.name])
        until = time.monotonic() + 30
        while True:
            listing = json.loads(
                await self.cli.run(
                    ["sandbox", "list", "--selector", f"ih.lease={lease.lease_id}", "-o", "json"]
                )
            )
            if listing.get("next_page_token"):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=absence_inventory")
                raise BrokerError("identity")
            containers = await self.cli.containers(lease.native_id) if lease.native_id else []
            if not listing.get("sandboxes") and not containers:
                break
            if time.monotonic() >= until:
                raise BrokerError("unavailable", "Owned cleanup requires reconciliation")
            await asyncio.sleep(0.2)
        lease.status = "sandbox_deleted"
        self.store.save(lease)
        inventory = json.loads(await self.cli.run(["provider", "list", "-o", "json"]))
        if inventory.get("next_page_token"):
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=provider_inventory")
            raise BrokerError("identity")
        ledger_name = f"ih-ledger-{lease.lease_id}"
        providers = [
            item for item in inventory.get("providers", []) if item.get("name") == ledger_name
        ]
        if len(providers) > 1:
            _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=provider_duplicates")
            raise BrokerError("identity")
        if providers:
            provider = providers[0]
            if (
                not lease.ledger_native_id
                or provider.get("id") != lease.ledger_native_id
                or provider.get("type") != spec.ledger_profile
                or provider.get("workspace") != self.cli.workspace
                or provider.get("credential_keys") != ["IH_LEDGER_TOKEN"]
            ):
                _LOG.warning("IH_NATIVE_IDENTITY_FAILURE boundary=native_revoke category=ledger_provider_identity")
                raise BrokerError(
                    "identity", "Unconfirmed credential creation requires operator reconciliation"
                )
            await self.cli.run(["provider", "delete", ledger_name])
            inventory = json.loads(await self.cli.run(["provider", "list", "-o", "json"]))
            if inventory.get("next_page_token") or any(
                item.get("name") == ledger_name for item in inventory.get("providers", [])
            ):
                raise BrokerError("unavailable")
        lease.status = "deleted"
        self.store.save(lease)
