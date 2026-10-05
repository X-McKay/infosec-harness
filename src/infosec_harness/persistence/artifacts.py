"""Content-addressed artifact store (D5): filesystem locally, S3/MinIO when configured.

Callers store bytes and get back a ``sha256:...`` ref; the DB keeps refs, not bytes.
"""

from __future__ import annotations

import hashlib
import re
from functools import lru_cache
from pathlib import Path

from infosec_harness._io import atomic_write_bytes
from infosec_harness.persistence.paths import workspace_dir
from infosec_harness.settings import get_settings

_REF = re.compile(r"^sha256:([0-9a-f]{64})$")


class ArtifactError(RuntimeError):
    """Base class for an artifact reference that cannot supply trustworthy bytes."""


class InvalidArtifactReference(ArtifactError):
    """The reference is not a canonical SHA-256 content address."""


class ArtifactMissingError(ArtifactError):
    """The referenced content-addressed object is no longer retained."""


class ArtifactIntegrityError(ArtifactError):
    """The stored bytes do not match the digest in their reference."""


def _digest_from_ref(ref: str) -> str:
    match = _REF.fullmatch(ref)
    if match is None:
        raise InvalidArtifactReference(
            "artifact reference must be 'sha256:' followed by 64 lowercase hexadecimal digits"
        )
    return match.group(1)


def _verify(ref: str, data: bytes) -> bytes:
    expected = _digest_from_ref(ref)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise ArtifactIntegrityError(
            f"artifact {ref} is corrupt: stored content has sha256:{actual}"
        )
    return data


class ArtifactStore:
    def put_text(self, text: str, *, media_type: str = "text/plain") -> str:
        return self.put_bytes(text.encode(), media_type=media_type)

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:  # pragma: no cover
        raise NotImplementedError

    def get_bytes(self, ref: str) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def delete(self, ref: str) -> None:  # pragma: no cover
        """Explicitly delete one shared object; callers must first retire every referencing run."""
        raise NotImplementedError

    def get_text(self, ref: str) -> str:
        return self.get_bytes(ref).decode(errors="replace")


class FilesystemStore(ArtifactStore):
    def __init__(self) -> None:
        self.root = workspace_dir() / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        return self.root / digest[:2] / digest[2:]

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = hashlib.sha256(data).hexdigest()
        p = self._path(digest)
        p.parent.mkdir(parents=True, exist_ok=True)
        # Publish atomically. Concurrent writers produce the same bytes for this key, and a put
        # repairs an object whose contents were damaged out of band.
        atomic_write_bytes(p, data)
        return f"sha256:{digest}"

    def get_bytes(self, ref: str) -> bytes:
        digest = _digest_from_ref(ref)
        try:
            data = self._path(digest).read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactMissingError(f"artifact {ref} is not retained") from exc
        return _verify(ref, data)

    def delete(self, ref: str) -> None:
        digest = _digest_from_ref(ref)
        self._path(digest).unlink(missing_ok=True)


class S3Store(ArtifactStore):
    def __init__(self) -> None:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError

        s = get_settings()
        self.bucket = s.s3_bucket
        self._client = boto3.client(
            "s3", endpoint_url=s.s3_endpoint or None, region_name=s.s3_region,
            aws_access_key_id=s.s3_access_key or None, aws_secret_access_key=s.s3_secret_key or None,
            aws_session_token=s.s3_session_token or None,
            verify=str(s.s3_ca_file) if s.s3_ca_file else True,
            config=Config(s3={"addressing_style": s.s3_addressing_style}),
        )
        try:
            self._client.head_bucket(Bucket=self.bucket)
        except ClientError as error:
            response = error.response
            code = str(response.get("Error", {}).get("Code", ""))
            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            missing = code in {"404", "NoSuchBucket"} or status == 404
            if ((status is not None and status != 404) or code in {"403", "AccessDenied"}
                    or not missing or not s.s3_create_bucket):
                raise
            request = {"Bucket": self.bucket}
            if s.s3_region != "us-east-1":
                request["CreateBucketConfiguration"] = {"LocationConstraint": s.s3_region}
            self._client.create_bucket(**request)

    def _key(self, digest: str) -> str:
        return f"{digest[:2]}/{digest[2:]}"

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = hashlib.sha256(data).hexdigest()
        self._client.put_object(Bucket=self.bucket, Key=self._key(digest), Body=data, ContentType=media_type)
        return f"sha256:{digest}"

    def get_bytes(self, ref: str) -> bytes:
        digest = _digest_from_ref(ref)
        try:
            obj = self._client.get_object(Bucket=self.bucket, Key=self._key(digest))
        except Exception as exc:
            response = getattr(exc, "response", {})
            code = str(response.get("Error", {}).get("Code", ""))
            if code in {"404", "NoSuchKey", "NotFound"}:
                raise ArtifactMissingError(f"artifact {ref} is not retained") from exc
            raise
        body = obj["Body"]
        try:
            data = body.read()
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close()
        return _verify(ref, data)

    def delete(self, ref: str) -> None:
        digest = _digest_from_ref(ref)
        self._client.delete_object(Bucket=self.bucket, Key=self._key(digest))


@lru_cache
def get_store() -> ArtifactStore:
    settings = get_settings()
    backend = settings.artifact_backend
    if backend == "s3" or (backend == "auto" and settings.s3_endpoint):
        return S3Store()
    return FilesystemStore()
