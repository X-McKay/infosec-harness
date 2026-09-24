"""Content-addressed artifact store (D5): filesystem locally, S3/MinIO when configured.

Callers store bytes and get back a ``sha256:...`` ref; the DB keeps refs, not bytes.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from infosec_harness.sandbox.docker import default_workspace
from infosec_harness.settings import get_settings


class ArtifactStore:
    def put_text(self, text: str, *, media_type: str = "text/plain") -> str:
        return self.put_bytes(text.encode(), media_type=media_type)

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:  # pragma: no cover
        raise NotImplementedError

    def get_bytes(self, ref: str) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def get_text(self, ref: str) -> str:
        return self.get_bytes(ref).decode(errors="replace")


class FilesystemStore(ArtifactStore):
    def __init__(self) -> None:
        self.root = default_workspace() / "artifacts"
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str):
        return self.root / digest[:2] / digest[2:]

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = hashlib.sha256(data).hexdigest()
        p = self._path(digest)
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_bytes(data)
        return f"sha256:{digest}"

    def get_bytes(self, ref: str) -> bytes:
        return self._path(ref.removeprefix("sha256:")).read_bytes()


class S3Store(ArtifactStore):
    def __init__(self) -> None:
        import boto3

        s = get_settings()
        self.bucket = s.s3_bucket
        self._client = boto3.client(
            "s3", endpoint_url=s.s3_endpoint or None, region_name=s.s3_region,
            aws_access_key_id=s.s3_access_key or None, aws_secret_access_key=s.s3_secret_key or None,
        )
        try:
            self._client.head_bucket(Bucket=self.bucket)
        except Exception:
            self._client.create_bucket(Bucket=self.bucket)

    def _key(self, digest: str) -> str:
        return f"{digest[:2]}/{digest[2:]}"

    def put_bytes(self, data: bytes, *, media_type: str = "application/octet-stream") -> str:
        digest = hashlib.sha256(data).hexdigest()
        self._client.put_object(Bucket=self.bucket, Key=self._key(digest), Body=data, ContentType=media_type)
        return f"sha256:{digest}"

    def get_bytes(self, ref: str) -> bytes:
        obj = self._client.get_object(Bucket=self.bucket, Key=self._key(ref.removeprefix("sha256:")))
        return obj["Body"].read()


@lru_cache
def get_store() -> ArtifactStore:
    return S3Store() if get_settings().s3_endpoint else FilesystemStore()
