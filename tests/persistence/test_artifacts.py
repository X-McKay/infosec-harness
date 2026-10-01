from __future__ import annotations

import hashlib
from io import BytesIO

import pytest

from infosec_harness.persistence import artifacts


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(artifacts, "default_workspace", lambda: tmp_path)
    return artifacts.FilesystemStore()


def test_filesystem_artifacts_are_verified_retained_and_explicitly_deleted(store):
    ref = store.put_bytes(b"retained evidence")

    assert store.get_bytes(ref) == b"retained evidence"
    assert store.get_text(ref) == "retained evidence"

    store.delete(ref)
    store.delete(ref)  # Explicit deletion is idempotent for maintenance retries.
    with pytest.raises(artifacts.ArtifactMissingError, match="not retained"):
        store.get_bytes(ref)


def test_filesystem_artifact_corruption_is_detected_and_put_repairs_it(store):
    body = b"trusted evidence"
    ref = store.put_bytes(body)
    digest = ref.removeprefix("sha256:")
    store._path(digest).write_bytes(b"corrupted")

    with pytest.raises(artifacts.ArtifactIntegrityError, match="is corrupt"):
        store.get_bytes(ref)

    assert store.put_bytes(body) == ref
    assert store.get_bytes(ref) == body


@pytest.mark.parametrize("ref", ["", "sha256:abc", "../escape", "sha256:" + "A" * 64])
def test_artifact_references_are_canonical_and_cannot_escape_the_store(store, ref):
    with pytest.raises(artifacts.InvalidArtifactReference):
        store.get_bytes(ref)
    with pytest.raises(artifacts.InvalidArtifactReference):
        store.delete(ref)


class _MissingObject(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class _FakeS3:
    def __init__(self, objects=None):
        self.objects = objects or {}
        self.deleted = []
        self.returned_bodies = []

    def get_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise _MissingObject
        body = BytesIO(self.objects[Key])
        self.returned_bodies.append(body)
        return {"Body": body}

    def delete_object(self, *, Bucket, Key):
        self.deleted.append((Bucket, Key))


def _s3_store(client):
    store = artifacts.S3Store.__new__(artifacts.S3Store)
    store.bucket = "evidence"
    store._client = client
    return store


def test_s3_artifact_reads_verify_content_and_report_missing_objects():
    body = b"remote evidence"
    digest = hashlib.sha256(body).hexdigest()
    ref = f"sha256:{digest}"
    key = f"{digest[:2]}/{digest[2:]}"
    client = _FakeS3({key: body})
    store = _s3_store(client)

    assert store.get_bytes(ref) == body
    client.objects[key] = b"wrong"
    with pytest.raises(artifacts.ArtifactIntegrityError):
        store.get_bytes(ref)
    assert all(body.closed for body in client.returned_bodies)
    with pytest.raises(artifacts.ArtifactMissingError, match="not retained"):
        store.get_bytes("sha256:" + "0" * 64)

    store.delete(ref)
    assert client.deleted == [("evidence", key)]
