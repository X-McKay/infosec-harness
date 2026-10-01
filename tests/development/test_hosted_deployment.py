"""Kubernetes control-plane deployment preserves trusted/sandbox separation."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_hosted_workloads_require_explicit_worker_activation_and_keep_secrets_private():
    resources = list(yaml.safe_load_all((ROOT / "deploy/k8s/control-plane/workloads.yaml").read_text()))
    assert {r["kind"] for r in resources} == {"Namespace", "ServiceAccount", "ConfigMap", "Deployment", "Service"}
    deployments = {r["metadata"]["name"]: r for r in resources if r["kind"] == "Deployment"}
    assert deployments["harness-worker"]["spec"]["replicas"] == 0
    for deployment in deployments.values():
        pod = deployment["spec"]["template"]["spec"]
        assert not pod["automountServiceAccountToken"]
        assert pod["securityContext"]["runAsNonRoot"]
        assert all("hostPath" not in volume for volume in pod["volumes"])
        container = pod["containers"][0]
        assert container["securityContext"]["readOnlyRootFilesystem"]
        assert not container["securityContext"]["allowPrivilegeEscalation"]
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert {"secretRef": {"name": "harness-service-credentials"}} in container["envFrom"]
    config = next(r["data"] for r in resources if r["kind"] == "ConfigMap")
    assert config["HARNESS_TEMPORAL_TLS"] == config["HARNESS_DATABASE_TLS"] == "true"
    assert config["HARNESS_ALLOW_INSECURE_RUNTIME"] == "false"
    assert config["HARNESS_ARTIFACT_BACKEND"] == "s3"
    assert config["HARNESS_S3_CREATE_BUCKET"] == "false"
    assert not any("KEY" in key or "PASSWORD" in key or "DATABASE_URL" in key for key in config)
    service = next(r for r in resources if r["kind"] == "Service")
    assert service["spec"]["type"] == "ClusterIP"


def test_worker_requires_verified_remote_executor_and_shared_paths():
    resources = list(yaml.safe_load_all((ROOT / "deploy/k8s/control-plane/workloads.yaml").read_text()))
    worker = next(r for r in resources if r["metadata"]["name"] == "harness-worker")
    pod = worker["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {v["name"]: v for v in container["env"]}
    assert env["DOCKER_TLS_VERIFY"]["value"] == "1"
    assert "valueFrom" in env["DOCKER_HOST"]
    assert env["TMPDIR"]["value"] == "/workspace"
    assert any(v.get("persistentVolumeClaim") for v in pod["volumes"])
    assert any(v.get("secret", {}).get("secretName") == "harness-docker-tls" for v in pod["volumes"])
