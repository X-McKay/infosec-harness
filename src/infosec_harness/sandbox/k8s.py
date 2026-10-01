"""Render hardened Kubernetes probe Pod specifications; no submission runner is implemented.

The Docker runner remains the execution path. These specifications support deployment design
and deterministic policy tests, and do not establish actual cluster isolation.
"""

from __future__ import annotations

from typing import Any

from infosec_harness.settings import get_settings

SANDBOX_UID = 10001


def render_probe_pod(name: str, image: str, script: str, namespace: str = "harness-sandbox",
                     runtime_class: str = "gvisor") -> dict[str, Any]:
    """Render the Pod spec for one probe run. Hardening mirrors the Docker runner:
    gVisor RuntimeClass, no network (a default-deny NetworkPolicy in the namespace), no
    service-account token, non-root, all capabilities dropped, read-only root + tmpfs work
    dirs, and resource limits."""
    s = get_settings()
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace,
                     "labels": {"app": "harness-probe"}},
        "spec": {
            "runtimeClassName": runtime_class,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "enableServiceLinks": False,
            "securityContext": {"runAsNonRoot": True, "runAsUser": SANDBOX_UID,
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{
                "name": "probe",
                "image": image,
                "command": ["sh", "-c", script],
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": s.sandbox_read_only_root,
                    "capabilities": {"drop": ["ALL"]},
                },
                "resources": {"limits": {"cpu": s.sandbox_cpus, "memory": s.sandbox_memory,
                                         "ephemeral-storage": "1Gi"}},
                "volumeMounts": [{"name": "work", "mountPath": "/work"},
                                 {"name": "tmp", "mountPath": "/tmp"}],
            }],
            "volumes": [{"name": "work", "emptyDir": {"medium": "Memory", "sizeLimit": "256Mi"}},
                        {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
            "activeDeadlineSeconds": s.sandbox_probe_timeout_s,
        },
    }
