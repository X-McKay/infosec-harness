#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
state_root="$repo_root/.harness/minikube"
minikube_home="$state_root/home"
kubeconfig="$state_root/kubeconfig"
# A path-derived suffix avoids colliding with a similarly named Minikube Docker
# container from another checkout while keeping repeated invocations in this
# checkout on the same profile.
profile="infosec-harness-$(printf '%s' "$repo_root" | sha256sum | cut -c1-12)"
namespace="infosec-harness-lab"

# Do not merge with or mutate the user's normal Minikube/Kubernetes state.
# Every kubectl invocation also supplies --kubeconfig explicitly as defense in
# depth, including subprocesses started by the Python evidence recorder.
umask 077
install -d -m 700 "$state_root" "$minikube_home"
if [[ -L "$kubeconfig" ]]; then
  echo "refusing symlinked repository kubeconfig: $kubeconfig" >&2
  exit 1
fi
touch "$kubeconfig"
chmod 600 "$kubeconfig"
export MINIKUBE_HOME="$minikube_home"
export KUBECONFIG="$kubeconfig"

kubectl_lab() {
  kubectl --kubeconfig "$kubeconfig" --context "$profile" "$@"
}

if ! command -v minikube >/dev/null; then
  echo "minikube v1.38.1 is required; install the checksum-verified binary before bootstrapping" >&2
  exit 1
fi
if ! minikube version --short | grep -qx 'v1.38.1'; then
  echo "minikube v1.38.1 is required for this pinned local profile" >&2
  exit 1
fi

command="${1:-}"
if [[ "$#" -gt 0 ]]; then
  shift
fi

case "$command" in
  bootstrap)
    minikube start -p "$profile" --driver=docker --container-runtime=containerd --kubernetes-version=v1.35.1 --cni=kindnet --cpus=2 --memory=4096 --disk-size=20g --embed-certs
    chmod 600 "$kubeconfig"
    kubectl_lab apply -k infra/minikube
    kubectl_lab -n "$namespace" wait --for=jsonpath='{.status.phase}'=Succeeded pod/noexec-worker-self-test --timeout=90s
    kubectl_lab -n "$namespace" rollout status deployment/synthetic-oracle --timeout=90s
    ;;
  status)
    minikube status -p "$profile"
    kubectl_lab -n "$namespace" get pod,networkpolicy
    ;;
  context)
    printf 'profile=%s\nkubeconfig=%s\nminikube_home=%s\nnamespace=%s\n' \
      "$profile" "$kubeconfig" "$minikube_home" "$namespace"
    ;;
  kubectl)
    if [[ "$#" -eq 0 ]]; then
      echo "usage: $0 kubectl <kubectl arguments>" >&2
      exit 2
    fi
    kubectl_lab "$@"
    ;;
  admission-status)
    cluster_running=false
    namespace_ready=false
    default_deny=false
    oracle_healthy=false
    if minikube status -p "$profile" --output=json >/dev/null 2>&1; then
      cluster_running=true
    fi
    if [[ "$(kubectl_lab get namespace "$namespace" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || true)" == "restricted" ]]; then
      namespace_ready=true
    fi
    if kubectl_lab -n "$namespace" get networkpolicy default-deny-ingress-egress >/dev/null 2>&1; then
      default_deny=true
    fi
    if [[ "$(kubectl_lab -n "$namespace" get deployment synthetic-oracle -o jsonpath='{.status.availableReplicas}' 2>/dev/null || true)" == "1" ]] \
      && [[ "$(kubectl_lab -n "$namespace" get job synthetic-approved-probe -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || true)" == "True" ]] \
      && [[ "$(kubectl_lab -n "$namespace" get job synthetic-denied-probe -o jsonpath='{.status.conditions[?(@.type=="Complete")].status}' 2>/dev/null || true)" == "True" ]]; then
      oracle_healthy=true
    fi
    printf '{"profile":"%s","minikube_version":"%s","cluster_running":%s,"namespace_ready":%s,"default_deny_enforced":%s,"observer_healthy":false,"observer_mode":"unavailable","synthetic_oracle_healthy":%s,"collected_at":"%s"}\n' \
      "$profile" "$(minikube version --short)" "$cluster_running" "$namespace_ready" "$default_deny" "$oracle_healthy" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ;;
  oracle)
    # These jobs are synthetic controller-owned probes, not target workloads.
    # Their opposite expected outcomes establish whether the selected CNI is
    # enforcing the deny-by-default policy, but do not replace host observation.
    kubectl_lab -n "$namespace" rollout status deployment/synthetic-oracle --timeout=90s
    oracle_cluster_ip="$(kubectl_lab -n "$namespace" get service synthetic-oracle -o jsonpath='{.spec.clusterIP}')"
    if [[ ! "$oracle_cluster_ip" =~ ^[0-9.]+$ ]]; then
      echo "synthetic oracle has no IPv4 ClusterIP" >&2
      exit 1
    fi
    kubectl_lab -n "$namespace" create configmap synthetic-oracle-target \
      --from-literal="cluster_ip=$oracle_cluster_ip" --dry-run=client -o yaml | kubectl_lab apply -f -
    kubectl_lab -n "$namespace" delete job synthetic-approved-probe synthetic-denied-probe --ignore-not-found
    kubectl_lab apply -f infra/kubernetes/probes/oracle-probes.yaml
    set +e
    kubectl_lab -n "$namespace" wait --for=condition=complete job/synthetic-approved-probe --timeout=45s
    approved_status=$?
    kubectl_lab -n "$namespace" wait --for=condition=complete job/synthetic-denied-probe --timeout=45s
    denied_status=$?
    set -e
    if [[ "$approved_status" -eq 0 && "$denied_status" -eq 0 ]]; then
      uv run infosec-harness minikube-lab-record-experiment --profile "$profile" --namespace "$namespace"
      echo '{"oracle_healthy":true,"policy_enforced":true,"note":"synthetic allow and deny probes matched expectations"}'
      exit 0
    fi
    echo '{"oracle_healthy":false,"policy_enforced":false,"note":"synthetic probes did not establish enforced allow/deny policy"}'
    exit 3
    ;;
  record-experiment)
    uv run infosec-harness minikube-lab-record-experiment --profile "$profile" --namespace "$namespace"
    ;;
  *)
    echo "usage: $0 {bootstrap|status|context|kubectl|admission-status|oracle|record-experiment}" >&2
    exit 2
    ;;
esac
