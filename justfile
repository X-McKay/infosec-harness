set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

bootstrap:
    uv sync --all-extras --dev --locked

check:
    uv run ruff check src tests
    uv run python -m compileall -q src

test:
    uv run pytest

policy-self-test:
    uv run infosec-harness policy-self-test

sandbox-self-test:
    uv run infosec-harness sandbox-self-test

abox-worker-plan sealed_input:
    uv run infosec-harness abox-worker-plan {{sealed_input}}

abox-worker-live-self-test sealed_input:
    uv run infosec-harness abox-worker-live-self-test {{sealed_input}}

network-self-test:
    uv run infosec-harness network-self-test

observer-self-test:
    uv run infosec-harness observer-self-test

benchmark-self-test:
    uv run infosec-harness benchmark-self-test

benchmark-dry-run task_id:
    uv run infosec-harness benchmark-dry-run {{task_id}} --lane regression

evaluate-replay:
    uv run infosec-harness evaluate-replay

diff-review repo before after:
    uv run infosec-harness diff-review {{repo}} {{before}} {{after}}

context-self-test:
    uv run infosec-harness context-self-test

compare-runs left right:
    uv run infosec-harness compare-runs {{left}} {{right}}

retention-audit:
    uv run infosec-harness retention-audit

cost-reconcile run_id usage_json:
    uv run infosec-harness cost-reconcile {{run_id}} {{usage_json}}

minikube-install:
    mise install minikube

minikube-lab-bootstrap:
    ./scripts/minikube_lab.sh bootstrap

minikube-lab-status:
    ./scripts/minikube_lab.sh status

minikube-lab-context:
    ./scripts/minikube_lab.sh context

minikube-lab-kubectl *args:
    ./scripts/minikube_lab.sh kubectl {{args}}

minikube-lab-status-json:
    ./scripts/minikube_lab.sh admission-status

minikube-lab-oracle:
    ./scripts/minikube_lab.sh oracle

minikube-lab-record-experiment:
    ./scripts/minikube_lab.sh record-experiment

minikube-lab-admission:
    ./scripts/minikube_lab.sh admission-status | uv run infosec-harness minikube-lab-admission --status /dev/stdin

triage sarif repo revision *args:
    uv run infosec-harness triage {{sarif}} {{repo}} {{revision}} {{args}}

report run_id:
    uv run infosec-harness report {{run_id}}

cost-report run_id:
    uv run infosec-harness cost-report {{run_id}}

sbom:
    uv run infosec-harness sbom
