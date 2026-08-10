"""Pure policy helpers: paths, budgets, signatures, and conservative redaction."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .domain import AuthorizationManifest, Budget, EgressPolicy, PolicyDecision, Usage

_SECRET = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[^\s'\"]{6,}")
INPUT_TOKEN_COST = 0.000001
OUTPUT_TOKEN_COST = 0.000002


class PolicyError(ValueError):
    pass


def digest(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def canonical_path(root: Path, requested: str) -> Path:
    if "\x00" in requested:
        raise PolicyError("NUL in path")
    root = root.resolve(strict=True)
    candidate = (root / requested).resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise PolicyError("path escapes authorized repository") from exc
    if candidate.is_symlink():
        candidate = candidate.resolve(strict=True)
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise PolicyError("symlink escapes authorized repository") from exc
    return candidate


def redact(text: str) -> tuple[str, list[str]]:
    fingerprints: list[str] = []

    def replacement(match: re.Match[str]) -> str:
        fingerprints.append(digest(match.group(0))[:20])
        return "[REDACTED_SECRET]"

    return _SECRET.sub(replacement, text), fingerprints


def check_usage(budget: Budget, usage: Usage) -> None:
    if usage.input_tokens > budget.max_input_tokens or usage.output_tokens > budget.max_output_tokens:
        raise PolicyError("token budget exhausted")


def estimated_cost(usage: Usage) -> float:
    return round(usage.input_tokens * INPUT_TOKEN_COST + usage.output_tokens * OUTPUT_TOKEN_COST, 6)


def check_budget(budget: Budget, usage: Usage) -> None:
    check_usage(budget, usage)
    if estimated_cost(usage) > budget.max_cost_usd:
        raise PolicyError("cost budget exhausted")


def tool_decision(action: str, subject: str, allowed: bool, reason: str) -> PolicyDecision:
    subject_hash = digest(subject)
    decision_id = digest(f"{action}|{subject_hash}|{allowed}|{reason}")[:24]
    return PolicyDecision(
        decision_id=decision_id,
        allowed=allowed,
        action=action,
        reason=reason,
        subject_hash=subject_hash,
    )


def signed_deny_egress_policy(run_id: str, key: bytes = b"local-fixture-key") -> EgressPolicy:
    expires_at = datetime.now(UTC) + timedelta(minutes=5)
    payload = f"{run_id}|{expires_at.isoformat()}|deny"
    signature = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return EgressPolicy(run_id=run_id, expires_at=expires_at, signature=signature)


def verify_egress_policy(policy: EgressPolicy, key: bytes = b"local-fixture-key") -> bool:
    payload = f"{policy.run_id}|{policy.expires_at.isoformat()}|deny"
    expected = hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()
    return policy.default_deny and policy.expires_at > datetime.now(UTC) and hmac.compare_digest(
        policy.signature, expected
    )


def authorization_payload(manifest: AuthorizationManifest) -> str:
    return manifest.model_dump_json(exclude={"signature"}, by_alias=True)


def sign_authorization(manifest: AuthorizationManifest, key: bytes = b"local-fixture-key") -> str:
    return hmac.new(key, authorization_payload(manifest).encode(), hashlib.sha256).hexdigest()


def verify_authorization(
    manifest: AuthorizationManifest,
    *,
    manifest_path: Path,
    repo: Path,
    revision: str,
    key: bytes = b"local-fixture-key",
) -> None:
    if manifest.expires_at <= datetime.now(UTC):
        raise PolicyError("authorization manifest expired")
    if not hmac.compare_digest(manifest.signature, sign_authorization(manifest, key)):
        raise PolicyError("authorization signature invalid")
    if manifest.revision != revision:
        raise PolicyError("authorization revision mismatch")
    try:
        expected_repo = canonical_path(manifest_path.parent, manifest.target_repository)
    except PolicyError as exc:
        raise PolicyError("authorization repository path invalid") from exc
    if expected_repo != repo.resolve(strict=True):
        raise PolicyError("authorization repository is outside manifest")
    if "read" not in manifest.allowed_actions:
        raise PolicyError("authorization does not permit read-only evidence collection")


def load_authorization(path: Path) -> AuthorizationManifest:
    try:
        return AuthorizationManifest.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError) as exc:
        raise PolicyError("authorization manifest cannot be loaded") from exc
