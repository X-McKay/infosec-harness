"""Sandbox failure classes. A leaf module: every sandbox module may raise these."""

from __future__ import annotations


class SandboxUnavailable(RuntimeError):
    """Raised when the required isolation runtime is not available and not overridden."""


class DisallowedBaseImage(ValueError):
    """Raised when an EnvironmentSpec names a base image outside the allowlist."""


class InvalidEnvironmentSpec(ValueError):
    """Raised when generated build fields could change Dockerfile structure or escape scope."""
