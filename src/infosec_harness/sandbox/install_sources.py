"""Static checks for explicit install sources; the build proxy owns actual egress.

This is deliberately not a shell interpreter. Literal HTTP(S) URLs in model-authored
install commands and environment values are checked without DNS or network access.
Dynamic and obfuscated commands still require the existing fail-closed build boundary.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Protocol, TypedDict
from urllib.parse import urlsplit

INSTALL_SOURCE_POLICY_VERSION = "build-install-sources/v1"
INVALID_SOURCE = "invalid or unresolved source host"
_URL = re.compile(r"https?://[^\s'\"<>`]*", re.IGNORECASE)
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class InstallSourceSpec(Protocol):
    install_commands: list[str]
    env: dict[str, str]


class InstallSourcePolicy(TypedDict):
    version: str
    approved_hosts: list[str]
    fingerprint: str


def _host(value: str) -> str | None:
    value = value.lower()
    if not value or len(value) > 253:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value if all(_LABEL.fullmatch(part) for part in value.split(".")) else None


def install_source_policy(approved_hosts: Iterable[str]) -> InstallSourcePolicy:
    """Freeze the operator host policy without credentials or repository input."""
    hosts: set[str] = set()
    for value in approved_hosts:
        host = _host(value)
        if host is None:
            raise ValueError("install-source operator policy requires plain valid hosts")
        hosts.add(host)
    policy = {"version": INSTALL_SOURCE_POLICY_VERSION, "approved_hosts": sorted(hosts)}
    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return {
        "version": INSTALL_SOURCE_POLICY_VERSION,
        "approved_hosts": sorted(hosts),
        "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(),
    }


def unapproved_install_sources(
    spec: InstallSourceSpec, approved_hosts: Iterable[str]
) -> tuple[str, ...]:
    """Return bounded host-only violations, never source URLs or parser exceptions."""
    allowed = frozenset(install_source_policy(approved_hosts)["approved_hosts"])
    rejected: set[str] = set()
    for text in (*spec.install_commands, *spec.env.values()):
        for match in _URL.finditer(text):
            source = match.group()
            try:
                if "\\" in source or any(ord(char) < 32 for char in source):
                    raise ValueError
                parsed = urlsplit(source)
                # Validate the port as well: urllib otherwise postpones malformed-port errors.
                _ = parsed.port
                host = _host(parsed.hostname or "")
            except ValueError:
                host = None
            if host is None:
                rejected.add(INVALID_SOURCE)
            elif host not in allowed:
                rejected.add(host)
    return tuple(sorted(rejected))
