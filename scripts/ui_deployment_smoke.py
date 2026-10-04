#!/usr/bin/env python3
"""Read-only deployment checks for the actual UI and its same-origin API proxy."""
from __future__ import annotations

import argparse
import json
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import TypeAdapter

from infosec_harness.agents.registry import AGENT_BINDINGS
from infosec_harness.api.contracts import (
    BatchSummary,
    ExperimentSummary,
    MetricsResponse,
    QualificationStatus,
    RunSummary,
    RuntimeStatus,
)


class SmokeFailure(ValueError):
    """Closed failure label; response bodies and transport exceptions remain private."""


def base_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError as exc:
        raise SmokeFailure("invalid endpoint") from exc
    if (any(character.isspace() for character in value) or parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment):
        raise SmokeFailure("invalid endpoint")
    return value.rstrip("/")


class Assets(HTMLParser):
    def __init__(self):
        super().__init__()
        self.root = False
        self.scripts = []
        self.styles = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.root |= tag == "div" and attrs.get("id") == "root"
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag == "link" and "stylesheet" in attrs.get("rel", "").split() and attrs.get("href"):
            self.styles.append(attrs["href"])


def check(api_url, web_url, *, timeout=60, expected_source_commit=None,
          expected_model_mode=None, expected_transport=None, client=None):
    api_url, web_url = base_url(api_url), base_url(web_url)
    if not 1 <= timeout <= 300:
        raise SmokeFailure("invalid timeout")
    if expected_source_commit is not None and not re.fullmatch("[a-f0-9]{40}", expected_source_commit):
        raise SmokeFailure("invalid expected source")
    deadline = time.monotonic() + timeout

    def fetch(url, kind):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SmokeFailure("deadline exceeded")
        try:
            with transport.stream("GET", url, timeout=min(5, remaining)) as response:
                if response.status_code != 200:
                    raise SmokeFailure("HTTP check failed")
                content_type = response.headers.get("content-type", "").split(";")[0]
                allowed = {"json": {"application/json"}, "html": {"text/html"},
                           "js": {"text/javascript", "application/javascript"},
                           "css": {"text/css"}}[kind]
                if content_type not in allowed:
                    raise SmokeFailure("unexpected content type")
                body = bytearray()
                for chunk in response.iter_bytes():
                    if time.monotonic() >= deadline:
                        raise SmokeFailure("deadline exceeded")
                    body.extend(chunk)
                    if len(body) > 5 * 1024 * 1024:
                        raise SmokeFailure("response too large")
                return bytes(body)
        except httpx.HTTPError as exc:
            raise SmokeFailure("transport check failed") from exc

    owned = client is None
    transport = client or httpx.Client(trust_env=False, follow_redirects=False)
    try:
        observed = []
        counts = {}
        for origin in (api_url, web_url):
            try:
                runtime = RuntimeStatus.model_validate_json(fetch(origin + "/api/runtime-status", "json"))
                qualification = QualificationStatus.model_validate_json(fetch(origin + "/api/qualification", "json"))
                agents = [row.agent for row in qualification.components]
                if (len(agents) != len(AGENT_BINDINGS) or set(agents) != set(AGENT_BINDINGS)
                        or any(row.scope != "agent_semantics" for row in qualification.components)):
                    raise SmokeFailure("incomplete component inventory")
                for actual, expected in ((runtime.api_source_commit, expected_source_commit),
                                         (runtime.model_mode, expected_model_mode),
                                         (runtime.assessment_transport, expected_transport)):
                    if expected is not None and actual != expected:
                        raise SmokeFailure("deployment identity mismatch")
                observed.append((runtime.api_source_commit, runtime.model_mode,
                                 runtime.assessment_transport))
                for path, model in (("batches", BatchSummary), ("runs", RunSummary),
                                    ("experiments", ExperimentSummary)):
                    rows = TypeAdapter(list[model]).validate_json(fetch(
                        origin + f"/api/{path}?population=operational", "json"))
                    counts[path] = len(rows)
                metrics = MetricsResponse.model_validate_json(fetch(
                    origin + "/api/metrics?population=operational", "json"))
                if metrics.population != "operational":
                    raise SmokeFailure("unexpected metrics population")
            except SmokeFailure:
                raise
            except (ValueError, TypeError, KeyError) as exc:
                raise SmokeFailure("invalid API contract") from exc
        if observed[0] != observed[1]:
            raise SmokeFailure("proxy identity mismatch")
        assets = set()
        for path in ("/", "/qualification", "/experiments"):
            parser = Assets()
            try:
                parser.feed(fetch(web_url + path, "html").decode("utf-8"))
            except UnicodeError as exc:
                raise SmokeFailure("invalid HTML") from exc
            if not parser.root or not parser.scripts:
                raise SmokeFailure("missing application shell")
            for kind, references in (("js", parser.scripts), ("css", parser.styles)):
                for reference in references:
                    url = urljoin(web_url + path, reference)
                    parts, expected = urlsplit(url), urlsplit(web_url)
                    if (parts.scheme, parts.netloc) != (expected.scheme, expected.netloc) or parts.fragment or parts.username:
                        raise SmokeFailure("external asset reference")
                    assets.add((url, kind))
                    if len(assets) > 64:
                        raise SmokeFailure("too many asset references")
        for url, kind in sorted(assets):
            if not fetch(url, kind):
                raise SmokeFailure("empty asset")
        return {"status": "passed", "components": len(AGENT_BINDINGS),
                "operational_counts": counts, "assets": len(assets), "writes": 0}
    finally:
        if owned:
            transport.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--web-url", required=True)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--expected-model-mode", choices=("live", "stub"))
    parser.add_argument("--expected-transport", choices=("brokered", "direct"))
    args = parser.parse_args(argv)
    try:
        print(json.dumps(check(**vars(args)), sort_keys=True))
        return 0
    except SmokeFailure as exc:
        print(json.dumps({"status": "failed", "reason": str(exc), "writes": 0}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
