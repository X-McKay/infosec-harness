"""The seeded corpus's ground truth is *true*: the vulnerable variants really are exploitable.

`test_corpus.py` checks the corpus is internally consistent (the finding points at real
code, the sink line matches the weakness). That is structural — it would still pass if a
"vulnerable" variant had been accidentally written safe, and every expected verdict in the
manifest would then be wrong without anything failing.

These tests close that gap for Python by driving each paired variant with a reference probe
written to the real marker protocol (`skills/probe-oracle-protocol/SKILL.md`) and reading
the result through the harness's own `oracle_signals`. The vulnerable variant must fire the
oracle and the fixed variant must not, with both reaching the precondition — exactly the
signal the graph triages on.

These run in-process rather than in the sandbox, so they assert the *corpus* is sound, not
that the container isolation is. Sandbox behaviour is covered by `test_sandbox*.py` and, at
runtime, by a gVisor host.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import pickle
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import URLError
from xml.sax import SAXException

import pytest

from infosec_harness.sandbox.markers import ORACLE_PREFIX, PRECONDITION_PREFIX, SINK_RETURNED_PREFIX
from infosec_harness.sandbox.output import oracle_signals, sink_returned
from infosec_harness.settings import REPO_ROOT

CORPUS = REPO_ROOT / "eval-corpus" / "python"


def _load(case: str, variant: str):
    path = CORPUS / case / variant / "app.py"
    spec = importlib.util.spec_from_file_location(f"corpus_{case}_{variant}_{uuid.uuid4().hex}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _probe_sqli(mod, nonce: str) -> None:
    conn = mod.init_db()
    print(f"{PRECONDITION_PREFIX}{nonce}")
    rows = mod.get_user(conn, "alice' OR '1'='1")
    print(f"{SINK_RETURNED_PREFIX}{nonce}")
    # Oracle: the payload changed the query's structure, so a row the filter should have
    # excluded came back. Not "the string looked like SQL".
    if any("TOP-SECRET" in str(row) for row in rows):
        print(f"{ORACLE_PREFIX}{nonce}")


def _probe_cmdi(mod, nonce: str) -> None:
    canary = Path(tempfile.gettempdir()) / f"harness_canary_{nonce}"
    print(f"{PRECONDITION_PREFIX}{nonce}")
    with contextlib.suppress(Exception):
        mod.count_lines(f"/dev/null; touch {canary}")
        print(f"{SINK_RETURNED_PREFIX}{nonce}")
    # Oracle: the injected command actually ran (canary_file form).
    if canary.exists():
        print(f"{ORACLE_PREFIX}{nonce}")
        canary.unlink()


def _probe_pathtraversal(mod, nonce: str) -> None:
    # Plant a file the document root must not reach, then traverse to it. Using a file we
    # created keeps the oracle independent of whatever the host has in /etc.
    outside = Path(mod.BASE).parent / f"outside_{nonce}.txt"
    outside.write_bytes(f"SECRET-{nonce}".encode())
    try:
        print(f"{PRECONDITION_PREFIX}{nonce}")
        data = b""
        # The fixed variant raises to refuse the path. That is the sink running and deciding,
        # so the marker is still printed: a negative, not a probe defect.
        with contextlib.suppress(ValueError):
            data = mod.read_doc(f"../{outside.name}")
        print(f"{SINK_RETURNED_PREFIX}{nonce}")
        # Oracle: a file outside the document root was read.
        if f"SECRET-{nonce}".encode() in data:
            print(f"{ORACLE_PREFIX}{nonce}")
    finally:
        outside.unlink(missing_ok=True)


def _probe_xss(mod, nonce: str) -> None:
    print(f"{PRECONDITION_PREFIX}{nonce}")
    rendered = str(mod.render_comment(f"<script>{nonce}</script>"))
    print(f"{SINK_RETURNED_PREFIX}{nonce}")
    # Oracle: the tag survived into the output unencoded.
    if f"<script>{nonce}</script>" in rendered:
        print(f"{ORACLE_PREFIX}{nonce}")


def _probe_codeinjection(mod, nonce: str) -> None:
    # The payload is an expression, never the marker text: if the setting is *evaluated* the
    # method call runs and yields the uppercased nonce, which a data-literal parser can never
    # produce. Judging the observable effect, not that the input looked like code.
    print(f"{PRECONDITION_PREFIX}{nonce}")
    result = None
    # The fixed variant's literal parser raises on a call node. That is the sink running and
    # refusing the input, so the marker is still printed: a negative, not a probe defect.
    with contextlib.suppress(ValueError, SyntaxError):
        result = mod.compute_setting(f"{nonce!r}.upper()")
    print(f"{SINK_RETURNED_PREFIX}{nonce}")
    # Oracle: the injected expression actually executed.
    if result == nonce.upper():
        print(f"{ORACLE_PREFIX}{nonce}")


def _probe_deserialization(mod, nonce: str) -> None:
    canary = Path(tempfile.gettempdir()) / f"harness_canary_{nonce}"

    class _Gadget:
        """Harness-local benign gadget: its unpickling callback only touches the canary.

        Not a real-world chain — the point is only that the payload, not the application,
        decides what runs while the bytes are being deserialized.
        """

        def __reduce__(self):
            return (Path.touch, (canary,))

    blob = pickle.dumps(_Gadget())
    print(f"{PRECONDITION_PREFIX}{nonce}")
    # The fixed variant's allowlist refuses the class the payload names. The sink ran and
    # decided, so the marker is still printed.
    with contextlib.suppress(pickle.UnpicklingError):
        mod.load_profile(blob)
    print(f"{SINK_RETURNED_PREFIX}{nonce}")
    # Oracle: deserializing the bytes invoked the payload's own callback.
    if canary.exists():
        print(f"{ORACLE_PREFIX}{nonce}")
        canary.unlink()


def _probe_xxe(mod, nonce: str) -> None:
    # A marker file we create under the sandbox temp dir, per skills/cwe-611-xxe: the entity
    # points at that file only, never a real system path and never a URL — the probe has no
    # network, and this oracle does not need one.
    marker = Path(tempfile.gettempdir()) / f"harness_xxe_{nonce}.txt"
    marker.write_text(f"SECRET-{nonce}")
    document = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE note [<!ENTITY leak SYSTEM "file://{marker}">]>\n'
        "<note><body>&leak;</body></note>"
    )
    try:
        print(f"{PRECONDITION_PREFIX}{nonce}")
        text = ""
        # A hardened parser may instead reject the DOCTYPE outright; that refusal is the sink
        # deciding, so the marker is still printed.
        with contextlib.suppress(SAXException):
            text = mod.parse_note(document)
        print(f"{SINK_RETURNED_PREFIX}{nonce}")
        # Oracle: the parser resolved the external entity, so the file's contents came back in
        # the parsed document. Not "the XML contained a DOCTYPE".
        if f"SECRET-{nonce}" in text:
            print(f"{ORACLE_PREFIX}{nonce}")
    finally:
        marker.unlink(missing_ok=True)


def _probe_ssrf(mod, nonce: str) -> None:
    # No egress, per skills/cwe-918-ssrf: the attacker-chosen destination is a listener this
    # probe starts on loopback. The target builds its own HTTP client, so there is no
    # transport to inject — a stub would be a silent false negative, the listener is not.
    token = f"SSRF-REACHED-{nonce}"

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = token.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass  # keep the probe's stdout to the markers

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/internal/metadata"
        print(f"{PRECONDITION_PREFIX}{nonce}")
        body = ""
        # The fixed variant's allowlist raises to refuse the destination. That is the code
        # deciding, so the marker is still printed.
        with contextlib.suppress(ValueError, URLError):
            body = mod.fetch_preview(url)
        print(f"{SINK_RETURNED_PREFIX}{nonce}")
        # Oracle: the code really issued the request to the caller-chosen host and threaded
        # the response back — no allowlist or address check stopped it.
        if token in body:
            print(f"{ORACLE_PREFIX}{nonce}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


PROBES = {"sqli": _probe_sqli, "cmdi": _probe_cmdi,
          "pathtraversal": _probe_pathtraversal, "xss": _probe_xss,
          "codeinjection": _probe_codeinjection, "deserialization": _probe_deserialization,
          "xxe": _probe_xxe, "ssrf": _probe_ssrf}
PAIRS = [(case, variant, variant == "vulnerable")
         for case in PROBES for variant in ("vulnerable", "fixed")]


def _run_probe(case: str, variant: str) -> tuple[bool, bool, bool]:
    nonce = uuid.uuid4().hex
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        PROBES[case](_load(case, variant), nonce)
    output = captured.getvalue()
    fired, reached = oracle_signals(output, nonce)
    return fired, reached, sink_returned(output, nonce)


@pytest.mark.parametrize(("case", "variant", "should_fire"), PAIRS,
                         ids=[f"{c}-{v}" for c, v, _ in PAIRS])
def test_variant_fires_the_oracle_only_when_it_is_vulnerable(case, variant, should_fire):
    fired, reached, returned = _run_probe(case, variant)
    assert reached, f"{case}/{variant}: probe never reached the sink — it proves nothing"
    assert returned, (
        f"{case}/{variant}: the sink call never returned, so a negative here would be a probe "
        f"defect rather than evidence the code resisted the payload"
    )
    assert fired is should_fire, (
        f"{case}/{variant}: oracle_fired={fired}, expected {should_fire}. The corpus's "
        f"ground truth says this variant is {'exploitable' if should_fire else 'safe'}."
    )


def test_every_python_cwe_directory_has_a_reference_probe():
    """A new CWE case must come with a probe here, or its ground truth stays unchecked."""
    on_disk = {d.name for d in CORPUS.iterdir()
               if d.is_dir() and (d / "fixed").exists()}
    assert on_disk == set(PROBES), f"no reference probe for: {sorted(on_disk - set(PROBES))}"
