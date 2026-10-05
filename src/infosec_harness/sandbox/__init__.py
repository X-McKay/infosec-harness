"""Sandbox: target image builds and probe execution under gVisor.

Only the leaf constant lives here so that ``settings`` can import it without loading any
sandbox module.
"""

# The only OCI runtime that counts as isolation. Anything else needs the explicit
# insecure-development override, and the configured name is never evidence on its own: the daemon
# must register it and select it as its default (``docker.runtime_available``).
REQUIRED_RUNTIME = "runsc"
