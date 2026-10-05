"""The stdout markers a probe (or the harness's own control test) prints, one definition.

Probe templates, the control tests in ``canary``, the probe run script in ``docker`` and the
parsers in ``output`` all read these constants; none of them spells a marker literally.
"""

from __future__ import annotations

# Printed when the probe has set up the exploit condition and is about to call the sink.
PRECONDITION_PREFIX = "HARNESS_PRECONDITION::"
# Printed *after* the sink call returns. The precondition marker is printed before it, so on
# its own it proves the probe meant to call the sink, not that the call completed: a probe that
# threw or swallowed an error in between is indistinguishable from one the code resisted. That
# produced a measured false negative on javascript-cmdi-vulnerable, the costliest error class
# this system has.
SINK_RETURNED_PREFIX = "HARNESS_SINK_RETURNED::"
# Printed when the exploit condition was observed.
ORACLE_PREFIX = "HARNESS_ORACLE::"
# File oracle: a probe that cannot print may instead create /tmp/<FILE_ORACLE_NAME_PREFIX><nonce>;
# the probe run script then echoes CANARY_PREFIX<nonce> on its behalf.
FILE_ORACLE_NAME_PREFIX = "harness_canary_"
CANARY_PREFIX = "HARNESS_CANARY_PRESENT::"
