# Tool policies

One directory per toolset, each declaring the contract the tool standard
(agent-playbook §5) requires. A `tool.yaml` holds only fields something enforces: `name`,
`effect` (what the tool does to external state; sets the agent's minimum execution class),
`retry_safety`, `timeout_seconds`, `max_output_bytes` and `tools` (each `{name, effect}`).
Unknown keys are rejected, so a field cannot be declared without an enforcer.

`../runtime/capabilities.py` applies the timeout and output bound to every call:
`repo-read-only` has a 30 s timeout and a 120000-byte result bound, and `sandbox-shell` a 180 s
command deadline and an 8000-byte result. Tool implementations live in
`../runtime/capabilities.py`, `repository.py`, `symbols.py` and `target.py`; runner policy enforcement lives in `../sandbox/`.

`tool.yaml` is loaded and checked by `infosec_harness.tools.policies`, and
`tests/agents/test_tool_policies.py` asserts the declared effects are consistent with each agent's
execution class and with the toolsets it enables.
