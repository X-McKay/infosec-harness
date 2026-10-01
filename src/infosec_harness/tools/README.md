# Tool policies

One directory per toolset, each declaring the contract the tool standard
(agent-playbook §5) requires: what the tool *does* to external state, whether retrying it is
safe, its timeout, and the data it handles.

Tool implementations live in `../agents/capabilities.py`, `../agents/repo_tools.py` and
`../agents/symbol_inspection.py`; runner policy enforcement lives in `../sandbox/`.
These directories contain packaged policy data, rather than tool implementations.
Capabilities are constructed consistently for durable execution.

`tool.yaml` is loaded and checked by `infosec_harness.tools.policies`, and
`tests/agents/test_tool_policies.py` asserts the declared effects are consistent with each agent's
execution class and with the toolsets it enables.
