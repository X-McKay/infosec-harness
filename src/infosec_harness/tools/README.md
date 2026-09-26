# Tool policies

One directory per toolset, each declaring the contract the tool standard
(agent-playbook §5) requires: what the tool *does* to external state, whether retrying it is
safe, its timeout, and the data it handles.

The implementations live in `../agents/capabilities.py`, because pydantic-ai capabilities have
to be built once and compared by identity for durable execution. These directories carry the
**policy**, which was previously nowhere: nothing in the system declared that
`run_in_sandbox` executes code while `read_file` only observes, even though that difference is
what sets the minimum execution class for every agent that enables it.

`tool.yaml` is loaded and checked by `infosec_harness.tools.policies`, and
`tests/test_tool_policies.py` asserts the declared effects are consistent with each agent's
execution class and with the toolsets it enables.
