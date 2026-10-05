# Runtime architecture and boundaries

One Temporal workflow owns one investigation. PydanticAI's native Temporal integration
records model and tool activity results and resumes the agent loop after worker loss.
The investigator uses read/search/write/execute/run_probe tools and dynamically loaded skills;
there is no hard-coded sequence of reconnaissance, planner, builder and verdict agents.

`repository.py` captures approved source without executing its hooks. `agent.py` exposes
a narrow toolbox. `workflow.py` prepares the workspace, runs the agent, validates its
verdict against receipts and citations, and cleans up. `models.py` contains strict inputs
and results. `web.py` projects Temporal state; it does not maintain a second job ledger.

OpenShell owns three native profiles:

| Profile | Code and permissions |
| --- | --- |
| workspace | Untrusted repository and generated experiments; narrowly allowed package egress; no model provider |
| probe | Fresh copy of the prepared workspace; no external network or provider |
| model | Only the small model executor and dependencies; explicit provider; no repository execution |

The trusted worker controls profiles. Model instructions cannot change policy, credentials,
images or limits. Provider credentials remain inside the native model boundary. The model
executor accepts serialized PydanticAI requests, makes one provider attempt and returns a
bounded response. There is no application credential-broker protocol or model catalogue.

`openshell.py` validates native policy and provider admission, pins images and verifies
actual workload properties. OpenShell v0.1.2's API does not expose all outer isolation
properties, so a dedicated-daemon Docker inspector reads the exact native-owned containers.
It cannot serve as an execution fallback. The checks include namespaces, mounts, non-root
identity, capability removal, seccomp, no-new-privileges, network and cgroup limits.

Command delivery is an external effect. A durable local receipt fence is fsynced before
sending it. Completed results can be reused; an interrupted dispatch with no terminal
receipt is unknown and is never blindly resent. The receipt directory and source snapshots
must survive worker restart and be available to any worker servicing this queue. Use a
single worker or shared durable storage with atomic exclusive-create semantics. Losing
this storage is not a recoverable replay guarantee.

Each probe runs in a separate offline sandbox. Before copying and after running it, the
runtime checks the original source against the captured snapshot. A definitive result
requires valid source citations, cited successful probe receipts, untruncated output,
source verification and explicit target, positive-control and negative-control observations.
The observations are self-reported by the authored experiment. They do not prove semantic
correctness, and a post-execution check cannot detect modification followed by restoration.
These limits require adversarial live evaluation rather than stronger claims from metadata.

Budgets bound model requests, tokens, tool calls, individual commands, transfers, outputs
and total workflow time. Cancellation reaches owned activities and cleanup. Tests exercise
real local Temporal replay, worker restart, deadline and unknown-delivery behavior, separately
from mocked OpenShell checks and actual native qualification.

Workflow generation v9 breaks compatibility with the former staged graph. Drain old task
queues before changing workers. The API lists this generation's investigations only.
