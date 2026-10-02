# Intake source guidance and bounded repair admission

Intake 1.0.4 (`intake-output-v4`) clarifies that report source ranges ascend from
`start_id` to `end_id`. Report IDs and report-line positions do not establish code
line numbers. Unsupported `start_line` or `end_line` claims must be null in their
entirety. Literal grounding, confidence, classification and source acceptance
remain unchanged; neither prompts nor retry feedback grant permissions.

The canonical builder in `intake_contracts.py` generates `intake/agent.yaml`.
The exact prior 1.0.3 specification is retained in `agent-v1.0.3.yaml`, alongside
1.0.2. Workers register all four execution identities. The new workflow marker
`intake-source-guidance-v1` selects v4 only after the existing atomic marker;
absence selects v3 with its original prompt and reservation. Existing reference
and unsupported-claim repair markers retain their original meanings and bytes.
A separate `intake-literal-line-repair-v1` marker changes feedback only after the
unchanged guard rejects missing literal code-line evidence. Historical absence
preserves legacy feedback. Valid outputs do not consume the repair marker.

Admission now allows 32,000 input tokens per request and 128,000 cumulative input
for four requests. The request count, 64,000 cumulative output, output retries,
cost ceiling and acceptance policy are unchanged. Offline SDK-shaped reconstructions
from the preserved failing responses measured next-repair bounds of 21,465 and
20,680; 32,000 gives about 49% headroom over the larger bound and room for another
similar repair. These are conservative byte-BPE reservation bounds, not observed
provider token counts or exact records of the rejected requests. They do not
prove every future repair fits. The prior v3 limits remain 20,000/80,000.

An enabled broker deployment must update the intake operator profile's
`max_input_tokens_per_request` to 32000, resolve the unchanged four-request/output
bounds against the new agent budget, and issue fresh authenticated contracts and
reservations. A backend/profile mismatch remains rejected. Existing profiles,
contracts, leases and held allocations must remain available for recovery and
must not be reassigned to a new image or configuration. This is an explicit
bounded budget increase, not a quality threshold change or benchmark promotion.

Deterministic source/repair/selector/reservation tests cover rejection and
historical compatibility. Synthetic marker tests are not actual Temporal replay.
Real provider qualification, actual historical replay and deployed admission are
`not_checked` until separately executed. No dataset labels, scorers, quality
thresholds or source guards are changed by this candidate.
