# Verification

Top-level tests cover contracts, source confinement, bounded processes, agent tools,
model serialization, API state projection, evidence gates, native adapter admission and
full-cohort evaluation accounting. Temporal tests start the pinned real local service to
exercise replay, restart, cancellation and unknown execution. Set
`HARNESS_TEST_REQUIRE_TEMPORAL=1` to make missing Temporal a failure rather than a skip.

Ordinary tests block ambient model requests. `harness qualify` supplies separate native
OpenShell evidence; `harness eval --allow-inference` supplies separately authorized live
model evidence. Mocked tests never stand in for either gate.
