# Target reachability feedback — 2026-10-05

Candidate `ecf0333`, generation v11, completed five cases with correct verdicts before
`pathtraversal-fixed` failed with `UnexpectedModelBehavior: Exceeded maximum output retries (2)`.
Thirty cases were unstarted. The complete-corpus gate failed; task-success and unsafe-negative
gates remain not_checked. This is not a full-corpus accuracy result.

All native model calls in the failed investigation returned successfully. Three offline probes
exited zero, preserved original source bytes, exercised the real function and observed its
containment guard rejecting traversal. Each marker declared `target_reached: false`, with the
oracle and both controls true and vulnerability_observed false. The last model response
explicitly interpreted target_reached as exploit/sink reachability, rather than execution of
the target entrypoint and its security check. Generic validation feedback did not resolve this.

The correction clarifies field semantics in the packaged probe skill and gives specific
feedback when a cited probe declares incomplete observation prerequisites. It does not change
marker parsing, evidence qualification, source verification, labels, budgets or thresholds.
A security rejection can show the real target ran; setup/import failure cannot. The agent must
inspect its probe, derive truthful observations, execute a new probe and cite its new ID, or
return inconclusive. Runtime finalization independently reconstructs native receipts.

The failed workflow and all five owned sandbox records were terminal/closed. Exact owned-ID
reconciliation passed without execution or model redispatch. A replacement worker will use a
fresh queue and a fresh full-cohort report; the original failed attempt is preserved. Generation
v11 remains unchanged: the Temporal graph and activity contracts are unchanged. Historical
histories retain their original worker identity and are not resumed against changed source.

Private evidence: `.harness/openshell/private/live-eval-v11-32556d01708d/`.

| Report | SHA-256 |
| --- | --- |
| `cohort.json` | `930bd523425f3ac039c6d98b71898dee8c6da1549c26c7975079f4980917b455` |
| `sixth-case-failure.json` | `3c5704370cbc261a4e915c3ef380e6763ab47a08935ded237ca2c6296c103355` |
| `sixth-case-history.json` | `b4d10a58a46ed8086d3d0ecc6abfbcd22a192ccd98b35fe90000b0e121c427a3` |

Validation: 263 deterministic tests passed (one network test deselected), with
`HARNESS_TEST_REQUIRE_TEMPORAL=1`; lint, compilation and generated contract/instruction
checks passed. Completed native history (145 events) replayed with zero model/native
dispatches. The feedback repair regression uses mocked model/process evidence; it does
not establish live-model quality. A new full cohort is required for that gate.

## Mixed-citation feedback correction

Candidate `c34f1cc` again completed five correct cases before the same negative case
exhausted output corrections. The model cited earlier exploratory probes without markers
alongside newer well-formed markers declaring target_reached false. The validator's
format-error branch took precedence, so both delivered corrections discussed marker format
and never delivered target semantics. All model calls returned complete receipts; all seven
owned sandbox records were closed and exact reconciliation passed.

The follow-up removes competing diagnostic branches and returns one complete requirement
message. It explains marker format and entrypoint semantics together, independent of which
citation fails first. The same semantics now appear in always-visible agent instructions.
This removes runtime lines and preserves the exact admission predicate and two-correction
budget. A regression includes an earlier malformed citation alongside the false target claim.
The 169-event completed native history still replays with zero external dispatches.

Private evidence: `.harness/openshell/private/live-eval-v11-201cc101da4a/`.

| Report | SHA-256 |
| --- | --- |
| `cohort.json` | `a3cfd39728a499931efbb15210c3b16bbed0ec67e9b31de8dbe057cba5f70a26` |
| `sixth-case-failure.json` | `41ae404e40fd8d159568a08a63e75fcc38d946329c11e744186f1db3aa449b4c` |
| `sixth-case-history.json` | `224298bf709ce354be5df5c232b1d466e25710dc9c8d5c5a9c9d804af8ff96d8` |

## Generated artifact rejection

The bounded one-case diagnostic on `9cd4adf` failed before verdict validation. The second
probe exited zero but left a generated symlink `data/link_to_outside` pointing to `../outside`.
Read-only tar-header inspection identified that exact member; no archive was extracted on
the worker. Post-execution source verification correctly rejected the archive metadata.
This was a completed known command, not uncertain dispatch. The agent had not loaded the
probe skill, and its two probes lacked valid final observation markers.

The correction preserves the archive prohibition, and adds generic cleanup guidance:
remove agent-created symlinks and special files in finally before returning, without
changing original source. Always-visible instructions require loading the probe skill.
Only the narrowly typed post-execution metadata rejection returns incomplete evidence
with cleanup feedback after a completed command. It cannot qualify a definitive verdict.
Unknown execution, identity failure, capture failure and source mutation still propagate;
there is no automatic command retry. The agent may explicitly prepare a new probe.

The workflow graph and Evidence contract are unchanged; native activity behavior changes
require a new frozen worker identity/queue and do not resume old work.

Private evidence: `.harness/openshell/private/live-eval-v11-073ba6b9f94c/`.

| Report | SHA-256 |
| --- | --- |
| `diagnostic.json` | `8b195d5f2b3a1b34c697bfdc991f1844de34347a91274096918fde03a234ab9c` |
| `diagnostic-history.json` | `13755d7bb7aa4f5f3486843e73c3391b6845076c573201efe7216283d384774e` |

All four owned diagnostic sandbox records were closed; exact owned-ID reconciliation passed.
Focused agent/OpenShell regressions passed (97); generated contracts, lint and compilation
passed. The completed native history (169 events) replayed with zero external dispatches.

Full deterministic suite: 267 passed, one network test deselected, with required real Temporal.
