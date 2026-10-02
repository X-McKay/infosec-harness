# Per-agent non-thinking experiment

The 0.2.8 candidate adds optional `enable_thinking` to backend capabilities, operator profiles
and immutable executor contracts. Omitted `None` preserves provider defaults and historical
serialized identities; explicit `false` or `true` changes identity and must match exactly.
Existing per-agent backend routing can select a cloned intake backend. The trusted adapter
constructs only `chat_template_kwargs.enable_thinking`; arbitrary caller body/header overrides
remain blocked. Other agents retain their default reasoning mode. No caps, prompts, scorers,
retry bounds, expiry rules or uncertain-hold recovery rules change.

The candidate at `e481cfe93454dec73b2de878502b314a18bd6f5c` passed canonical checks, generated
and development-skill drift checks, all 2,507 deterministic tests (40 skipped, 861 warnings),
and all six CI checks. Twenty-three new regressions cover strict typing, default identity
compatibility, operator-profile equality, admission/direct/executor wire parity, override
rejection and exact diagnostic comparison of budgets, settings and prices. UI behavior is
unchanged; local UI checks are `not_applicable`, and CI web checks passed.

One frozen live sample at `https://llm.almckay.io/v1` returned HTTP 200 and the expected strict
output-tool answer, using 295 input and 27 output tokens with zero reported reasoning tokens.
The sample script then called a SDK usage property as a method and failed during reporting.
That original report and the complete request/response are retained. A separate offline replay
of the saved response passed typed validation and unchanged semantic expectations without
another live request. Offline analysis SHA-256:
`8ed5f25de18776a0ccd10e0138b2625d19f0dabaa1a19d434e30ca5be4d2c4f7`.
This demonstrates one observed working non-thinking structured response, not broad model quality
or server grammar enforcement.

The exact executor image is
`sha256:e8620acf18ba78f9f7739423cb1119c7f4d27ae1e3c3c3bbceba98facb7103b1`.
The qualified runsc builder and isolated import attestation passed; image proof SHA-256:
`161d9a1e51ee29289e852c4309db177a5371de16bd9ff117c64bc372e648fa36`.
One fresh intake contract passed native Ready, verification and deletion with zero provider
calls. All 171 prior request/result contents and 15 uncertain holds matched the independent
v4 dump. The other ten agents were not newly qualified on this image. Source/config proof:
`c692515db685999781216413a8d319f33c5d216f8572ba31a8117713e4665f9c`;
readiness proof: `e66d2c14f3463af1dabc4817b956aecda40576f94f34798336da7ae9c790d305`.

The first diagnostic wrapper stopped with an `OSError` before recording a case. A zero-inference
reproduction identified settings cached before applying the dedicated trial environment: its
ledger read tried localhost port 5432 instead of the owned database on 18445. Independent SQL,
lease and native inventory checks proved zero new admissions or leases and unchanged prior
contents/holds. The failed manifest, report and exclusive claim remain retained. A separately
frozen wrapper applies the environment before settings-dependent imports. This is a private
experiment-wrapper correction; production service configuration was not changed.

The fresh intake-only diagnostic manifest SHA-256 is
`ffc673e593ea9f11c9ba9fb864ad261cbc5e50f650f49f5b630e0d628b71c27a`.
Its unchanged frozen intake case failed execution after three completed responses and a
subsequent budget rejection. All three responses reported zero reasoning tokens, so the
reasoning control worked through OpenShell. Cleanup passed; no uncertain completion or
allocation overrun was created. This diagnostic always reports full qualification as
`not_checked`. Native Temporal, production graph, held-out quality, hosted service/Kubernetes
acceptance and server grammar attestation remain `not_checked` for the new candidate.


Independent replay found that all three returned argument objects were identical and passed
`AtomicFinding` schema validation. Each cited the `vulnerability_class` evidence range from
`S000002` through `S000001`; reconstruction correctly rejected the reversed range. The next
two requests contained that repair feedback, but the model repeated its original arguments.
SDK admission rendering reproduced conservative input reserves of 11,912, 15,294 and 18,676
tokens. An offline construction of the unsent fourth request using the saved third response
and identical repair feedback produced a 22,058-token reserve, above the unchanged 20,000
per-request limit. This derived request is not captured provider traffic. The failure was
semantic evidence referencing followed by context admission, not malformed fields or JSON.
Independent analysis SHA-256: `328113b88e164a479e39b49eec13fae25100179899f7a19a9f84dc7e9814a212`;
validation replay: `5ead4116284282ab350430eff27c3ac1c90c1f4542156cdf2832bc2272362574`.

Terminal preservation passed: 174 records, comprising 159 completed responses and 15 original
uncertain held requests. All prior 171 request/result contents and all 15 holds matched the
independent v4 dump. There were no accepted or dispatch-intent records. All 154 leases were
deleted; native inventory was empty. Provider and primary service identities remained unchanged.
The fresh private 0600 database dump and both failed wrapper attempts are retained. Terminal
seal SHA-256: `417822a2782bb1273b586857a9165ca9a449e60844c2618a175aa41b3696d1a6`.
Dedicated infrastructure remains running. An empty fixed-category log capture does not prove
historical failure causes.


## Targeted source-range repair

The 0.2.9 candidate at `0717cffa9217d80d00cdb85f1dd60b18556cd720` adds the trusted claim
name and static source-line ordering/null-endpoint guidance to reversed-range repair feedback.
It does not echo untrusted report text, IDs or model values. Accepted and rejected source
ranges, whole-output evidence checks, budgets, expected outcomes and output schemas remain
unchanged. Temporal patch `intake-reference-repair-v1` preserves the exact previous retry text
for histories without the marker. The executor sources and E862 image remain unchanged;
the feedback is host validator behavior. Existing held requests remain fenced and are not
rebound to new reasoning settings or feedback.

Canonical checks and the complete deterministic suite passed: 2,533 tests, 40 skipped,
861 warnings. Actual local Temporal recorded two independently authored synthetic histories,
one with legacy no-marker feedback and one with the new patch and targeted feedback. Both
completed using FunctionModel responses, then replayed under the current validator with zero
fresh model calls. Four synthetic responses and zero external provider calls were used. These
are real Temporal activity/replay checks, not prior production failure histories. Owned workers
stopped and workflows completed; the primary service stayed running. Evidence SHA-256:
`668329e85a5162102614b7f816ee8f5e29a95fe9f15cf4ea9701b71259423d2c`.

The separately frozen native intake repair manifest SHA-256 is
`bb9731866bd92796f1507031050459f8c7966f81ff9602f8eb402d1169a431c5`.
The source/config checkpoint explicitly reused the earlier one-intake Ready proof solely for
the unchanged image/contract; a fresh, independent 174-record checkpoint owned current ledger
truth. Source proof SHA-256: `52ace9ab9472f15cb55e105cd2b0c1c9b6f31d92ff865ed010cbcc62d169faca`.

The real OpenShell-brokered intake case passed execution, unchanged semantic scoring and
cleanup in 22.231 seconds. It completed three requests, using 9,398 input and 1,428 output
tokens, with no uncertain completion. This is a successful diagnostic case; full native
qualification remains `not_checked` for this candidate until fresh all-agent Temporal and
production-graph trials. The other ten agents retain provider-default reasoning and were
not newly qualified on E862.


Independent saved-response analysis confirmed the feedback mechanism: the first answer had
reversed `cwe` and `vulnerability_class` ranges. Request two carried targeted `cwe` feedback;
its response corrected that range. Request three carried targeted `vulnerability_class`
feedback; its response corrected the remaining range. Reversed-range counts were 2, 1 and 0.
Every response passed `AtomicFinding` schema validation and reported 476 output tokens with
zero reasoning tokens. Supported claim values and confidences were identical across the three
responses; only references changed. No scoring threshold or evidence guard was weakened.
Analysis SHA-256: `f6a08990bd19da96a2931811ae1966a3e724b83aea987a01e6e78835c543a67b`;
correction proof: `874c18589f6497ad2406f72b264b25a3b9309b626718d2a6e1f5d3c98d185e6d`.
This is one successful frozen case, not a population reliability or held-out quality claim.


Final retention is `passed`: 177 records comprise 162 completed responses and the original
15 uncertain held requests. The fresh three-request union matches the passing report exactly.
All prior 174 request/result contents and all 15 hold objects matched the independent previous
dump. No accepted or dispatch-intent records remained. All 155 leases were deleted, native
inventory was empty, and provider, primary service, image, host source and configuration
identities remained stable. Dedicated infrastructure remains running. Final evidence seal:
`c2c3da899c24a9ce5ddaed74f01a5c7105b2053ff8980cda6b07faa1f76a1be6`.
All six CI gates for the runtime candidate passed. The empty fixed-category capture is retained
without inferring any historical cause from its absence.
