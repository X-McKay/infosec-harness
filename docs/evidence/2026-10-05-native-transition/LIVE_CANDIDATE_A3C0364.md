# Live candidate a3c0364 — failed, preserved

Candidate: `a3c036469da518bb2831c18ee9c3481b51c78c40`.
The complete 36-case cohort started through the ordinary production worker and
`harness eval --allow-inference` against managed Temporal. The worker used only
`https://llm.almckay.io/v1`, served model `Qwen3.6-35B-A3B-NVFP4`, native OpenShell
provider `ih-qwen` and the pinned workspace/model images in the qualification checkpoint.
Original limits, labels and thresholds were unchanged.

The first case, `sqli-vulnerable`, failed in its first model activity. The provider
returned HTTP 400: `System message must be at the beginning.` The native executor
receipt contains a complete exit-1 result and traceback. This is a confirmed rejected
request, not a successful investigation or a model-quality score. Token usage/cost
for the rejected request was not reported. No inference request was automatically
resent. The other 35 cases remain unstarted.

| Gate | Status |
| --- | --- |
| Complete corpus | failed |
| Task success rate | not_checked |
| Unsafe negatives | not_checked |
| Owned workspace/model cleanup and closed-run fence | passed |

The cohort's numeric success fraction is zero because no case completed; it is not
an estimate of the model's investigation accuracy. Exact owned lifecycle records were
closed and reconciliation completed. The owned worker stopped; the managed Temporal
service and original history remain intact.

Private reports under `.harness/openshell/private/live-eval/`:

| Report | SHA-256 |
| --- | --- |
| `cohort-a3c0364.json` | `fbaa8582627ea2e19633f820bbcbed21b807a3792dd6bb1c9e5c308052d9c45c` |
| `first-case-failure.json` | `72b61aaf4ccef9afa3506435a2100ca79ec76e2713f3af05c19cf28409df06ed` |
| `first-case-history.json` | `2200b574b6762169c5527f8cc28fda9c4c8cddcc01e6eb07146a4b70dd3ef76e` |

The next candidate uses PydanticAI's native compatible-chat profile to combine leading
system messages and prepare inline instructions before dispatch. A wire-level
regression requires one initial system message while retaining base, current and
dynamically loaded skill instructions. This changes message rendering, so subsequent
live results must use a new source commit and executor image rather than overwrite
this cohort.

The rebuilt executor image is
`sha256:5822d49afc2ec89fd347d90a8e80dd34675c8410a41a57f8c61c89022749d830`.
Its provider-free native import gate passed, followed by exactly one authorized
native typed call reproducing the multiple-leading-system-message shape. The call
passed in 3.431 seconds with 61 input and 302 output tokens (280 reasoning tokens),
`max_tokens=1024`, native confinement and exact cleanup. This verifies the rendering
fix, not corpus accuracy. Native configuration SHA-256:
`28c31dd21c3457974e85734d892d17da46ee00d4a171116e0caf060e1e6bfba9`.
Private report `native-selfhost-multiple-system-report.json` SHA-256:
`0da53be2a2943ed31e97eb7f084f89cee1a6cee141925ab89f22f2e413906dfe`.
Private import report `profile-fixed-model-import-report.json` SHA-256:
`d29583d4ed7e96e1d2eaf3ce12cb3e165fbe6eea4b29d8c4985a3ad488a1b069`.

Independent review also found two candidate defects: contrary complete probe evidence
could be omitted from a definitive verdict, and worker identity was checked during
preparation/finalization but not every native activity. These require regression fixes
before the next candidate. Their existence precludes promotion of this checkpoint.

The successor uses workflow generation v10. Contrary complete source-verified probe
observations force `inconclusive` for either proposed definitive label; contrary
receipt IDs remain visible even if omitted by the agent. A native Temporal activity
interceptor checks prepared, startup and current worker identity before model, tool
and skill activity handlers run. Real two-worker tests cover delivery to a mismatched
worker before execution. Cleanup also needs the prepared worker binding so another
runtime cannot report success without inspecting the original owned resources.

The Java workspace additionally passed renewed PyPI egress, denied unrelated egress,
and hash-pinned pip installation followed by offline import. Reports:
`final-jdk17-egress-report.json` SHA-256
`fe16a24b7716fe8da45ab3eb82e98e8a9bec725278288b1527bca3c2c3e2edd9`, and
`final-jdk17-pip-report.json` SHA-256
`d4bcafb564ff1b32ae5c1ead1ce44b00132dba6805dbc0cd47663ace94be1cbf`.
Actual native Maven downloads initially failed: Java dual-stack sockets were denied,
and IPv4 then exposed a missing proxy-CA trust path. A workspace-local copy of the
JDK trust store with the native public CA, plus process-scoped IPv4/JVM options,
preserved TLS verification and eventually compiled the unchanged Java 17 corpus.
Partial transfer failures remain recorded; one eventual successful compile does not
establish reliable clean-cache Maven builds. The setup is documented as a skill,
without a runtime language-specific branch or network-policy expansion.
Private `java-native-jvm-trust-control-report.json` SHA-256:
`c15b7327113d79bbdb2288999db2214ae45408d5c55816277469bafff5784bce`.
