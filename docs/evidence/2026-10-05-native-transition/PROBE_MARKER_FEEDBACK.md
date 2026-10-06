# Probe observation format — 2026-10-05

The readiness-gated `3273bd5` cohort completed eleven native model requests without the
startup disconnect. Three offline probes exited zero with source verification and meaningful
SQL target/control output. Each nevertheless emitted a standalone final `HARNESS_PROBE`
line with JSON or key/value observations on preceding lines. The strict five-field, one-line
protocol did not parse those observations. The model repeatedly proposed a definitive
verdict and exhausted two output corrections. No definitive result was admitted; 35 cases
remained unstarted. All five owned sandboxes closed and explicit reconciliation passed.

The next candidate supplies targeted feedback for a successful cited probe whose marker
is malformed: prefix and exactly five boolean fields must share the final stdout line,
with a direct `print('HARNESS_PROBE '+json.dumps(observations))` illustration. Values must
come from executed target/control checks. The model may author a new probe and cite its
new receipt or choose inconclusive. Parser strictness, output-correction limit, total budgets,
ground truth and release thresholds remain unchanged. Packaged probe guidance also names
the actual `write` tool and warns against separate marker/JSON lines. The agent now directs
probe authors to load that skill. Expertise stays in the packaged skill; runtime validation
still owns admission.

A regression reproduces the exact split-line output and repairs it through PydanticAI
feedback using a new native operation ID, without resending the old execution. The v11
graph is unchanged; its worker code/skill fingerprint changes. The terminal candidate's
worker stopped before replacement. This establishes sustained connectivity for eleven
completed calls, not model quality or a guarantee against future policy changes.

Private evidence: `.harness/openshell/private/live-eval-v11-d18c1e1591da/`.
Completed model receipts report 82,752 input and 7,364 output tokens, including 3,573
reasoning tokens in the provider-specific usage extension. Monetary cost is unavailable.

| File | SHA-256 |
| --- | --- |
| `cohort.json` | `060607a86bc766bb98c7e0c39d79b65e50c48e96522ef284047b0a1c17bc349c` |
| `first-case-failure.json` | `a525be07423bac964e17785d55ae3179731ed5baaaeb3077acc9b865e7968600` |
| `first-case-history.json` | `6fb36b253e93143c4d6e95f355e1f5e827e6804a34376f218713b079d8e05ebc` |

The changed candidate passed 259 deterministic tests with pinned Temporal required,
plus lint, compilation and generated drift checks. Native configuration and images are
unchanged; the proven readiness gate remains in place.
