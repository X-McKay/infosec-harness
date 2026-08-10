# Offline evaluation and gym experiments

The initial environment is replay-only. It uses synthetic SARIF/source artifacts,
sealed deterministic grades, no provider calls, no repository execution, and a
deny-network benchmark profile. It is a controller/evidence evaluation, not active
security testing.

## Experiment 1: evidence-slice completeness

Compare the current code-flow plus bounded-read slice against primary-location-only
evidence on the frozen development set. Hold model, prompt, disposition schema, and
token budget fixed. Primary metrics are correct disposition and evidence validity;
hard constraints are zero fabricated citations, zero policy violations, and no increase
in high-severity false dismissals. Report paired task-level outcomes and cost.

## Experiment 2: abstention and escalation policy

Compare a single replay/fake decision with a deterministic abstain-on-proof-gap rule.
Do not change tool authority. Measure selective coverage, high-risk false-dismissal
rate, review burden, and dollars per correct disposition. The release decision requires
the holdout to remain untouched until the configuration is fixed.

## Experiment 3: budget frontier

Use fake/replay responses to sweep fixed token/cost caps. Plot correct dispositions and
evidence validity against the reserved and observed cost. Timeout, provider refusal,
policy block, grader error, and infrastructure error stay separate and unscored.

No experiment may enable networked workers, target execution, package download, or
high-risk benchmark lanes. Those require the separately documented containment gate.
