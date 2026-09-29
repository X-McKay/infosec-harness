# Sealed held-out staging protocol

Do not open dataset or fixture contents after the candidate is frozen. The preparation agent
has seen them, so it must not participate in candidate changes or score interpretation.

After freezing the candidate, copy this bundle's `fixtures/` directory to
`evals/heldout/quality-gates-v1/fixtures/`. Copy the repository's packaged agents directory to a
temporary directory outside the checkout. For one agent at a time, replace only
`<agents-dir>/<agent>/evals/dataset.yaml` with the corresponding sealed dataset, set the
`agents_dir` setting to that temporary directory, and run the existing `harness eval run
<agent>` command. Destroy that temporary agents directory before preparing the next agent.
This preserves the deployed agent protocol and prevents a second held-out dataset from being
discoverable through the configured agents directory.

The expected fields remain in the sealed dataset because the deterministic adapter consumes
them after inference. The adapter renders only `payload` into the model prompt; it never renders
the case object, `expected`, group, or category. Fixture repositories contain executable source
only and no expectations or verdict labels.

Budget: at most ten held-out case attempts total for the candidate. Run the complete frozen
baseline separately for three repetitions; those baseline repetitions do not consume held-out
candidate attempts. Do not rerun a failed candidate case or tune from held-out results.

Before staging, run `python validate.py`. It validates counts, grouping, path confinement,
absence of goldens in repository roots, and independent Python/JavaScript reference assertions.
It performs no inference and no network access.
