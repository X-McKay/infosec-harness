# Sealed held-out staging protocol

Do not open dataset or fixture contents after the candidate is frozen. The preparation agent
has seen them, so it must not participate in candidate changes or score interpretation.

After freezing the candidate, copy this bundle's `fixtures/` directory to
`evals/heldout/quality-gates-v1/fixtures/`. Then run one agent at a time against its sealed
dataset, in place:

```bash
harness eval run <agent> --dataset evals/heldout/quality-gates-v1/datasets/<agent>/dataset.yaml
```

`--dataset` replaces only the cases; the agent's deployed spec, protocol and release policy are
unchanged, and no agents directory is copied or reconfigured, so a second held-out dataset is
never discoverable through the configured agents directory. The release report records the
sealed dataset's path and case-set digest in its provenance.

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
