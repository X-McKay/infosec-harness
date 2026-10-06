# Corpus sources

The active qualification dataset is the 82-case seeded paired corpus described
in [eval-corpus](../../eval-corpus/README.md). It is small, synthetic and known to developers;
it cannot establish independently held-out or production-scale generalization.

Until 2026-10-06 the fixtures also carried their own labels: each pair lived under
`<topic>/vulnerable` and `<topic>/fixed`, sources opened with `# VULNERABLE:` or `# FIXED:`
comments explaining the weakness or the defence, test names and package metadata stated the
outcome, and the two findings of a pair had different descriptions. The corpus was de-labelled
in commits `1ab456c` (neutral `a`/`b` directories), `4f0d5e6` (comments, test names and
metadata), `7a8df53` (one shared title and description per pair) and `f7bc84f`
(`tests/evals/test_corpus_hygiene.py`, which keeps it that way). Accuracy measured on the
corpus before those commits is not independent evidence. The answer key is the manifest and the
maintainers-only table in the corpus README; neither may be copied into agent inputs.

Historical external datasets under `eval-corpus/external/` retain their own attribution,
provenance and quarantined cases. Vul4J data is attributed to Bui, Scandariato et al., MSR 2022,
with dataset licensing recorded in the manifest. These datasets are not currently accepted
by the evaluator. Before using them, independently implement and review source masking so
proof-of-vulnerability tests and golden labels are unavailable to the candidate. The old
harvester and staged scoring implementation were retired with the staged architecture.
