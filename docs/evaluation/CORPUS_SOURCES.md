# Corpus sources

The active qualification dataset is the unchanged 36-case seeded paired corpus described
in [eval-corpus](../../eval-corpus/README.md). It is small, synthetic and known to developers;
it cannot establish independently held-out or production-scale generalization.

Historical external datasets under `eval-corpus/external/` retain their own attribution,
provenance and quarantined cases. Vul4J data is attributed to Bui, Scandariato et al., MSR 2022,
with dataset licensing recorded in the manifest. These datasets are not currently accepted
by the evaluator. Before using them, independently implement and review source masking so
proof-of-vulnerability tests and golden labels are unavailable to the candidate. The old
harvester and staged scoring implementation were retired with the staged architecture.
