# Broker qualification checkpoint (2026-10-04)

[`CREDENTIAL_BROKER_QUALIFICATION_CURRENT.md`](CREDENTIAL_BROKER_QUALIFICATION_CURRENT.md)
assembles separately measured results at commits `449be68` and `10f35e9`: the deterministic
suite, recorded-history replay, native agents and SDK replay, a real production graph,
controller integration and all-eleven native readiness. It proves each listed measurement on its
named commit. It does not declare a combined fresh full-dataset run, hosted or Kubernetes
qualification, or provider reliability. Its component reuse argument depended on a dependency
ledger that was removed on 2026-10-04 because it referenced absolute paths on one workstation;
that reuse cannot be reassessed, and wave-one changes to the broker since then require a rebuilt
executor image and fresh qualification.
