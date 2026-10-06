# OpenShell feasibility and deployment revision (2026-10-01)

[`OPENSHELL_FEASIBILITY.md`](OPENSHELL_FEASIBILITY.md) records that OpenShell v0.1.2 failed its
Landlock qualification under the harness daemon's `runsc` default, and that a bounded G0
prototype on a separate checkout-owned Docker daemon then passed feasibility review.
[`OPENSHELL_DEPLOYMENT_REVISION.md`](OPENSHELL_DEPLOYMENT_REVISION.md) is the approved
dedicated-daemon topology that decision produced. Together they prove the topology is feasible
for a test prototype. They do not establish production credential routing, real-provider
behavior or recovery; the G0 prototype code has since been deleted and only this record remains.
The workstation path was redacted on 2026-10-04.
