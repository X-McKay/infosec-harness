"""Operator qualification runners for the credential broker.

These modules run from a checkout under explicit operator handoff. Serving code never imports
them, and importing one grants no inference, lifecycle, or ledger authority. Each runner
records `not_checked` for anything it did not actually observe.

- ``validators``: pure manifest, source, configuration and baseline checks.
- ``runner``: one direct, native LocalOps or native Temporal phase (``python -m``).
- ``pilot``: the frozen-manifest phase orchestrator used by ``scripts/broker_real_provider_check.py``.
- ``workflow``: the Temporal workflow used by the native Temporal phase.
- ``graph``: one frozen production graph trial used by ``scripts/broker_real_graph_check.py``.
- ``service`` and ``service_workflow``: local HTTPS/PostgreSQL/Temporal service fixtures with an
  explicit fake native lifecycle, used by ``scripts/broker_service_check.py``.
- ``native``: mock-provider native acceptance through the production controller and executor.
"""
