"""Temporary re-export: ``render_intake_prompt`` lives in ``agents.render``.

Delete this module once graph/pipeline.py, evals/run.py and qualification/broker/runner.py import
it from ``infosec_harness.agents.render``.
"""

from infosec_harness.agents.render import render_intake_prompt

__all__ = ["render_intake_prompt"]
