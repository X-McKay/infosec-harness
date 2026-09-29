"""Sweep the cost of one `recon` run over repository size, offline.

    uv run python scripts/measure_exploration.py                  # baseline curve
    uv run python scripts/measure_exploration.py --json out.json   # machine-readable

No provider and no container are involved: the model is a `FunctionModel` running the fixed
exploration procedure in `evals/exploration.py`, and the repository is synthetic so its size
is the only variable. See that module's docstring for what this does and does not measure.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
from pathlib import Path

from infosec_harness.agents.budgets import run_budget, size_factor
from infosec_harness.agents.registry import load_spec
from infosec_harness.evals.exploration import Measurement, measure_recon, synth_repo

DEFAULT_SIZES = (10, 100, 500, 2000)

# The tool surface as it shipped before this experiment. Named explicitly rather than taken
# from the spec, so "baseline" keeps meaning the same thing after the spec changes.
SHIPPED = ("list_files", "read_file", "search_code", "describe_callables")

# One variant per candidate, each adding exactly one tool to the shipped surface, so the
# before/after is attributable to that tool and not to the whole change.
VARIANTS: dict[str, tuple[str, ...]] = {
    "baseline": SHIPPED,
    "+read_files": (*SHIPPED, "read_files"),
    "+list_tree": (*SHIPPED, "list_tree"),
    "+repo_digest": (*SHIPPED, "repo_digest"),
    "all": (*SHIPPED, "read_files", "list_tree", "repo_digest"),
    # Whatever agents/recon/agent.yaml declares right now, overlay-free.
    "as-shipped": (),
}

_SKILLS = {"Skills": {"directories": "skills",
                      "include": ["lang-python", "lang-java", "lang-javascript", "lang-perl"]}}


def overlay_for(tools: tuple[str, ...]) -> dict:
    """A spec overlay exposing exactly `tools`, with every other capability left in place.

    The other capabilities matter: dropping them would change the tool definitions in the
    prompt and so the per-request input, and the comparison would no longer be of the repo
    toolset alone.
    """
    return {"capabilities": [_SKILLS, {"RepoReadOnly": {"tools": list(tools)}},
                             {"WarnOnCacheBusts": {}}]}


async def sweep(variants: list[str], sizes: tuple[int, ...]) -> list[Measurement]:
    out: list[Measurement] = []
    with tempfile.TemporaryDirectory() as tmp:
        repos = {n: synth_repo(Path(tmp) / f"repo{n}", n) for n in sizes}
        for label in variants:
            for n in sizes:
                # "as-shipped" measures agents/recon/agent.yaml itself, with no overlay at all,
                # so the table cannot drift from the spec that is actually committed.
                overlay = None if label == "as-shipped" else overlay_for(VARIANTS[label])
                out.append(await measure_recon(repos[n], label=label, source_files=n,
                                               overlay=overlay))
    return out


def _budget_line(n: int) -> str:
    budget = run_budget("recon", load_spec("recon").metadata).scaled_for(n)
    return f"{budget.max_requests:>4} ({size_factor(n):.2f}x)"


def render(rows: list[Measurement]) -> str:
    lines = ["", "recon: cost of one run vs repository size (offline, FunctionModel)", ""]
    header = f"{'variant':<13} {'files':>6} {'requests':>9} {'tools':>6} " \
             f"{'result kB':>10} {'peak hist':>10} {'src named':>11} {'dirs known':>11} " \
             f"{'req budget':>12} {'verdict':>8}"
    lines += [header, "-" * len(header)]
    last = None
    for r in rows:
        if last is not None and r.label != last:
            lines.append("")
        last = r.label
        budget = run_budget("recon", load_spec("recon").metadata).scaled_for(r.source_files)
        verdict = "OK" if r.requests <= budget.max_requests else "OVER"
        lines.append(f"{r.label:<13} {r.source_files:>6} {r.requests:>9} {r.tool_calls:>6} "
                     f"{r.result_bytes / 1024:>10.1f} {r.peak_history_tokens:>10} "
                     f"{r.files_seen:>5}/{r.source_files:<5} "
                     f"{r.dirs_seen:>5}/{r.dirs_total:<5} "
                     f"{_budget_line(r.source_files):>12} {verdict:>8}")
        if r.unmet:
            lines.append(f"{'':<12} {'':>6} unmet needs: {', '.join(r.unmet)}")
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--variant", action="append", choices=sorted(VARIANTS),
                    help="measure only these variants (default: all)")
    ap.add_argument("--size", action="append", type=int,
                    help=f"repository sizes to sweep (default: {list(DEFAULT_SIZES)})")
    ap.add_argument("--json", type=Path, help="also write the rows as JSON")
    args = ap.parse_args()
    variants = args.variant or list(VARIANTS)
    sizes = tuple(args.size or DEFAULT_SIZES)
    rows = asyncio.run(sweep(variants, sizes))
    print(render(rows))
    if args.json:
        args.json.write_text(json.dumps([r.as_row() for r in rows], indent=2) + "\n")


if __name__ == "__main__":
    main()
