"""The investigator's OpenShell tools: read, search and write files, execute, run_probe."""

from pydantic_ai.toolsets import FunctionToolset

from infosec_harness.agents.investigator import InvestigationDeps
from infosec_harness.sandbox import OpenShell

from . import execute, workspace


def build_toolset(openshell: OpenShell) -> FunctionToolset[InvestigationDeps]:
    """One sequential toolset; its id names the native Temporal tool activity."""
    tools = FunctionToolset[InvestigationDeps](id="workspace", sequential=True)
    workspace.register(tools, openshell)
    execute.register(tools, openshell)
    return tools
