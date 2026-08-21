"""
Aegis Invariant Kernel — CrewAI Middleware
Turn-key, drop-in deterministic safety clearance for CrewAI tools, agents, and crews.

Zero hard dependency on `crewai` itself: every wrapper is duck-typed against the
public CrewAI BaseTool contract (`name`, `description`, `args_schema`, `_run`),
so this package works across CrewAI versions without pinning.
"""

from .guard import (
    AegisGuardedTool,
    aegis_crewai_tool,
    guard_tool,
    guard_tools,
    guard_agent,
    guard_crew,
)
from aegis_kernel import AegisEngine, AegisBlockedError, AegisVerdict, ToolCall

__all__ = [
    "AegisGuardedTool",
    "aegis_crewai_tool",
    "guard_tool",
    "guard_tools",
    "guard_agent",
    "guard_crew",
    "AegisEngine",
    "AegisBlockedError",
    "AegisVerdict",
    "ToolCall",
]

__version__ = "1.1.0"
