"""
Framework adapters for popular Python AI Agent Frameworks (CrewAI, AutoGen, LangChain).
"""

from typing import Any, Callable, Dict, Optional, List
from .engine import AegisEngine
from .decorator import aegis_guard, AegisBlockedError
from .types import ToolCall, AegisVerdict

class AegisCrewAITool:
    """
    CrewAI Tool Wrapper: Wraps a CrewAI BaseTool or tool function
    with deterministic Aegis invariant verification.
    """
    def __init__(self, tool_instance: Any, engine: Optional[AegisEngine] = None):
        self.tool = tool_instance
        self.engine = engine or AegisEngine()
        self.name = getattr(tool_instance, "name", getattr(tool_instance, "__name__", "crewai_tool"))
        self.description = getattr(tool_instance, "description", "")

    def run(self, *args: Any, **kwargs: Any) -> Any:
        params = dict(kwargs)
        if args:
            params["_args"] = list(args)

        tool_call = ToolCall(tool=self.name, params=params)
        verdict = self.engine.evaluate(tool_call)

        if not verdict.allowed:
            first_v = verdict.violations[0]
            # Return structured error string for CrewAI self-healing loop
            return f"ERROR [Aegis Policy Blocked]: {first_v.rule_id} - {first_v.message}. Suggested Fix: {first_v.suggested_fix or 'Adhere to policy bounds.'}"

        if hasattr(self.tool, "_run"):
            return self.tool._run(*args, **kwargs)
        elif callable(self.tool):
            return self.tool(*args, **kwargs)
        else:
            raise ValueError(f"Target {self.tool} is not callable")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)

def wrap_autogen_function(func: Callable[..., Any], engine: Optional[AegisEngine] = None) -> Callable[..., Any]:
    """
    Wraps an AutoGen tool function to intercept executions and return
    self-healing structured feedback if an invariant is violated.
    """
    eng = engine or AegisEngine()
    tool_name = func.__name__

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        params = dict(kwargs)
        if args:
            params["_args"] = list(args)

        tool_call = ToolCall(tool=tool_name, params=params)
        verdict = eng.evaluate(tool_call)

        if not verdict.allowed:
            first_v = verdict.violations[0]
            return {
                "error": True,
                "status": "BLOCKED",
                "rule_id": first_v.rule_id,
                "message": first_v.message,
                "suggested_fix": first_v.suggested_fix,
                "proof_hash": verdict.proof_hash
            }

        return func(*args, **kwargs)

    return wrapped
