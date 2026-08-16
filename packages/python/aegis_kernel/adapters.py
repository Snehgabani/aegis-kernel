"""
Framework adapters for popular Python AI Agent Frameworks (CrewAI, AutoGen, LangChain).
"""

import asyncio
from typing import Any, Callable, Dict, Optional, List, Union
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

class AegisLangChainTool:
    """
    LangChain Tool Wrapper: Wraps a LangChain BaseTool, StructuredTool, or Python callable
    with deterministic Aegis invariant verification with zero external dependencies.
    Supports both traditional `.run()` and modern LCEL / LangGraph `.invoke()` / `.ainvoke()`.
    """
    def __init__(
        self,
        tool_instance: Any,
        engine: Optional[AegisEngine] = None,
        handle_tool_error: bool = True
    ):
        self.tool = tool_instance
        self.engine = engine or AegisEngine()
        self.name = getattr(tool_instance, "name", getattr(tool_instance, "__name__", "langchain_tool"))
        self.description = getattr(tool_instance, "description", "")
        self.handle_tool_error = handle_tool_error

    def _extract_params(self, tool_input: Any = None, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        params = dict(kwargs)
        if tool_input is not None:
            if isinstance(tool_input, dict):
                params.update(tool_input)
            elif isinstance(tool_input, str):
                if "query" not in params and "input" not in params:
                    params["query"] = tool_input
                else:
                    params["_input"] = tool_input
            else:
                params["_tool_input"] = tool_input
        if args:
            params["_args"] = list(args)
        return params

    def run(self, tool_input: Any = None, *args: Any, **kwargs: Any) -> Any:
        params = self._extract_params(tool_input, *args, **kwargs)
        tool_call = ToolCall(tool=self.name, params=params)
        verdict = self.engine.evaluate(tool_call)

        if not verdict.allowed:
            first_v = verdict.violations[0]
            if self.handle_tool_error:
                return f"Error: [Aegis Policy Blocked] {first_v.rule_id} - {first_v.message}. Suggested Fix: {first_v.suggested_fix or 'Adhere to policy bounds.'}"
            raise AegisBlockedError(verdict)

        if hasattr(self.tool, "run") and callable(self.tool.run) and self.tool.run != self.run:
            return self.tool.run(tool_input, *args, **kwargs) if tool_input is not None else self.tool.run(*args, **kwargs)
        elif hasattr(self.tool, "_run") and callable(self.tool._run):
            return self.tool._run(tool_input, *args, **kwargs) if tool_input is not None else self.tool._run(*args, **kwargs)
        elif callable(self.tool):
            if tool_input is not None and not kwargs and not args:
                return self.tool(tool_input)
            return self.tool(*args, **kwargs)
        else:
            raise ValueError(f"Target {self.tool} is not callable")

    def invoke(self, input: Any, config: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Any:
        """LangChain Runnable Protocol compatibility."""
        return self.run(input, **kwargs)

    async def ainvoke(self, input: Any, config: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Any:
        """Async LangChain Runnable Protocol compatibility."""
        params = self._extract_params(input, **kwargs)
        tool_call = ToolCall(tool=self.name, params=params)
        verdict = self.engine.evaluate(tool_call)

        if not verdict.allowed:
            first_v = verdict.violations[0]
            if self.handle_tool_error:
                return f"Error: [Aegis Policy Blocked] {first_v.rule_id} - {first_v.message}. Suggested Fix: {first_v.suggested_fix or 'Adhere to policy bounds.'}"
            raise AegisBlockedError(verdict)

        if hasattr(self.tool, "ainvoke") and callable(self.tool.ainvoke):
            return await self.tool.ainvoke(input, config=config, **kwargs)
        elif hasattr(self.tool, "_arun") and callable(self.tool._arun):
            return await self.tool._arun(input, **kwargs)
        elif asyncio.iscoroutinefunction(self.tool):
            return await self.tool(input, **kwargs)
        else:
            return self.run(input, **kwargs)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.run(*args, **kwargs)

def wrap_langchain_tool(tool: Any, engine: Optional[AegisEngine] = None, handle_tool_error: bool = True) -> AegisLangChainTool:
    """Convenience helper to wrap any LangChain tool or callable with Aegis invariant verification."""
    return AegisLangChainTool(tool, engine=engine, handle_tool_error=handle_tool_error)

