"""
CrewAI tool / agent / crew guards backed by the Aegis Invariant Kernel engine.

Design notes
------------
* Blocked calls return a *structured self-healing feedback string* by default,
  because CrewAI feeds tool errors back to the LLM, which then retries with a
  corrected call. Set ``on_block="raise"`` to raise ``AegisBlockedError`` and
  hard-stop the task instead.
* All wrappers are duck-typed: any object exposing ``_run``/``run``/callable
  plus optional ``name``/``description``/``args_schema`` works.
"""

import asyncio
import functools
from typing import Any, Callable, Iterable, List, Optional

from aegis_kernel import AegisBlockedError, AegisEngine, ToolCall
from aegis_kernel.types import AegisVerdict

_ON_BLOCK_MODES = ("feedback", "raise")


def _format_block_feedback(verdict: AegisVerdict) -> str:
    """Structured, LLM-parseable feedback so the agent can self-correct."""
    v = verdict.violations[0] if verdict.violations else None
    rule_id = v.rule_id if v else "INVARIANT-POLICY"
    message = v.message if v else "Security policy constraint violated."
    fix = (v.suggested_fix if v else None) or "Adhere to policy bounds and retry."
    return (
        "AEGIS_BLOCKED: Tool execution denied by deterministic invariant. "
        f"rule_id={rule_id}; reason={message}; suggested_fix={fix}; "
        f"proof_hash={verdict.proof_hash}"
    )


def _collect_params(args: tuple, kwargs: dict) -> dict:
    params = dict(kwargs)
    if args:
        params["_args"] = list(args)
    return params


class AegisGuardedTool:
    """
    Drop-in replacement for a CrewAI tool with pre-execution invariant clearance.

    Preserves ``name``, ``description`` and ``args_schema`` so CrewAI's tool
    binding and function-calling schemas remain unchanged.
    """

    def __init__(
        self,
        tool: Any,
        engine: Optional[AegisEngine] = None,
        on_block: str = "feedback",
        tool_name: Optional[str] = None,
    ):
        if on_block not in _ON_BLOCK_MODES:
            raise ValueError(f"on_block must be one of {_ON_BLOCK_MODES}")
        self.tool = tool
        self.engine = engine or AegisEngine()
        self.on_block = on_block
        self.name = tool_name or getattr(tool, "name", getattr(tool, "__name__", "crewai_tool"))
        self.description = getattr(tool, "description", getattr(tool, "__doc__", "") or "")
        # Preserved so CrewAI can still derive the function-calling schema.
        self.args_schema = getattr(tool, "args_schema", None)
        self.result_as_answer = getattr(tool, "result_as_answer", False)

    # -- clearance ---------------------------------------------------------

    def evaluate(self, *args: Any, **kwargs: Any) -> AegisVerdict:
        params = _collect_params(args, kwargs)
        return self.engine.evaluate(ToolCall(tool=self.name, params=params))

    def _clear_or_block(self, args: tuple, kwargs: dict) -> Optional[str]:
        verdict = self.evaluate(*args, **kwargs)
        if verdict.allowed:
            return None
        if self.on_block == "raise":
            raise AegisBlockedError(verdict)
        return _format_block_feedback(verdict)

    # -- execution ---------------------------------------------------------

    def _execute_inner(self, *args: Any, **kwargs: Any) -> Any:
        inner_run = getattr(self.tool, "_run", None)
        if callable(inner_run):
            return inner_run(*args, **kwargs)
        outer_run = getattr(self.tool, "run", None)
        if callable(outer_run):
            return outer_run(*args, **kwargs)
        if callable(self.tool):
            return self.tool(*args, **kwargs)
        raise TypeError(f"Wrapped CrewAI tool {self.tool!r} is not executable")

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        blocked = self._clear_or_block(args, kwargs)
        if blocked is not None:
            return blocked
        return self._execute_inner(*args, **kwargs)

    def run(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        blocked = self._clear_or_block(args, kwargs)
        if blocked is not None:
            return blocked
        inner = getattr(self.tool, "_arun", None)
        if callable(inner):
            return await inner(*args, **kwargs)
        result = self._execute_inner(*args, **kwargs)
        if asyncio.iscoroutine(result):
            return await result
        return result

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._run(*args, **kwargs)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"AegisGuardedTool(name={self.name!r}, on_block={self.on_block!r})"


def guard_tool(
    tool: Any,
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
    tool_name: Optional[str] = None,
) -> AegisGuardedTool:
    """Wrap a single CrewAI tool (BaseTool instance or callable)."""
    return AegisGuardedTool(tool, engine=engine, on_block=on_block, tool_name=tool_name)


def guard_tools(
    tools: Iterable[Any],
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
) -> List[AegisGuardedTool]:
    """Wrap a list of CrewAI tools, sharing one engine (one policy commitment hash)."""
    shared = engine or AegisEngine()
    return [
        t if isinstance(t, AegisGuardedTool) else AegisGuardedTool(t, engine=shared, on_block=on_block)
        for t in tools
    ]


def guard_agent(agent: Any, engine: Optional[AegisEngine] = None, on_block: str = "feedback") -> Any:
    """Replace ``agent.tools`` in place with Aegis-guarded equivalents. Returns the agent."""
    tools = getattr(agent, "tools", None)
    if tools:
        agent.tools = guard_tools(tools, engine=engine, on_block=on_block)
    return agent


def guard_crew(crew: Any, engine: Optional[AegisEngine] = None, on_block: str = "feedback") -> Any:
    """
    One-line hardening for an entire Crew: every tool of every agent is wrapped
    with the same engine so the whole crew shares a single auditable policy.
    """
    shared = engine or AegisEngine()
    for agent in getattr(crew, "agents", []) or []:
        guard_agent(agent, engine=shared, on_block=on_block)
    return crew


def aegis_crewai_tool(
    tool_name: Optional[str] = None,
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator for plain-function CrewAI tools (used with ``@tool`` from crewai_tools).

    Example::

        from crewai.tools import tool
        from aegis_kernel_crewai import aegis_crewai_tool

        @tool("Database Query")
        @aegis_crewai_tool(tool_name="database_query")
        def run_query(query: str) -> str:
            return db.execute(query)
    """
    active_engine = engine or AegisEngine()

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        name = tool_name or func.__name__

        def _check(args: tuple, kwargs: dict) -> Optional[str]:
            verdict = active_engine.evaluate(ToolCall(tool=name, params=_collect_params(args, kwargs)))
            if verdict.allowed:
                return None
            if on_block == "raise":
                raise AegisBlockedError(verdict)
            return _format_block_feedback(verdict)

        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                blocked = _check(args, kwargs)
                if blocked is not None:
                    return blocked
                return await func(*args, **kwargs)

            return async_wrapper

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            blocked = _check(args, kwargs)
            if blocked is not None:
                return blocked
            return func(*args, **kwargs)

        return sync_wrapper

    return decorator
