"""
AutoGen / AG2 guards backed by the Aegis Invariant Kernel engine.

Blocked calls return a structured JSON-serializable dict (AutoGen surfaces tool
results back to the model, enabling self-correction) unless ``on_block="raise"``.
"""

import asyncio
import functools
import json
from typing import Any, Callable, Dict, Optional

from aegis_kernel import AegisBlockedError, AegisEngine, ToolCall
from aegis_kernel.types import AegisVerdict

_ON_BLOCK_MODES = ("feedback", "raise")


def _block_payload(verdict: AegisVerdict) -> Dict[str, Any]:
    v = verdict.violations[0] if verdict.violations else None
    return {
        "error": True,
        "status": "AEGIS_BLOCKED",
        "rule_id": v.rule_id if v else "INVARIANT-POLICY",
        "severity": v.severity if v else "critical",
        "message": v.message if v else "Security policy constraint violated.",
        "suggested_fix": (v.suggested_fix if v else None) or "Adhere to policy bounds and retry.",
        "proof_hash": verdict.proof_hash,
        "policy_commitment_hash": verdict.policy_commitment_hash,
    }


def _collect_params(args: tuple, kwargs: dict) -> dict:
    params = dict(kwargs)
    if args:
        params["_args"] = list(args)
    return params


def guard_function(
    func: Callable[..., Any],
    engine: Optional[AegisEngine] = None,
    tool_name: Optional[str] = None,
    on_block: str = "feedback",
) -> Callable[..., Any]:
    """
    Wrap a plain AutoGen tool function (sync or async) with invariant clearance.

    Works with both the legacy ``register_function(f, caller=..., executor=...)``
    pattern and the modern ``AssistantAgent(tools=[f])`` pattern — AutoGen
    inspects ``__name__``/``__doc__``/signature, all preserved by ``functools.wraps``.
    """
    if on_block not in _ON_BLOCK_MODES:
        raise ValueError(f"on_block must be one of {_ON_BLOCK_MODES}")
    eng = engine or AegisEngine()
    name = tool_name or getattr(func, "__name__", "autogen_tool")

    def _check(args: tuple, kwargs: dict) -> Optional[Dict[str, Any]]:
        verdict = eng.evaluate(ToolCall(tool=name, params=_collect_params(args, kwargs)))
        if verdict.allowed:
            return None
        if on_block == "raise":
            raise AegisBlockedError(verdict)
        return _block_payload(verdict)

    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            blocked = _check(args, kwargs)
            if blocked is not None:
                return blocked
            return await func(*args, **kwargs)

        async_wrapper.__aegis_engine__ = eng  # type: ignore[attr-defined]
        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        blocked = _check(args, kwargs)
        if blocked is not None:
            return blocked
        return func(*args, **kwargs)

    sync_wrapper.__aegis_engine__ = eng  # type: ignore[attr-defined]
    return sync_wrapper


def guard_function_map(
    agent: Any,
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
) -> Any:
    """
    Harden a legacy AutoGen ``UserProxyAgent``/``ConversableAgent`` executor in
    place by wrapping every entry of its registered ``_function_map``.
    """
    shared = engine or AegisEngine()
    fmap = getattr(agent, "_function_map", None)
    if isinstance(fmap, dict):
        for fname, fn in list(fmap.items()):
            fmap[fname] = guard_function(fn, engine=shared, tool_name=fname, on_block=on_block)
    return agent


class AegisGuardedFunctionTool:
    """
    Duck-typed wrapper for autogen-core ``FunctionTool`` / ``BaseTool`` objects
    (autogen-agentchat >= 0.4). Preserves ``name``, ``description``, and
    ``schema`` so model-side tool binding is unchanged; intercepts ``run`` and
    ``run_json``.
    """

    def __init__(
        self,
        tool: Any,
        engine: Optional[AegisEngine] = None,
        on_block: str = "feedback",
    ):
        if on_block not in _ON_BLOCK_MODES:
            raise ValueError(f"on_block must be one of {_ON_BLOCK_MODES}")
        self.tool = tool
        self.engine = engine or AegisEngine()
        self.on_block = on_block
        self.name = getattr(tool, "name", getattr(tool, "__name__", "autogen_tool"))
        self.description = getattr(tool, "description", "")

    @property
    def schema(self) -> Any:
        return getattr(self.tool, "schema", None)

    def _check(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        verdict = self.engine.evaluate(ToolCall(tool=self.name, params=params))
        if verdict.allowed:
            return None
        if self.on_block == "raise":
            raise AegisBlockedError(verdict)
        return _block_payload(verdict)

    async def run_json(self, args: Dict[str, Any], cancellation_token: Any = None, **kwargs: Any) -> Any:
        blocked = self._check(dict(args))
        if blocked is not None:
            return blocked
        inner = getattr(self.tool, "run_json", None)
        if callable(inner):
            return await inner(args, cancellation_token, **kwargs)
        raise TypeError(f"Wrapped tool {self.tool!r} has no run_json")

    async def run(self, args: Any, cancellation_token: Any = None, **kwargs: Any) -> Any:
        params = dict(args) if isinstance(args, dict) else {"_args": [args]}
        blocked = self._check(params)
        if blocked is not None:
            return blocked
        inner = getattr(self.tool, "run", None)
        if callable(inner):
            result = inner(args, cancellation_token, **kwargs)
            if asyncio.iscoroutine(result):
                return await result
            return result
        raise TypeError(f"Wrapped tool {self.tool!r} has no run")

    def return_value_as_string(self, value: Any) -> str:
        inner = getattr(self.tool, "return_value_as_string", None)
        if callable(inner):
            return inner(value)
        return value if isinstance(value, str) else json.dumps(value, default=str)


def guard_tool(
    tool: Any,
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
) -> Any:
    """Wrap an autogen-core tool object, or fall back to function wrapping for callables."""
    if callable(tool) and not hasattr(tool, "run") and not hasattr(tool, "run_json"):
        return guard_function(tool, engine=engine, on_block=on_block)
    return AegisGuardedFunctionTool(tool, engine=engine, on_block=on_block)


def guard_agent(agent: Any, engine: Optional[AegisEngine] = None, on_block: str = "feedback") -> Any:
    """
    One-line hardening for an AutoGen agent:

    * legacy agents: wraps the executor ``_function_map``
    * autogen-agentchat >= 0.4 agents: wraps ``agent._tools`` / ``agent.tools``
    """
    shared = engine or AegisEngine()
    guard_function_map(agent, engine=shared, on_block=on_block)
    for attr in ("_tools", "tools"):
        tools = getattr(agent, attr, None)
        if isinstance(tools, list) and tools:
            setattr(agent, attr, [guard_tool(t, engine=shared, on_block=on_block) for t in tools])
            break
    return agent
