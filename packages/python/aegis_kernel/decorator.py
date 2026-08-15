import asyncio
import functools
from typing import Any, Callable, Optional, List, Dict
from .engine import AegisEngine
from .types import ToolCall, AegisVerdict

class AegisBlockedError(Exception):
    def __init__(self, verdict: AegisVerdict):
        self.verdict = verdict
        rule_info = verdict.violations[0].rule_id if verdict.violations else "INVARIANT-POLICY"
        msg_info = verdict.violations[0].message if verdict.violations else "Security policy constraint violated"
        msg = f"Aegis Invariant Violation: Tool execution blocked. Rule: {rule_info} - {msg_info}"
        super().__init__(msg)

def aegis_guard(
    tool_name: Optional[str] = None,
    mode: str = "enforce",
    rules: Optional[List[Dict[str, Any]]] = None,
    engine: Optional[AegisEngine] = None
):
    """
    Decorator to wrap Python agent tool functions (sync or async coroutines)
    with sub-2ms deterministic Aegis invariant verification.
    """
    active_engine = engine if engine is not None else AegisEngine(mode=mode, rules=rules)

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        actual_name = tool_name or func.__name__

        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                params = dict(kwargs)
                if args:
                    params["_args"] = list(args)

                tool_call = ToolCall(tool=actual_name, params=params)
                verdict = active_engine.evaluate(tool_call)

                if not verdict.allowed:
                    raise AegisBlockedError(verdict)

                return await func(*args, **kwargs)

            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                params = dict(kwargs)
                if args:
                    params["_args"] = list(args)

                tool_call = ToolCall(tool=actual_name, params=params)
                verdict = active_engine.evaluate(tool_call)

                if not verdict.allowed:
                    raise AegisBlockedError(verdict)

                return func(*args, **kwargs)

            return sync_wrapper

    return decorator
