"""
Microsoft Semantic Kernel function-invocation filter backed by Aegis.

Usage (Semantic Kernel Python >= 1.0)::

    from semantic_kernel import Kernel
    from aegis_kernel_autogen import add_aegis_filter

    kernel = Kernel()
    add_aegis_filter(kernel)                 # every function invocation is now guarded

or explicitly::

    from semantic_kernel.filters import FilterTypes
    from aegis_kernel_autogen import aegis_invocation_filter

    kernel.add_filter(FilterTypes.FUNCTION_INVOCATION, aegis_invocation_filter())

The filter is duck-typed against Semantic Kernel's
``FunctionInvocationContext`` contract (``context.function.name``,
``context.function.plugin_name``, ``context.arguments`` mapping,
``context.result``), so this package does not depend on ``semantic-kernel``.
"""

from typing import Any, Awaitable, Callable, Dict, Optional

from aegis_kernel import AegisBlockedError, AegisEngine, ToolCall
from aegis_kernel.types import AegisVerdict

_ON_BLOCK_MODES = ("feedback", "raise")


def _block_message(verdict: AegisVerdict) -> str:
    v = verdict.violations[0] if verdict.violations else None
    rule_id = v.rule_id if v else "INVARIANT-POLICY"
    message = v.message if v else "Security policy constraint violated."
    fix = (v.suggested_fix if v else None) or "Adhere to policy bounds and retry."
    return (
        "AEGIS_BLOCKED: Function invocation denied by deterministic invariant. "
        f"rule_id={rule_id}; reason={message}; suggested_fix={fix}; "
        f"proof_hash={verdict.proof_hash}"
    )


def _extract_tool_name(context: Any) -> str:
    fn = getattr(context, "function", None)
    name = getattr(fn, "name", None) or "sk_function"
    plugin = getattr(fn, "plugin_name", None)
    return f"{plugin}-{name}" if plugin else name


def _extract_params(context: Any) -> Dict[str, Any]:
    arguments = getattr(context, "arguments", None)
    if arguments is None:
        return {}
    try:
        return dict(arguments)
    except (TypeError, ValueError):
        return {"_arguments": str(arguments)}


def _set_blocked_result(context: Any, message: str) -> None:
    """Set a FunctionResult on the context when semantic-kernel is installed,
    otherwise fall back to assigning the raw message."""
    try:
        from semantic_kernel.functions import FunctionResult  # type: ignore

        context.result = FunctionResult(
            function=context.function.metadata if hasattr(context.function, "metadata") else context.function,
            value=message,
            metadata={"aegis_blocked": True},
        )
    except Exception:
        context.result = message


class AegisSemanticKernelFilter:
    """Async function-invocation filter: clearance before ``next(context)``."""

    def __init__(self, engine: Optional[AegisEngine] = None, on_block: str = "feedback"):
        if on_block not in _ON_BLOCK_MODES:
            raise ValueError(f"on_block must be one of {_ON_BLOCK_MODES}")
        self.engine = engine or AegisEngine()
        self.on_block = on_block

    async def __call__(self, context: Any, next: Callable[[Any], Awaitable[None]]) -> None:
        tool_call = ToolCall(tool=_extract_tool_name(context), params=_extract_params(context))
        verdict = self.engine.evaluate(tool_call)

        if not verdict.allowed:
            if self.on_block == "raise":
                raise AegisBlockedError(verdict)
            _set_blocked_result(context, _block_message(verdict))
            return  # short-circuit: the guarded function is never invoked

        await next(context)


def aegis_invocation_filter(
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
) -> AegisSemanticKernelFilter:
    """Build a filter coroutine compatible with ``kernel.add_filter(...)``."""
    return AegisSemanticKernelFilter(engine=engine, on_block=on_block)


def add_aegis_filter(
    kernel: Any,
    engine: Optional[AegisEngine] = None,
    on_block: str = "feedback",
) -> AegisSemanticKernelFilter:
    """
    One-line hardening for a Semantic Kernel instance. Returns the filter so
    callers can keep a handle on the shared engine.
    """
    filt = aegis_invocation_filter(engine=engine, on_block=on_block)
    add = getattr(kernel, "add_filter", None)
    if not callable(add):
        raise TypeError("kernel does not expose add_filter(); pass a semantic_kernel.Kernel instance")
    try:
        from semantic_kernel.filters import FilterTypes  # type: ignore

        add(FilterTypes.FUNCTION_INVOCATION, filt)
    except ImportError:
        add("function_invocation", filt)
    return filt
