"""
Aegis Invariant Kernel — AutoGen & Microsoft Semantic Kernel Middleware
Turn-key deterministic tool-call safety clearance for:

* AutoGen / AG2 (legacy ``pyautogen`` two-agent ``register_function`` pattern)
* autogen-agentchat >= 0.4 (``FunctionTool`` / ``BaseTool`` duck-typed wrappers)
* Microsoft Semantic Kernel (function-invocation filter)

Zero hard dependency on either framework: all integration points are duck-typed.
"""

from .autogen_guard import (
    guard_function,
    guard_function_map,
    guard_agent,
    guard_tool,
    AegisGuardedFunctionTool,
)
from .semantic_kernel_guard import (
    AegisSemanticKernelFilter,
    aegis_invocation_filter,
    add_aegis_filter,
)
from aegis_kernel import AegisEngine, AegisBlockedError, AegisVerdict, ToolCall

__all__ = [
    "guard_function",
    "guard_function_map",
    "guard_agent",
    "guard_tool",
    "AegisGuardedFunctionTool",
    "AegisSemanticKernelFilter",
    "aegis_invocation_filter",
    "add_aegis_filter",
    "AegisEngine",
    "AegisBlockedError",
    "AegisVerdict",
    "ToolCall",
]

__version__ = "1.1.0"
