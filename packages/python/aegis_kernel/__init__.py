"""
Aegis Invariant Kernel for Python
Deterministic, sub-2ms safety clearance gateway for AI Agent tool execution.
"""

from .types import AegisVerdict, AegisViolation, ToolCall, AegisConfig
from .engine import AegisEngine
from .decorator import aegis_guard, AegisBlockedError
from .checkers import PythonStateChecker, PythonPiiTokenVault
from .adapters import AegisCrewAITool, wrap_autogen_function, AegisLangChainTool, wrap_langchain_tool

__all__ = [
    "AegisVerdict",
    "AegisViolation",
    "ToolCall",
    "AegisConfig",
    "AegisEngine",
    "aegis_guard",
    "AegisBlockedError",
    "AegisCrewAITool",
    "wrap_autogen_function",
    "AegisLangChainTool",
    "wrap_langchain_tool",
    "PythonStateChecker",
    "PythonPiiTokenVault",
]

__version__ = "1.1.0"


