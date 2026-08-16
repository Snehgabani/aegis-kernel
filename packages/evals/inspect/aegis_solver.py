"""
Aegis Invariant Kernel - UK AI Safety Institute (AISI) Inspect AI Adapter.

This module provides native @solver and @tool interceptors for the UK/US AISI
inspect_ai framework, allowing independent researchers and labs to benchmark
AI agents with and without deterministic invariant protection.
"""

from typing import Any, Callable, Dict, Optional
import time

try:
    from inspect_ai.solver import solver, Solver, TaskState, Generate
    from inspect_ai.tool import Tool, tool
except ImportError:
    # Graceful fallback when inspect_ai is not installed in local environment
    def solver(func):
        return func
    def tool(func):
        return func
    Solver = Any
    TaskState = Any
    Generate = Any

# Import Python Aegis Engine
try:
    from aegis_kernel.engine import AegisEngine
except ImportError:
    # Minimal in-tree fallback for test isolation
    class AegisEngine:
        def __init__(self, fail_policy: str = "fail-closed", packs: Optional[list] = None):
            self.fail_policy = fail_policy
            self.packs = packs or ["@aegis/sql-guard", "@aegis/soc2-guard"]
        def evaluate(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
            tool_name = tool_call.get("tool", "")
            params = tool_call.get("params", {})
            query = params.get("query", "").upper() if isinstance(params, dict) else ""
            if "DELETE" in query and "WHERE" not in query:
                return {"allowed": False, "violations": [{"rule_id": "SQL-001"}]}
            if "DROP TABLE" in query:
                return {"allowed": False, "violations": [{"rule_id": "SQL-002"}]}
            return {"allowed": True, "violations": []}


@solver
def aegis_guard_solver(
    packs: Optional[list] = None,
    fail_policy: str = "fail-closed",
    log_telemetry: bool = True,
) -> Solver:
    """
    Inspect AI Solver decorator wrapping model tool executions with Aegis Invariant Kernel.
    
    Usage:
        inspect eval agentharm_eval --solver aegis_guard_solver(packs=['@aegis/soc2-guard'])
    """
    engine = AegisEngine(fail_policy=fail_policy, packs=packs)

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        # Step 1: Allow model to propose agent actions
        state = await generate(state)

        # Step 2: Intercept proposed tool calls
        if hasattr(state, "messages") and state.messages:
            last_message = state.messages[-1]
            if hasattr(last_message, "tool_calls") and last_message.tool_calls:
                filtered_tool_calls = []
                for tc in last_message.tool_calls:
                    tool_call_dict = {
                        "tool": tc.function if hasattr(tc, "function") else str(tc),
                        "params": tc.arguments if hasattr(tc, "arguments") else {},
                    }
                    verdict = engine.evaluate(tool_call_dict)
                    if verdict.get("allowed", False):
                        filtered_tool_calls.append(tc)
                    else:
                        # Append invariant rejection event to state metadata
                        if hasattr(state, "metadata") and state.metadata is not None:
                            rejections = state.metadata.setdefault("aegis_rejections", [])
                            rejections.append({
                                "tool": tool_call_dict["tool"],
                                "violations": verdict.get("violations", []),
                                "timestamp": time.time(),
                            })
                last_message.tool_calls = filtered_tool_calls

        return state

    return solve
