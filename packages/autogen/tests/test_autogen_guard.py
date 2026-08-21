"""Tests for AutoGen guards (duck-typed, no autogen dependency)."""

import asyncio

import pytest

from aegis_kernel import AegisBlockedError, AegisEngine
from aegis_kernel_autogen import (
    AegisGuardedFunctionTool,
    guard_agent,
    guard_function,
    guard_function_map,
    guard_tool,
)


def execute_sql(query: str) -> str:
    """Run a SQL statement."""
    return f"EXECUTED: {query}"


def test_guard_function_allows_safe_calls():
    guarded = guard_function(execute_sql)
    assert guarded(query="SELECT * FROM users WHERE id = 7") == "EXECUTED: SELECT * FROM users WHERE id = 7"


def test_guard_function_preserves_metadata_for_autogen_schema():
    guarded = guard_function(execute_sql)
    assert guarded.__name__ == "execute_sql"
    assert guarded.__doc__ == "Run a SQL statement."


def test_guard_function_blocks_with_structured_payload():
    guarded = guard_function(execute_sql)
    result = guarded(query="DROP TABLE users;")
    assert result["error"] is True
    assert result["status"] == "AEGIS_BLOCKED"
    assert result["rule_id"] == "SQL-002"
    assert len(result["proof_hash"]) == 64


def test_guard_function_raise_mode():
    guarded = guard_function(execute_sql, on_block="raise")
    with pytest.raises(AegisBlockedError):
        guarded(query="TRUNCATE TABLE audit;")


def test_guard_async_function():
    async def transfer(amount: float) -> str:
        return "SENT"

    guarded = guard_function(transfer, tool_name="wire_transfer")
    assert asyncio.run(guarded(amount=50)) == "SENT"
    blocked = asyncio.run(guarded(amount=999999))
    assert blocked["status"] == "AEGIS_BLOCKED"
    assert blocked["rule_id"] == "FIN-001"


def test_guard_function_map_legacy_agent():
    class LegacyExecutor:
        def __init__(self):
            self._function_map = {"execute_sql": execute_sql}

    agent = LegacyExecutor()
    guard_function_map(agent)
    blocked = agent._function_map["execute_sql"](query="DROP TABLE t")
    assert blocked["status"] == "AEGIS_BLOCKED"


class FakeFunctionTool:
    """Duck-typed stand-in for autogen_core.tools.FunctionTool."""

    name = "database_query"
    description = "Runs SQL."
    schema = {"parameters": {"query": {"type": "string"}}}

    async def run_json(self, args, cancellation_token=None, **kwargs):
        return {"ok": True, "query": args["query"]}

    async def run(self, args, cancellation_token=None, **kwargs):
        return {"ok": True}

    def return_value_as_string(self, value):
        return str(value)


def test_guarded_function_tool_run_json():
    tool = guard_tool(FakeFunctionTool())
    assert isinstance(tool, AegisGuardedFunctionTool)
    assert tool.name == "database_query"
    assert tool.schema == {"parameters": {"query": {"type": "string"}}}

    ok = asyncio.run(tool.run_json({"query": "SELECT 1"}))
    assert ok == {"ok": True, "query": "SELECT 1"}

    blocked = asyncio.run(tool.run_json({"query": "DELETE FROM orders"}))
    assert blocked["status"] == "AEGIS_BLOCKED"
    assert blocked["rule_id"] == "SQL-001"


def test_guard_agent_wraps_modern_tools_list():
    class ModernAgent:
        def __init__(self):
            self._tools = [FakeFunctionTool()]

    agent = guard_agent(ModernAgent())
    assert isinstance(agent._tools[0], AegisGuardedFunctionTool)


def test_guard_tool_falls_back_to_callable():
    guarded = guard_tool(execute_sql)
    assert callable(guarded)
    assert guarded(query="SELECT 1") == "EXECUTED: SELECT 1"


def test_shared_engine_policy_commitment():
    engine = AegisEngine()
    f1 = guard_function(execute_sql, engine=engine)
    t1 = guard_tool(FakeFunctionTool(), engine=engine)
    assert f1.__aegis_engine__ is engine
    assert t1.engine is engine
