"""Tests for the CrewAI middleware package (duck-typed, no crewai dependency)."""

import asyncio

import pytest

from aegis_kernel import AegisBlockedError, AegisEngine
from aegis_kernel_crewai import (
    AegisGuardedTool,
    aegis_crewai_tool,
    guard_agent,
    guard_crew,
    guard_tool,
    guard_tools,
)


class FakeCrewAITool:
    """Duck-typed stand-in for crewai.tools.BaseTool."""

    name = "database_query"
    description = "Executes SQL against the production database."
    args_schema = {"query": "str"}

    def _run(self, query: str) -> str:
        return f"EXECUTED: {query}"


class FakeAgent:
    def __init__(self, tools):
        self.tools = tools


class FakeCrew:
    def __init__(self, agents):
        self.agents = agents


def test_allows_safe_sql():
    tool = guard_tool(FakeCrewAITool())
    result = tool.run(query="SELECT id FROM users WHERE tenant_id = 42")
    assert result == "EXECUTED: SELECT id FROM users WHERE tenant_id = 42"


def test_blocks_drop_table_with_self_healing_feedback():
    tool = guard_tool(FakeCrewAITool())
    result = tool.run(query="DROP TABLE users;")
    assert isinstance(result, str)
    assert result.startswith("AEGIS_BLOCKED:")
    assert "rule_id=SQL-002" in result
    assert "proof_hash=" in result


def test_blocks_unbounded_delete():
    tool = guard_tool(FakeCrewAITool())
    result = tool.run(query="DELETE FROM orders")
    assert result.startswith("AEGIS_BLOCKED:")
    assert "rule_id=SQL-001" in result


def test_raise_mode_raises_blocked_error():
    tool = guard_tool(FakeCrewAITool(), on_block="raise")
    with pytest.raises(AegisBlockedError):
        tool.run(query="TRUNCATE TABLE audit_log;")


def test_preserves_crewai_tool_contract():
    tool = guard_tool(FakeCrewAITool())
    assert tool.name == "database_query"
    assert "production database" in tool.description
    assert tool.args_schema == {"query": "str"}


def test_numeric_bound_via_custom_engine():
    engine = AegisEngine(rules=[{
        "id": "FIN-CUSTOM",
        "pack_id": "finance-guard",
        "type": "numeric",
        "params": {"field": "amount", "max": 500},
    }])

    def transfer(amount: float) -> str:
        return "SENT"

    guarded = guard_tool(transfer, engine=engine, tool_name="wire_transfer")
    assert guarded.run(amount=100) == "SENT"
    assert guarded.run(amount=50000).startswith("AEGIS_BLOCKED:")


def test_guard_tools_shares_engine():
    tools = guard_tools([FakeCrewAITool(), lambda q: q])
    assert len(tools) == 2
    assert tools[0].engine is tools[1].engine


def test_guard_agent_and_crew():
    crew = FakeCrew([FakeAgent([FakeCrewAITool()]), FakeAgent([FakeCrewAITool()])])
    guard_crew(crew)
    for agent in crew.agents:
        assert all(isinstance(t, AegisGuardedTool) for t in agent.tools)
    # Same policy commitment across the whole crew
    hashes = {t.engine.policy_hash for a in crew.agents for t in a.tools}
    assert len(hashes) == 1
    assert crew.agents[0].tools[0].run(query="DROP TABLE x").startswith("AEGIS_BLOCKED:")


def test_guard_agent_idempotent_on_empty_tools():
    agent = FakeAgent([])
    guard_agent(agent)
    assert agent.tools == []


def test_decorator_sync_and_async():
    @aegis_crewai_tool(tool_name="database_exec")
    def run_sql(query: str) -> str:
        return "OK"

    @aegis_crewai_tool(tool_name="database_exec_async")
    async def run_sql_async(query: str) -> str:
        return "OK"

    assert run_sql(query="SELECT 1") == "OK"
    assert run_sql(query="DROP TABLE t").startswith("AEGIS_BLOCKED:")

    assert asyncio.run(run_sql_async(query="SELECT 1")) == "OK"
    blocked = asyncio.run(run_sql_async(query="DROP TABLE t"))
    assert blocked.startswith("AEGIS_BLOCKED:")


def test_verdict_exposes_proof_hash():
    tool = guard_tool(FakeCrewAITool())
    verdict = tool.evaluate(query="SELECT 1")
    assert verdict.allowed
    assert len(verdict.proof_hash) == 64
    assert len(verdict.policy_commitment_hash) == 64
