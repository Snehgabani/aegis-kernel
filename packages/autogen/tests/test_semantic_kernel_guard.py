"""Tests for the Semantic Kernel invocation filter (duck-typed, no semantic-kernel dependency)."""

import asyncio

import pytest

from aegis_kernel import AegisBlockedError, AegisEngine
from aegis_kernel_autogen import (
    AegisSemanticKernelFilter,
    add_aegis_filter,
    aegis_invocation_filter,
)


class FakeFunction:
    def __init__(self, name="query_db", plugin_name="DatabasePlugin"):
        self.name = name
        self.plugin_name = plugin_name


class FakeContext:
    def __init__(self, arguments, function=None):
        self.function = function or FakeFunction()
        self.arguments = arguments
        self.result = None


def _run_filter(filt, context):
    called = {"next": False}

    async def next_(ctx):
        called["next"] = True
        ctx.result = "FUNCTION_EXECUTED"

    asyncio.run(filt(context, next_))
    return called["next"]


def test_filter_allows_safe_invocation():
    filt = aegis_invocation_filter()
    ctx = FakeContext({"query": "SELECT name FROM customers WHERE id = 3"})
    assert _run_filter(filt, ctx) is True
    assert ctx.result == "FUNCTION_EXECUTED"


def test_filter_blocks_and_short_circuits():
    filt = aegis_invocation_filter()
    ctx = FakeContext({"query": "DROP TABLE customers;"})
    assert _run_filter(filt, ctx) is False  # next() never invoked
    assert isinstance(ctx.result, str)
    assert ctx.result.startswith("AEGIS_BLOCKED:")
    assert "SQL-002" in ctx.result


def test_filter_raise_mode():
    filt = aegis_invocation_filter(on_block="raise")
    ctx = FakeContext({"query": "TRUNCATE TABLE audit;"})
    with pytest.raises(AegisBlockedError):
        _run_filter(filt, ctx)


def test_filter_tool_name_includes_plugin():
    engine = AegisEngine(rules=[{
        "id": "STATE-TEST",
        "pack_id": "custom",
        "type": "numeric",
        "params": {"field": "amount", "max": 10},
    }])
    filt = AegisSemanticKernelFilter(engine=engine)
    ctx = FakeContext({"amount": 5}, function=FakeFunction(name="transfer", plugin_name="Payments"))
    assert _run_filter(filt, ctx) is True


def test_add_aegis_filter_duck_typed_kernel():
    registered = {}

    class FakeKernel:
        def add_filter(self, filter_type, filt):
            registered["type"] = filter_type
            registered["filter"] = filt

    filt = add_aegis_filter(FakeKernel())
    assert registered["type"] == "function_invocation"
    assert registered["filter"] is filt
    assert isinstance(filt, AegisSemanticKernelFilter)


def test_add_aegis_filter_requires_kernel_contract():
    with pytest.raises(TypeError):
        add_aegis_filter(object())
