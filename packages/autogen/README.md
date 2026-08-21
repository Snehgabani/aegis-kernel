# @aegis-kernel — AutoGen & Semantic Kernel Middleware (`aegis-kernel-autogen`)

Turn-key deterministic safety clearance for [AutoGen / AG2](https://github.com/microsoft/autogen) and [Microsoft Semantic Kernel](https://github.com/microsoft/semantic-kernel) tool invocations — powered by the [Aegis Invariant Kernel](https://github.com/Snehgabani/aegis-kernel).

- **Deterministic** — AST/invariant analysis, not LLM-as-judge.
- **Sub-2ms, in-process** — zero network egress, zero incremental cost per call.
- **Self-healing** — blocked calls return a structured `AEGIS_BLOCKED` payload that the model sees and corrects against.
- **Auditable** — SHA-256 `proof_hash` + policy commitment hash on every verdict.
- **Zero framework pinning** — duck-typed against AutoGen and Semantic Kernel public contracts; neither is a dependency.

## Install

```bash
pip install aegis-kernel-autogen
```

## AutoGen (autogen-agentchat ≥ 0.4)

```python
from autogen_agentchat.agents import AssistantAgent
from aegis_kernel_autogen import guard_function, guard_tool

def execute_sql(query: str) -> str:
    """Run a SQL statement."""
    return db.execute(query)

agent = AssistantAgent(
    name="dba",
    model_client=client,
    tools=[guard_function(execute_sql)],   # blocked calls return AEGIS_BLOCKED payloads
)
```

`guard_tool(...)` wraps `FunctionTool` objects directly (preserving `name`, `description`, and `schema`); `guard_agent(agent)` hardens an existing agent's tool list in place.

## AutoGen legacy (pyautogen / AG2 two-agent pattern)

```python
from aegis_kernel_autogen import guard_function_map

user_proxy.register_function(function_map={"execute_sql": execute_sql})
guard_function_map(user_proxy)   # every registered function is now Aegis-guarded
```

## Microsoft Semantic Kernel

```python
from semantic_kernel import Kernel
from aegis_kernel_autogen import add_aegis_filter

kernel = Kernel()
add_aegis_filter(kernel)   # deterministic clearance on every function invocation
```

Blocked invocations short-circuit *before* the plugin function executes; the result surfaces to the planner as `AEGIS_BLOCKED: ... rule_id=...; suggested_fix=...`.

## Custom policy

```python
from aegis_kernel import AegisEngine
from aegis_kernel_autogen import add_aegis_filter, guard_function

engine = AegisEngine(rules=[
    {"id": "FIN-001", "pack_id": "finance-guard", "type": "numeric",
     "params": {"field": "amount", "max": 5000}},
])
add_aegis_filter(kernel, engine=engine)
tool = guard_function(wire_transfer, engine=engine)   # one shared policy commitment
```

## Links

- [Docs](https://snehgabani.github.io/aegis-kernel/docs/) · [Playground](https://snehgabani.github.io/aegis-kernel/playground/) · [Core repo](https://github.com/Snehgabani/aegis-kernel)

MIT © Sneh Gabani
