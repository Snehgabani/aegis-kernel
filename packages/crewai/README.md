# @aegis-kernel — CrewAI Middleware (`aegis-kernel-crewai`)

Turn-key, drop-in deterministic safety clearance for [CrewAI](https://github.com/crewAIInc/crewAI) tools, agents, and entire crews — powered by the [Aegis Invariant Kernel](https://github.com/Snehgabani/aegis-kernel).

- **Deterministic** — AST/invariant analysis, not LLM-as-judge. No false-negative roulette.
- **Sub-2ms, in-process** — zero network egress, zero incremental cost per call.
- **Self-healing** — blocked calls return structured `AEGIS_BLOCKED:` feedback that CrewAI feeds back to the LLM so the agent corrects itself.
- **Auditable** — every verdict carries a SHA-256 `proof_hash` and policy commitment hash.
- **Zero framework pinning** — duck-typed against the CrewAI `BaseTool` contract; no `crewai` dependency in this package.

## Install

```bash
pip install aegis-kernel-crewai
```

## Quickstart — one line hardens the whole crew

```python
from crewai import Agent, Crew, Task
from aegis_kernel_crewai import guard_crew

crew = Crew(agents=[analyst, dba], tasks=[task])
guard_crew(crew)          # every tool of every agent is now Aegis-guarded
crew.kickoff()
```

## Wrap a single tool

```python
from aegis_kernel_crewai import guard_tool

safe_sql_tool = guard_tool(sql_tool)                    # feedback mode (default)
strict_tool   = guard_tool(sql_tool, on_block="raise")  # raise AegisBlockedError
```

## Decorator for function tools

```python
from crewai.tools import tool
from aegis_kernel_crewai import aegis_crewai_tool

@tool("Database Query")
@aegis_crewai_tool(tool_name="database_query")
def run_query(query: str) -> str:
    return db.execute(query)
```

## Custom policy

```python
from aegis_kernel import AegisEngine
from aegis_kernel_crewai import guard_crew

engine = AegisEngine(rules=[
    {"id": "FIN-001", "pack_id": "finance-guard", "type": "numeric",
     "params": {"field": "amount", "max": 5000}},
    {"id": "SQL-002", "pack_id": "sql-guard", "type": "sql",
     "params": {"block_statements": ["DROP", "TRUNCATE", "ALTER", "GRANT"]}},
])
guard_crew(crew, engine=engine)
```

## What gets blocked out of the box

| Rule | Blocks |
|------|--------|
| `SQL-001` | `DELETE`/`UPDATE` without a `WHERE` clause (incl. `1=1` tautologies) |
| `SQL-002` | `DROP`, `TRUNCATE`, `ALTER` |
| `FIN-001` | `amount > 10000` |
| `DATA-001/002` | Credit cards, SSNs, API keys/tokens in tool params |
| `SOC2-001`, `HIPAA-001` | Sensitive file paths, NPI/DEA identifiers |

## Links

- [Docs](https://snehgabani.github.io/aegis-kernel/docs/) · [Playground](https://snehgabani.github.io/aegis-kernel/playground/) · [Core repo](https://github.com/Snehgabani/aegis-kernel)

MIT © Sneh Gabani
