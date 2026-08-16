# Aegis Invariant Kernel for Python

> **Deterministic Tool-Call Safety Gateway for Autonomous AI Agents**  
> *Sub-0.1ms Latency • Zero External Dependencies • Zero Network Egress*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://pypi.org/project/aegis-kernel/)
[![Tests](https://img.shields.io/badge/tests-11%2F11%20passing-brightgreen.svg)](#)

---

## 🚀 Installation

```bash
pip install aegis-kernel
```

---

## ⚡ Quickstart

### Protect Database Tools
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # Automatically blocks destructive SQL (DELETE without WHERE, DROP TABLE, etc.)
    return db.execute(query)
```

### Protect Financial & Payout Operations
```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="payout_tool")
def transfer_funds(amount: float, recipient_id: str):
    # Automatically blocks transactions exceeding numeric risk limits
    return payment_gateway.transfer(amount, recipient_id)
```

### CrewAI & AutoGen Integration
```python
from aegis_kernel import AegisCrewAITool

safe_tool = AegisCrewAITool(my_existing_tool)
```

---

## 📄 License

Distributed under the [MIT License](https://opensource.org/licenses/MIT). Copyright (c) 2026 Sneh Gabani.
