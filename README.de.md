# Aegis Invariant Kernel (Deutsch)

> **Deterministisches Tool-Call-Sicherheitsgateway für autonome KI-Agenten**  
> *Latenz <1,5ms • Kein Netzwerk-Egress • Deterministische AST-Richtlinien & Zustandsinvarianten*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://pypi.org/project/aegis-kernel/)
[![Adversarial Benchmark](https://img.shields.io/badge/F1%20Score-100.0%25-brightgreen.svg)](./packages/evals)

---

## 🚀 Übersicht

**Aegis** ist ein extrem schneller, prozessinterner Sicherheitskern zum Schutz von Produktionsumgebungen vor unkontrollierten Aktionen autonomer KI-Agenten. Aegis fängt Tool-Aufrufe (Datenbankabfragen, Finanztransaktionen, Dateiänderungen) vor deren Ausführung ab und prüft deterministische AST- und Zustandsinvarianten in **unter 1,5 ms**.

### Hauptmerkmale

1. **Deterministische SQL-AST-Prüfung**: Unterstützt PostgreSQL, MySQL und SQLite; blockiert Kommentar-Umgehungen (`DEL/**/ETE`) und Tautologien (`WHERE 1=1`).
2. **Finanzielle Risikogrenzen**: Validiert formatierte Währungen und BigInt-Beträge unter strikter Einhaltung konfigurierter Limite.
3. **PII- & Secrets-Maskierung**: Erkennt JWT-Tokens, Cloud-API-Schlüssel und Kreditkartendaten in Submillisekunden.
4. **Kryptografische Prüfprotokolle**: Erzeugt unveränderliche SHA-256 `proofHash`-Ereignisse für lückenlose Compliance-Nachweise.
5. **Universelle Framework-Unterstützung**: Native Adapter für Model Context Protocol (MCP), LangChain, OpenAI und Anthropic.

---

## ⚡ Python Schnellstart (Keine externen Abhängigkeiten)

```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # Wird blockiert, wenn die Abfrage Massenlöschungen ohne WHERE oder DROP enthält
    return db.execute(query)
```

---

## 📦 Node.js / TypeScript Installation

```bash
npm install @aegis-kernel/core @aegis-kernel/mcp
```
