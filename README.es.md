<div align="center">

# Aegis Invariant Kernel (Español)

> **Pasarela Determinista de Seguridad e Intercepción de Herramientas para Agentes de IA**  
> *Latencia <1.5ms • Cero Fuga de Red • Invariantes de Estado y Políticas Deterministas*

<br/>

[![Live Studio Demo](https://img.shields.io/badge/⚡_Live_Studio-Abrir_Sandbox_Interactivo-10b981?style=for-the-badge&logo=googlechrome&logoColor=white)](https://snehgabani.github.io/aegis-kernel/playground/)
[![Documentación](https://img.shields.io/badge/📖_Documentación-Ver_Guía_de_Arquitectura-3b82f6?style=for-the-badge&logo=gitbook&logoColor=white)](https://snehgabani.github.io/aegis-kernel/)

<br/>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://pypi.org/project/aegis-kernel/)
[![Adversarial Benchmark](https://img.shields.io/badge/F1%20Score-100.0%25-brightgreen.svg)](./packages/evals)

</div>

---

## 🚀 Resumen General

**Aegis** es un núcleo de seguridad en proceso y de latencia ultra baja que protege bases de datos e infraestructuras empresariales contra acciones destructivas o no autorizadas de agentes autónomos de IA. Intercepta llamadas a herramientas (*tool calls*) y aplica invariantes basados en árboles de sintaxis abstracta (AST) y límites numéricos en **menos de 1.5ms**.

### Características Principales

1. **Evaluación Determinista de AST SQL**: Analiza consultas SQL en PostgreSQL, MySQL y SQLite, detectando evasiones por comentarios (`DEL/**/ETE`) y cláusulas tautológicas (`WHERE 1=1`).
2. **Límites Financieros y Numéricos**: Normaliza divisas y restringe transferencias o cantidades dentro de rangos estrictos sin riesgo de desbordamiento.
3. **Enmascaramiento de Datos PII y Secretos**: Detecta tokens JWT, claves de cuentas de servicio GCP, URIs de bases de datos y números de tarjetas de crédito en milisegundos.
4. **Pruebas Criptográficas**: Emite registros inmutables con hashes SHA-256 vinculando cada acción a la política activa.
5. **Compatibilidad Universal**: Adaptadores nativos para Model Context Protocol (MCP), LangChain, CrewAI, OpenAI y Anthropic.

---

## ⚡ Inicio Rápido en Python (Cero Dependencias)

```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # Se bloquea automáticamente si la consulta contiene DELETE masivo o DROP TABLE
    return db.execute(query)
```

---

## 📦 Instalación en Node.js / TypeScript

```bash
npm install @aegis-kernel/core @aegis-kernel/mcp
```
