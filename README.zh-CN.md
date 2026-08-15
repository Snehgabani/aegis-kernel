# Aegis Invariant Kernel (简体中文)

> **自主 AI Agent 确定性工具调用安全网关**  
> *延迟 <1.5ms • 零网络出站 • 确定性 AST 策略与状态不变量*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://pypi.org/project/aegis-kernel/)
[![Adversarial Benchmark](https://img.shields.io/badge/F1%20Score-100.0%25-brightgreen.svg)](./packages/evals)

---

## 🚀 概述

**Aegis** 是一个超高速、进程内的安全准入内核，旨在防止自主 AI Agent（智能体）执行破坏性或未经授权的系统操作。它在 Agent 发起工具调用（数据库操作、资金转账、文件修改、API 请求）前进行拦截，并在 **1.5 毫秒内** 完成确定性抽象语法树（AST）分析与状态不变量验证。

### 核心优势

1. **确定性多方言 SQL AST 检验**：支持 PostgreSQL、MySQL、SQLite 与 T-SQL，精准识别注释混淆绕过（如 `DEL/**/ETE`）与恒真条件（如 `WHERE 1=1`）。
2. **严格金融与数值边界限制**：支持格式化货币归一化解析与 BigInt 计算，杜绝浮点溢出与越权大额转账。
3. **隐私信息（PII）与密钥脱敏**：亚毫秒级识别 JWT 令牌、GCP 凭据、数据库连接串及信用卡信息。
4. **加密审计存证**：每笔拦截事件均生成唯一的 SHA-256 `proofHash`，满足严格企业合规要求。
5. **主流生态全面集成**：原生支持 Model Context Protocol (MCP)、LangChain、OpenAI Function Calling 与 Anthropic Claude。

---

## ⚡ Python 极速上手（零第三方依赖）

```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # 若 SQL 包含无条件全表 DELETE 或 DROP TABLE，将直接被内核阻断
    return db.execute(query)
```

---

## 📦 TypeScript / Node.js 安装

```bash
npm install @aegis-kernel/core @aegis-kernel/mcp
```
