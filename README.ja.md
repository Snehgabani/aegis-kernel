# Aegis Invariant Kernel (日本語)

> **自律型 AI エージェント向け 決定論的ツール実行セキュリティゲートウェイ**  
> *レイテンシ <1.5ms • 外部ネットワーク送信ゼロ • 決定論的 AST ポリシー & 状態不変条件*

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://pypi.org/project/aegis-kernel/)
[![Adversarial Benchmark](https://img.shields.io/badge/F1%20Score-100.0%25-brightgreen.svg)](./packages/evals)

---

## 🚀 概要

**Aegis** は、自律型 AI エージェントによる意図しない破壊的アクションや情報漏洩を防止する、超高速インプロセス・セキュリティカーネルです。エージェントがツール（データベース、送金 API、ファイル操作など）を実行する直前にインターセプトし、**1.5ミリ秒以内** に抽象構文木（AST）および状態不変条件の厳密な検証を行います。

### 主な特徴

1. **決定論的 SQL AST 検証**: PostgreSQL、MySQL、SQLite 等に対応し、コメント分割回避（`DEL/**/ETE`）や恒真条件（`WHERE 1=1`）を確実に検知・ブロック。
2. **数値・財務上限ガード**: 通貨の自動正規化と BigInt 安全処理により、設定された上限を超える不正な送金・トランザクションを防御。
3. **機密情報・PII マスキング**: JWT トークン、クラウド認証鍵、DB 接続情報、クレジットカード番号をミリ秒未満でマスク。
4. **暗号署名監査ログ**: すべてのイベントに SHA-256 `proofHash` を発行し、改ざん不能なコンプライアンス証跡を保証。
5. **主要フレームワーク対応**: Model Context Protocol (MCP)、LangChain、OpenAI、Anthropic Claude に対応。

---

## ⚡ Python クイックスタート（外部依存ゼロ）

```python
from aegis_kernel import aegis_guard

@aegis_guard(tool_name="database_exec")
def execute_sql(query: str):
    # WHERE 句のない一括 DELETE や DROP TABLE は自動的に遮断されます
    return db.execute(query)
```

---

## 📦 Node.js / TypeScript インストール

```bash
npm install @aegis-kernel/core @aegis-kernel/mcp
```
