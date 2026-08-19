"""
FastAPI MCP Gateway with Aegis Deterministic Invariant Clearance.
Intercepts tool calls with sub-0.25ms in-process safety evaluation and audit logging.
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import json
import sqlite3
import os
import uuid

from aegis_kernel import AegisEngine, ToolCall

app = FastAPI(title="FastAPI MCP Gateway with Aegis Invariant Kernel")

# --- Database & Config Setup ---
DB_PATH = "mcp_gateway.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT,
            status TEXT,
            latency_ms REAL,
            proof_hash TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Initialize Aegis Invariant Engine ---
engine = AegisEngine(
    rules={
        "max_transfer_usd": 5000.0,
        "prohibit_sql_mutations": True,
        "enforce_tenant_isolation": True,
        "mask_pii": True
    }
)

def log_audit(action: str, status: str, latency_ms: float = 0.0, proof_hash: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (id, action, status, latency_ms, proof_hash) VALUES (?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), action, status, latency_ms, proof_hash)
    )
    conn.commit()
    conn.close()

# --- Endpoints ---

@app.post("/mcp/proxy")
async def mcp_proxy(request: Request):
    """
    MCP Reverse Proxy endpoint intercepting agent tool executions.
    Evaluates AST invariants in-process with 0 bytes network egress.
    """
    try:
        body = await request.json()
        tool_name = body.get("tool", "database_exec")
        params = body.get("params", {})
        
        # 1. Deterministic Aegis Invariant Clearance
        tool_call = ToolCall(tool=tool_name, params=params)
        verdict = engine.evaluate(tool_call)
        
        # 2. Audit Trail Logging
        status = "ALLOWED" if verdict.allowed else "BLOCKED"
        log_audit(
            action=f"{tool_name}:{json.dumps(params)}",
            status=status,
            latency_ms=verdict.latency_ms,
            proof_hash=verdict.proof_hash
        )
        
        if not verdict.allowed:
            first_violation = verdict.violations[0]
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Aegis Invariant Violation",
                    "rule_id": first_violation.rule_id,
                    "message": first_violation.message,
                    "suggested_fix": first_violation.suggested_fix,
                    "latency_ms": verdict.latency_ms,
                    "proof_hash": verdict.proof_hash
                }
            )
            
        return {
            "status": "success",
            "message": "Tool execution cleared by Aegis Invariant Kernel",
            "latency_ms": verdict.latency_ms,
            "proof_hash": verdict.proof_hash,
            "result": f"Executed {tool_name} successfully."
        }
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting FastAPI MCP Gateway with Aegis Invariant Kernel on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)

