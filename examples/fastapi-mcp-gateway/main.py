from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import StreamingResponse
import asyncio
import json
import sqlite3
import os
import uuid

# Mocking Aegis imports
from aegis_kernel import AegisGuard, detect_injection, SQLGuard

app = FastAPI(title="FastAPI MCP Gateway with Aegis Kernel")

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
            status TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Aegis Kernel Decorators and Guards ---
aegis = AegisGuard(
    policy="mcp_strict",
    nhi_spend_limit=50,
    features=["streaming_filter", "sql_safety"]
)

sql_guard = SQLGuard(dialect="sqlite")

def log_audit(action: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # SQLGuard checks for injection attempts before execution
    safe_action = sql_guard.sanitize(action)
    cursor.execute("INSERT INTO audit_logs (id, action, status) VALUES (?, ?, ?)", (str(uuid.uuid4()), safe_action, status))
    conn.commit()
    conn.close()

# --- Endpoints ---

@app.post("/mcp/proxy")
@aegis.protect()
async def mcp_proxy(request: Request):
    try:
        body = await request.json()
        query = body.get("query", "")
        
        # Immediate Aegis check
        if detect_injection(query):
            log_audit(action=query[:50], status="BLOCKED_INJECTION")
            raise HTTPException(status_code=403, detail="Aegis: Threat detected in input.")
            
        # Simulate MCP response
        log_audit(action=query[:50], status="ALLOWED")
        return {"status": "success", "result": f"Processed safely: {query}"}
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")

async def token_generator(prompt: str):
    tokens = ["Processing", " request", " for", f" '{prompt}'.", " Access", " granted."]
    for token in tokens:
        # Aegis streaming filter: inspect each token
        safe_token = aegis.filter_token(token)
        if safe_token:
            yield f"data: {safe_token}\n\n"
        else:
            yield f"data: [REDACTED]\n\n"
        await asyncio.sleep(0.1)

@app.get("/mcp/stream")
async def mcp_stream(prompt: str):
    if detect_injection(prompt):
        log_audit(action=prompt[:50], status="BLOCKED_STREAM_INJECTION")
        raise HTTPException(status_code=403, detail="Aegis: Threat detected.")
    
    log_audit(action=prompt[:50], status="STREAM_STARTED")
    return StreamingResponse(token_generator(prompt), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
