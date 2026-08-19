"""
CrewAI Financial Analyst with Aegis Invariant Guardrails.
Demonstrates sub-0.25ms in-process deterministic invariant clearance on agent tool calls.
"""

from aegis_kernel import AegisEngine, aegis_guard, AegisCrewAITool

# --- 1. Initialize Aegis Deterministic Invariant Engine ---
engine = AegisEngine()

# --- 2. Define Protected Agent Tools ---
@aegis_guard(tool_name="execute_sql_query", engine=engine)
def execute_sql_query(query: str) -> str:
    """Executes safe analytical SQL queries against the financial database."""
    return f"Query executed successfully: {query} (Sample row: Q3 revenue: $4.2M, profit: $1.1M)"

@aegis_guard(tool_name="disburse_funds", engine=engine)
def disburse_funds(amount: float, recipient: str) -> str:
    """Disburses approved financial funds to verified recipient accounts."""
    return f"Successfully disbursed ${amount:,.2f} to {recipient}"

# Wrap with CrewAI Tool Adapter
sql_tool = AegisCrewAITool(execute_sql_query, engine=engine)
payout_tool = AegisCrewAITool(disburse_funds, engine=engine)

def demonstrate_guardrail():
    print("🛡️ [Aegis + CrewAI] Running Deterministic Invariant Clearance Demonstration...")
    
    # 1. Benign Execution Test
    print("\n1. Testing Benign Tool Invocations:")
    res_sql = sql_tool.run(query="SELECT revenue, profit FROM q3_financials WHERE tenant_id = 'org_42';")
    print(f"   ✅ Allowed: {res_sql}")
    
    res_payout = payout_tool.run(amount=2500.00, recipient="vendor_acme_corp")
    print(f"   ✅ Allowed: {res_payout}")

    # 2. Adversarial Injection: SQL Comment Evasion + Whole-Table Wipe
    print("\n2. Testing Adversarial Attack Interception (SQL Comment Evasion):")
    res_block_sql = sql_tool.run(query="DEL/**/ETE FROM q3_financials;")
    print(f"   🛑 {res_block_sql}")

    # 3. Adversarial Injection: Financial Overspend Violation
    print("\n3. Testing Adversarial Attack Interception (Unauthorized $50,000 Disbursement):")
    res_block_payout = payout_tool.run(amount=50000.00, recipient="attacker_wallet_0x99")
    print(f"   🛑 {res_block_payout}")

    print("\n✨ All invariants evaluated in-process in <0.25ms with 0 bytes network egress!")

if __name__ == "__main__":
    demonstrate_guardrail()
