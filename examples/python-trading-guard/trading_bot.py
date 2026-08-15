"""
Aegis Invariant Kernel — Production Example: Python FinTech Trading Bot Guard

Demonstrates synchronous and async Python decorators enforcing deterministic
financial ceilings and invariant bounds in <1ms without network egress.
"""

import asyncio
from aegis_kernel import aegis_guard, AegisEngine

# Initialize the pure Python invariant engine
engine = AegisEngine()

# Guarded financial transaction function
@aegis_guard(engine=engine, tool_name="place_order")
def execute_trade(symbol: str, amount: float, account_id: str):
    print(f"💰 Trade Executed: {symbol} - ${amount:.2f} for account {account_id}")
    return {"status": "FILLED", "amount": amount}

# Guarded async disbursement coroutine
@aegis_guard(engine=engine, tool_name="send_payout")
async def async_payout(recipient: str, amount: float):
    await asyncio.sleep(0.01) # Simulated network call
    print(f"💸 Payout Sent: ${amount:.2f} to {recipient}")
    return {"status": "DISBURSED", "amount": amount}

def main():
    print("🛡️  Running Python FinTech Trading Guard Example...\n")

    # 1. Legitimate trade below threshold ($10k cap)
    print("Test 1: Safe $500 Trade")
    try:
        execute_trade(symbol="AAPL", amount=500.0, account_id="acc_101")
        print("✅ Trade Successful!\n")
    except Exception as e:
        print("❌ Blocked:", e)

    # 2. Rogue overspend attempt ($85k)
    print("Test 2: Rogue $85,000 Trade")
    try:
        execute_trade(symbol="NVDA", amount=85000.0, account_id="acc_101")
    except Exception as e:
        print(f"🚫 Disaster Prevented by Aegis: {e}\n")

    # 3. Async Payout Test
    print("Test 3: Async Legitimate Payout ($250)")
    asyncio.run(async_payout("vendor@corp.internal", 250.0))
    print("✅ Async Payout Completed Successfully!")

if __name__ == "__main__":
    main()
