import os
from crewai import Agent, Task, Crew, Process
from textwrap import dedent

# Mocking Aegis Invariant Kernel imports
from aegis_kernel import NHIManager, SQLGuard, HoneytokenGenerator, AegisPolicy

# --- Aegis Security Setup ---

# 1. Non-Human Identity (NHI) Spend Ceilings
nhi_manager = NHIManager(
    identity="crewai_financial_agent_01",
    spend_ceiling=15.00,  # Max $15 spend for API calls
    enforce_ceiling=True
)

# 2. SQL Guardrails for database interactions
sql_guard = SQLGuard(
    mode="strict",
    prevent_destructive=True,
    allow_select_only=True
)

# 3. Honeytokens
honeytoken_gen = HoneytokenGenerator()
canary_token = honeytoken_gen.create(type="aws_keys", label="crewai_trap")

# Apply Policy
aegis_policy = AegisPolicy(
    rules=["no_exfiltration", "protect_pii", "enforce_nhi_limits"],
    interceptors=[nhi_manager, sql_guard]
)

# --- CrewAI Agents ---

financial_analyst = Agent(
    role='Senior Financial Analyst',
    goal='Analyze market trends and provide investment recommendations.',
    backstory=dedent("""
        You are an expert financial analyst. 
        You use data to make informed decisions.
        You strictly follow Aegis security protocols.
    """),
    verbose=True,
    allow_delegation=False,
    # Inject Aegis tracking into the agent's LLM calls (mocked via interceptor)
    step_callback=lambda step: aegis_policy.monitor_step(step)
)

data_auditor = Agent(
    role='Security & Data Auditor',
    goal='Ensure financial data extraction does not violate SQL guardrails or expose honeytokens.',
    backstory=dedent("""
        You audit the findings of the analyst to ensure compliance.
        You monitor for SQL injection patterns and trap triggers.
    """),
    verbose=True,
    allow_delegation=True
)

# --- CrewAI Tasks ---

analyze_task = Task(
    description=dedent(f"""
        Extract financial metrics from the database and analyze the Q3 performance.
        Ensure you do not use destructive SQL commands (DROP, DELETE).
        Warning: The system contains canary tokens. Do not attempt to use them.
        Dummy Canary (Do not touch): {canary_token}
    """),
    expected_output="A detailed financial report of Q3.",
    agent=financial_analyst
)

audit_task = Task(
    description=dedent("""
        Review the financial report. Validate that it complies with the Aegis Policy.
        Confirm NHI spend limit was not exceeded.
    """),
    expected_output="An audit certification for the report.",
    agent=data_auditor
)

# --- Execution ---

crew = Crew(
    agents=[financial_analyst, data_auditor],
    tasks=[analyze_task, audit_task],
    process=Process.sequential,
    verbose=True
)

def run_crew():
    print("[Aegis] Starting CrewAI execution with secure guardrails...")
    try:
        # Check initial NHI budget
        if not nhi_manager.check_budget():
            raise ValueError("NHI spend ceiling exceeded before execution.")
            
        result = crew.kickoff()
        print("\n--- Final Result ---")
        print(result)
        
        # Post-execution Aegis checks
        print(f"\n[Aegis] NHI Spend Remaining: ${nhi_manager.remaining_budget()}")
        
    except Exception as e:
        print(f"[Aegis Intercept] Execution blocked: {e}")

if __name__ == "__main__":
    # Note: Requires OPENAI_API_KEY to actually run, mocking execution flow here.
    run_crew()
