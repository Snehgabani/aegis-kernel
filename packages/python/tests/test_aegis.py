import unittest
import sys
import os

# Add package directory to path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis_kernel import (
    AegisEngine,
    ToolCall,
    aegis_guard,
    AegisBlockedError,
    AegisCrewAITool,
    wrap_autogen_function,
    AegisLangChainTool,
    wrap_langchain_tool,
    PythonStateChecker,
    PythonPiiTokenVault,
)

class TestAegisPythonKernel(unittest.TestCase):
    def setUp(self):
        self.engine = AegisEngine(mode="enforce")

    def test_blocks_destructive_sql_operations(self):
        # 1. Mass DELETE without WHERE
        call1 = ToolCall(tool="db_exec", params={"query": "DELETE FROM users"})
        v1 = self.engine.evaluate(call1)
        self.assertFalse(v1.allowed)
        self.assertEqual(v1.verdict, "BLOCKED")
        self.assertEqual(v1.violations[0].rule_id, "SQL-001")

        # 2. DROP TABLE
        call2 = ToolCall(tool="db_exec", params={"query": "DROP TABLE accounts;"})
        v2 = self.engine.evaluate(call2)
        self.assertFalse(v2.allowed)
        self.assertEqual(v2.violations[0].rule_id, "SQL-002")

        # 3. Legitimate targeted SELECT with string literal containing DROP
        call3 = ToolCall(tool="db_exec", params={"query": "SELECT * FROM t WHERE note = 'DROP'"})
        v3 = self.engine.evaluate(call3)
        self.assertTrue(v3.allowed)
        self.assertEqual(v3.verdict, "ALLOWED")

        # 4. Tautology bypass attempts (WHERE 2>1, WHERE 1, WHERE id>0)
        for tautology in ["DELETE FROM users WHERE 2>1", "DELETE FROM users WHERE 1", "DELETE FROM users WHERE id > 0"]:
            call_t = ToolCall(tool="db_exec", params={"query": tautology})
            v_t = self.engine.evaluate(call_t)
            self.assertFalse(v_t.allowed, f"Expected {tautology} to be BLOCKED")
            self.assertEqual(v_t.violations[0].rule_id, "SQL-001")

        # 5. Tool-name and param-name alias bypasses (tools/call with stmt)
        call_alias = ToolCall(tool="tools/call", params={"stmt": "DROP TABLE users"})
        v_alias = self.engine.evaluate(call_alias)
        self.assertFalse(v_alias.allowed)
        self.assertEqual(v_alias.violations[0].rule_id, "SQL-002")

        # 6. Financial alias overspend (total/price/value instead of amount)
        for alias_field in ["total", "price", "value", "sum", "payout"]:
            call_f = ToolCall(tool="payment", params={alias_field: 50000})
            v_f = self.engine.evaluate(call_f)
            self.assertFalse(v_f.allowed, f"Expected financial limit on {alias_field} to be BLOCKED")
            self.assertEqual(v_f.violations[0].rule_id, "FIN-001")

        # 7. Negative amount & formatted currency string
        call_neg = ToolCall(tool="transfer", params={"amount": -100})
        self.assertFalse(self.engine.evaluate(call_neg).allowed)

        call_str = ToolCall(tool="transfer", params={"amount": "$50,000.00"})
        self.assertFalse(self.engine.evaluate(call_str).allowed)

    def test_blocks_financial_limits_and_pii(self):
        # Overspend
        fin_call = ToolCall(tool="transfer_funds", params={"amount": 50000})
        v_fin = self.engine.evaluate(fin_call)
        self.assertFalse(v_fin.allowed)
        self.assertEqual(v_fin.violations[0].rule_id, "FIN-001")

        # OpenAI API key leak
        key_call = ToolCall(tool="post_message", params={"body": "My token is sk-ant-api03-abcdef1234567890"})
        v_key = self.engine.evaluate(key_call)
        self.assertFalse(v_key.allowed)
        self.assertEqual(v_key.violations[0].rule_id, "DATA-002")

        # System file traversal
        sec_call = ToolCall(tool="read_file", params={"path": "/etc/shadow"})
        v_sec = self.engine.evaluate(sec_call)
        self.assertFalse(v_sec.allowed)
        self.assertEqual(v_sec.violations[0].rule_id, "SOC2-001")

    def test_python_decorator_guard(self):
        @aegis_guard(tool_name="database_runner")
        def execute_db(query: str):
            return f"Executed: {query}"

        # Should raise AegisBlockedError on rogue call
        with self.assertRaises(AegisBlockedError):
            execute_db(query="DELETE FROM transactions")

        # Should succeed on safe call
        result = execute_db(query="SELECT * FROM transactions WHERE id = 100")
        self.assertEqual(result, "Executed: SELECT * FROM transactions WHERE id = 100")

    def test_crewai_adapter(self):
        class MockCrewTool:
            name = "execute_sql"
            def _run(self, query: str):
                return f"Success: {query}"

        guarded = AegisCrewAITool(MockCrewTool(), engine=self.engine)
        
        # Blocked call returns structured error string
        err_res = guarded.run(query="DROP TABLE secret_records;")
        self.assertTrue("ERROR [Aegis Policy Blocked]: SQL-002" in err_res)

        # Safe call executes underlying _run
        ok_res = guarded.run(query="SELECT * FROM users WHERE id = 5;")
        self.assertEqual(ok_res, "Success: SELECT * FROM users WHERE id = 5;")

    def test_autogen_adapter(self):
        def transfer_funds(amount: float, recipient: str):
            return f"Transferred ${amount} to {recipient}"

        safe_transfer = wrap_autogen_function(transfer_funds, engine=self.engine)

        # Blocked call returns error dict
        blocked_dict = safe_transfer(amount=99999, recipient="attacker")
        self.assertTrue(blocked_dict.get("error"))
        self.assertEqual(blocked_dict.get("status"), "BLOCKED")
        self.assertEqual(blocked_dict.get("rule_id"), "FIN-001")

        # Allowed call executes
        res = safe_transfer(amount=100, recipient="alice")
        self.assertEqual(res, "Transferred $100 to alice")

    def test_langchain_adapter(self):
        class MockLangChainTool:
            name = "sql_db_query"
            description = "Executes SQL queries against the database"

            def run(self, query: str) -> str:
                return f"Result: {query}"

            def _run(self, query: str) -> str:
                return f"Result: {query}"

        mock_tool = MockLangChainTool()
        
        # 1. Error string mode (handle_tool_error=True)
        guarded_lc = wrap_langchain_tool(mock_tool, engine=self.engine, handle_tool_error=True)
        self.assertEqual(guarded_lc.name, "sql_db_query")
        
        # Blocked query returns self-healing error string
        blocked_res = guarded_lc.run(query="DROP TABLE users")
        self.assertTrue("Error: [Aegis Policy Blocked] SQL-002" in blocked_res)

        # Runnable .invoke() support
        invoke_blocked = guarded_lc.invoke({"query": "DELETE FROM users"})
        self.assertTrue("Error: [Aegis Policy Blocked] SQL-001" in invoke_blocked)

        # Allowed query succeeds
        allowed_res = guarded_lc.run("SELECT * FROM users WHERE id = 42")
        self.assertEqual(allowed_res, "Result: SELECT * FROM users WHERE id = 42")

        # 2. Strict exception mode (handle_tool_error=False)
        strict_lc = AegisLangChainTool(mock_tool, engine=self.engine, handle_tool_error=False)
        with self.assertRaises(AegisBlockedError):
            strict_lc.run(query="DROP TABLE orders")

        # 3. Async Runnable .ainvoke() support
        import asyncio

        class MockAsyncLangChainTool:
            name = "async_sql"
            async def ainvoke(self, input_dict: dict, config=None) -> str:
                await asyncio.sleep(0.001)
                return f"Async: {input_dict.get('query')}"

        async_tool = MockAsyncLangChainTool()
        guarded_async_lc = wrap_langchain_tool(async_tool, engine=self.engine)

        async def run_async_tests():
            # Blocked
            res_b = await guarded_async_lc.ainvoke({"query": "DROP TABLE critical_data"})
            self.assertTrue("Error: [Aegis Policy Blocked] SQL-002" in res_b)
            # Allowed
            res_a = await guarded_async_lc.ainvoke({"query": "SELECT count(*) FROM items WHERE status = 'active'"})
            self.assertEqual(res_a, "Async: SELECT count(*) FROM items WHERE status = 'active'")

        asyncio.run(run_async_tests())

    def test_async_python_decorator(self):
        import asyncio

        @aegis_guard(tool_name="async_database_runner")
        async def async_execute_db(query: str):
            await asyncio.sleep(0.001)
            return f"Async Executed: {query}"

        # Should raise AegisBlockedError on rogue async call
        async def run_blocked():
            with self.assertRaises(AegisBlockedError):
                await async_execute_db(query="DELETE FROM transactions")

        # Should succeed on safe async call
        async def run_allowed():
            result = await async_execute_db(query="SELECT * FROM transactions WHERE id = 100")
            self.assertEqual(result, "Async Executed: SELECT * FROM transactions WHERE id = 100")

        asyncio.run(run_blocked())
        asyncio.run(run_allowed())

    def test_state_invariants(self):
        # Cross-tenant mismatch test
        rule_params = {"tenant_field": "tenantId"}
        call = ToolCall(tool="update_profile", params={"tenantId": "tenant-attacker", "name": "Eve"})
        violations = PythonStateChecker.evaluate("SOC2-004", "soc2-guard", rule_params, call, state={"tenantId": "tenant-legit"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].rule_id, "SOC2-004")

        # Entity cancelled status test
        rule_params2 = {"target_field": "order_id", "assertion": "state.order_status != 'cancelled'"}
        call2 = ToolCall(tool="ship_order", params={"order_id": "ORD-999"})
        violations2 = PythonStateChecker.evaluate("SOC2-005", "soc2-guard", rule_params2, call2, state={"order_status": "cancelled"})
        self.assertEqual(len(violations2), 1)
        self.assertEqual(violations2[0].rule_id, "SOC2-005")

    def test_pii_token_vault(self):
        vault = PythonPiiTokenVault(salt="test-fixed-salt")
        raw_ssn = "123-45-6789"
        token = vault.tokenize(raw_ssn, token_type="SSN")
        
        self.assertTrue(token.startswith("<AEGIS_SSN_"))
        self.assertNotIn("123-45-6789", token)

        # Deterministic mapping within session
        self.assertEqual(vault.tokenize(raw_ssn, token_type="SSN"), token)

        # Detokenization
        msg = f"User profile SSN is {token}"
        restored = vault.detokenize(msg)
        self.assertEqual(restored, "User profile SSN is 123-45-6789")

    def test_zero_dependencies(self):
        """Verify that aegis_kernel relies only on Python standard library."""
        import aegis_kernel
        import inspect

        # Inspect all modules in aegis_kernel
        for name in dir(aegis_kernel):
            item = getattr(aegis_kernel, name)
            if inspect.ismodule(item):
                # Ensure no external third-party packages are loaded as package dependencies
                mod_file = getattr(item, "__file__", "")
                if mod_file:
                    self.assertTrue(
                        "site-packages" not in mod_file or "aegis" in mod_file,
                        f"Non-stdlib dependency detected: {item}"
                    )

    def test_sub_100_microsecond_performance(self):
        """Verify deterministic sub-0.1ms (< 100μs) evaluation latency."""
        import time

        call = ToolCall(tool="fast_eval", params={"query": "SELECT * FROM items WHERE id = 1"})
        
        # Warmup
        for _ in range(500):
            self.engine.evaluate(call)

        # Benchmark 5,000 iterations
        N = 5000
        start = time.perf_counter()
        for _ in range(N):
            self.engine.evaluate(call)
        total_time_ms = (time.perf_counter() - start) * 1000.0
        avg_latency_ms = total_time_ms / N

        self.assertLess(
            avg_latency_ms,
            0.10,
            f"Average evaluation latency {avg_latency_ms:.4f} ms exceeded sub-0.1ms budget!"
        )

if __name__ == "__main__":
    unittest.main()


