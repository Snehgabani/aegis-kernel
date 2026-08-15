import unittest
import sys
import os

# Add package directory to path for testing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from aegis_kernel import AegisEngine, ToolCall, aegis_guard, AegisBlockedError, AegisCrewAITool, wrap_autogen_function

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

        # 3. Legitimate targeted SELECT
        call3 = ToolCall(tool="db_exec", params={"query": "SELECT id, name FROM users WHERE id = 42"})
        v3 = self.engine.evaluate(call3)
        self.assertTrue(v3.allowed)
        self.assertEqual(v3.verdict, "ALLOWED")

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

    def test_sub_millisecond_latency(self):
        call = ToolCall(tool="fast_eval", params={"query": "SELECT * FROM items WHERE id = 1"})
        v = self.engine.evaluate(call)
        self.assertTrue(v.allowed)
        self.assertLess(v.latency_ms, 2.0)

if __name__ == "__main__":
    unittest.main()

