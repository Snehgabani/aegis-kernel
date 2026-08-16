import time
import hashlib
import json
from typing import Any, Dict, List, Optional, Union
from .types import AegisVerdict, AegisViolation, ToolCall, AegisConfig
from .checkers import PythonSqlChecker, PythonPiiChecker, PythonNumericChecker, PythonStateChecker, PythonPiiTokenVault

BUILTIN_RULES = [
    # SQL Guard
    {
        "id": "SQL-001",
        "pack_id": "sql-guard",
        "type": "sql",
        "params": {"statements": ["DELETE", "UPDATE"], "require": "WHERE_CLAUSE"}
    },
    {
        "id": "SQL-002",
        "pack_id": "sql-guard",
        "type": "sql",
        "params": {"block_statements": ["DROP", "TRUNCATE", "ALTER"]}
    },
    # Finance Guard
    {
        "id": "FIN-001",
        "pack_id": "finance-guard",
        "type": "numeric",
        "params": {"field": "amount", "max": 10000}
    },
    # Data Guard
    {
        "id": "DATA-001",
        "pack_id": "data-guard",
        "type": "pii",
        "params": {"patterns": ["CREDIT_CARD", "US_SSN", "CREDIT_CARD_CVV"]}
    },
    {
        "id": "DATA-002",
        "pack_id": "data-guard",
        "type": "pii",
        "params": {"patterns": ["OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_ACCESS_KEY", "STRIPE_KEY"]}
    },
    # SOC 2 & HIPAA
    {
        "id": "SOC2-001",
        "pack_id": "soc2-guard",
        "type": "pii",
        "params": {"patterns": ["SENSITIVE_FILE_PATH"]}
    },
    {
        "id": "HIPAA-001",
        "pack_id": "hipaa-guard",
        "type": "pii",
        "params": {"patterns": ["US_NPI", "US_DEA"]}
    }
]

class AegisEngine:
    def __init__(
        self,
        config: Optional[Union[AegisConfig, str]] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
        mode: str = "enforce",
        fail_policy: str = "fail-closed",
        packs: Optional[List[str]] = None,
    ):
        if isinstance(config, AegisConfig):
            self.mode = config.mode
            self.fail_policy = config.fail_policy
            self.rules = config.rules or rules or BUILTIN_RULES
        elif isinstance(config, str):
            self.mode = config
            self.fail_policy = fail_policy
            self.rules = rules or BUILTIN_RULES
        else:
            self.mode = mode
            self.fail_policy = fail_policy
            self.rules = rules or BUILTIN_RULES
        self.policy_hash = hashlib.sha256(json.dumps(self.rules, sort_keys=True).encode()).hexdigest()

    def evaluate(self, tool_call: ToolCall, state: Optional[Dict[str, Any]] = None) -> AegisVerdict:
        start_time = time.perf_counter()
        violations: List[AegisViolation] = []

        for rule in self.rules:
            rule_type = rule.get("type")
            rule_id = rule.get("id", "UNKNOWN")
            pack_id = rule.get("pack_id", "custom")
            params = rule.get("params", {})

            if rule_type == "sql" or rule_type == "sql_ast":
                violations.extend(PythonSqlChecker.evaluate(rule_id, pack_id, params, tool_call))
            elif rule_type == "pii" or rule_type == "regex":
                violations.extend(PythonPiiChecker.evaluate(rule_id, pack_id, params, tool_call))
            elif rule_type == "numeric":
                violations.extend(PythonNumericChecker.evaluate(rule_id, pack_id, params, tool_call))
            elif rule_type == "state" or rule_type == "state_invariant":
                violations.extend(PythonStateChecker.evaluate(rule_id, pack_id, params, tool_call, state))

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        # Cryptographic proof hash
        proof_payload = f"{tool_call.tool}:{json.dumps(tool_call.params, sort_keys=True)}:{self.policy_hash}"
        proof_hash = hashlib.sha256(proof_payload.encode()).hexdigest()

        is_allowed = len(violations) == 0 or self.mode == "shadow"
        verdict_str = "ALLOWED" if is_allowed else "BLOCKED"
        suggested_fix = violations[0].suggested_fix if violations else None

        return AegisVerdict(
            allowed=is_allowed,
            verdict=verdict_str,
            violations=violations,
            latency_ms=round(latency_ms, 3),
            proof_hash=proof_hash,
            policy_commitment_hash=self.policy_hash,
            suggested_fix=suggested_fix,
        )
