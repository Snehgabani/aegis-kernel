import re
from typing import Any, Dict, List
from .types import AegisViolation, ToolCall

PATTERNS = {
    "CREDIT_CARD": re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    "US_SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "OPENAI_API_KEY": re.compile(r"\b(?:sk-ant-api[0-9a-zA-Z_-]{15,}|sk-(?:proj-|live-)?[a-zA-Z0-9_-]{20,})\b"),
    "GITHUB_TOKEN": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{20,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "STRIPE_KEY": re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b"),
    "CREDIT_CARD_CVV": re.compile(r"\b(?:cvv|cvc|cvn|cid)\s*[:=]\s*\d{3,4}\b", re.IGNORECASE),
    "SENSITIVE_FILE_PATH": re.compile(r"(?:/etc/(?:shadow|passwd|sudoers)|\.ssh/(?:id_rsa|authorized_keys)|\.env(?:\.[a-zA-Z0-9_-]+)?|/proc/self/environ)"),
    "US_NPI": re.compile(r"\b[12]\d{9}\b"),
    "US_DEA": re.compile(r"\b[A-Z]{2}\d{7}\b"),
}

class PythonSqlChecker:
    @staticmethod
    def evaluate(rule_id: str, pack_id: str, params: Dict[str, Any], tool_call: ToolCall) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        sql_text = ""
        for val in tool_call.params.values():
            if isinstance(val, str) and any(kw in val.upper() for kw in ["SELECT", "DELETE", "DROP", "UPDATE", "TRUNCATE", "ALTER"]):
                sql_text = val
                break

        if not sql_text:
            return violations

        upper_sql = sql_text.upper()

        # 1. Blocked statements (DROP, TRUNCATE, ALTER)
        blocked_statements = params.get("block_statements", [])
        for stmt in blocked_statements:
            if re.search(rf"\b{stmt}\b", upper_sql):
                violations.append(AegisViolation(
                    rule_id=rule_id,
                    pack_id=pack_id,
                    severity="critical",
                    message=f"Destructive SQL statement '{stmt}' is prohibited in production agent workflows.",
                    suggested_fix=f"Remove prohibited {stmt} statement from query.",
                ))
                return violations

        # 2. Required WHERE clause for DELETE/UPDATE
        statements = params.get("statements", [])
        require = params.get("require")
        for stmt in statements:
            if re.search(rf"\b{stmt}\b", upper_sql):
                if require == "WHERE_CLAUSE":
                    where_match = re.search(r"\bWHERE\b\s+(.*)", sql_text, re.IGNORECASE | re.DOTALL)
                    if not where_match:
                        violations.append(AegisViolation(
                            rule_id=rule_id,
                            pack_id=pack_id,
                            severity="critical",
                            message=f"SQL {stmt} statement must include a valid targeted WHERE clause.",
                            suggested_fix=f"Add a WHERE condition to target specific rows.",
                        ))
                    else:
                        where_clause = where_match.group(1).strip()
                        # Check for constant tautologies like '1=1', 'true', 'id = id'
                        if re.search(r"^\s*(?:1\s*=\s*1|true|'a'\s*=\s*'a')\s*(?:;)?$", where_clause, re.IGNORECASE):
                            violations.append(AegisViolation(
                                rule_id=rule_id,
                                pack_id=pack_id,
                                severity="critical",
                                message=f"SQL {stmt} contains constant tautology WHERE clause bypassing safety filters.",
                                suggested_fix="Replace tautology with authentic column filters.",
                            ))

        return violations

class PythonPiiChecker:
    @staticmethod
    def evaluate(rule_id: str, pack_id: str, params: Dict[str, Any], tool_call: ToolCall) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        target_patterns = params.get("patterns", [])

        # Collect all string values recursively
        strings: List[str] = []
        def collect(obj: Any):
            if isinstance(obj, str):
                strings.append(obj)
            elif isinstance(obj, list):
                for item in obj: collect(item)
            elif isinstance(obj, dict):
                for val in obj.values(): collect(val)
        collect(tool_call.params)

        for pat_name in target_patterns:
            regex = PATTERNS.get(pat_name) or re.compile(pat_name, re.IGNORECASE)
            for text in strings:
                if regex.search(text):
                    violations.append(AegisViolation(
                        rule_id=rule_id,
                        pack_id=pack_id,
                        severity="critical",
                        message=f"Sensitive pattern '{pat_name}' detected in tool arguments.",
                        suggested_fix=f"Redact or parameterize sensitive tokens before invoking tool '{tool_call.tool}'.",
                    ))
                    break

        return violations

class PythonNumericChecker:
    @staticmethod
    def evaluate(rule_id: str, pack_id: str, params: Dict[str, Any], tool_call: ToolCall) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        field_name = params.get("field")
        max_val = params.get("max")
        min_val = params.get("min")

        if field_name and field_name in tool_call.params:
            val = tool_call.params[field_name]
            if isinstance(val, (int, float)):
                if max_val is not None and val > max_val:
                    violations.append(AegisViolation(
                        rule_id=rule_id,
                        pack_id=pack_id,
                        severity="critical",
                        message=f"Field '{field_name}' with value {val} exceeds maximum allowed boundary of {max_val}.",
                        suggested_fix=f"Constrain {field_name} <= {max_val}.",
                    ))
                if min_val is not None and val < min_val:
                    violations.append(AegisViolation(
                        rule_id=rule_id,
                        pack_id=pack_id,
                        severity="critical",
                        message=f"Field '{field_name}' with value {val} is below minimum allowed boundary of {min_val}.",
                        suggested_fix=f"Ensure {field_name} >= {min_val}.",
                    ))

        return violations
