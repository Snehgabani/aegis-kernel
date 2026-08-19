import re
from typing import Any, Dict, List, Optional
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

def looks_like_sql(val: str) -> bool:
    if not isinstance(val, str):
        return False
    s = re.sub(r"/\*.*?\*/", "", val)
    s = re.sub(r"--[^\n]*", "", s).strip()
    return bool(re.match(r"^(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|EXEC|EXECUTE|WITH)\b", s, re.IGNORECASE))


class PythonSqlChecker:
    @staticmethod
    def evaluate(rule_id: str, pack_id: str, params: Dict[str, Any], tool_call: ToolCall) -> List[AegisViolation]:
        violations: List[AegisViolation] = []

        strings: List[str] = []
        def collect(obj: Any):
            if isinstance(obj, str):
                strings.append(obj)
            elif isinstance(obj, list):
                for item in obj: collect(item)
            elif isinstance(obj, dict):
                for val in obj.values(): collect(val)
        collect(tool_call.params)

        sql_text = ""
        for val in strings:
            if looks_like_sql(val):
                sql_text = val
                break

        if not sql_text and strings:
            for val in strings:
                cleaned_val = re.sub(r"/\*.*?\*/", "", val)
                cleaned_val = re.sub(r"--[^\n]*", "", cleaned_val)
                if any(kw in cleaned_val.upper() for kw in ["DELETE", "DROP", "UPDATE", "TRUNCATE", "ALTER"]):
                    sql_text = val
                    break

        if not sql_text:
            return violations

        # Strip comments then string literals before searching for DDL statements (prevents comment evasions & false positives on note='DROP')
        sql_without_comments = re.sub(r"/\*.*?\*/", "", sql_text)
        sql_without_comments = re.sub(r"--[^\n]*", "", sql_without_comments)
        sql_without_strings = re.sub(r"'[^']*'", "''", sql_without_comments)
        upper_sql = sql_without_strings.upper()

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
                    where_match = re.search(r"\bWHERE\b\s+(.*)", sql_without_strings, re.IGNORECASE | re.DOTALL)
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
                        # Comprehensive tautology check (1=1, 2>1, true, 1, id>0, id<>-1, IS NOT NULL)
                        is_tautology = bool(
                            re.search(r"^\s*(?:1\s*=\s*1|2\s*>\s*1|(\d+)\s*=\s*\1|(\d+)\s*>\s*(\d+)|true|1|'a'\s*=\s*'a')\s*(?:;)?$", where_clause, re.IGNORECASE)
                            or re.search(r"\bIS\s+NOT\s+NULL\b", where_clause, re.IGNORECASE)
                            or re.search(r"\b[a-zA-Z_]\w*\s*>\s*0\b", where_clause, re.IGNORECASE)
                            or re.search(r"\b[a-zA-Z_]\w*\s*(?:<>|!=)\s*-\d+\b", where_clause, re.IGNORECASE)
                            or re.search(r"\bIN\s*\(\s*SELECT\b", where_clause, re.IGNORECASE)
                            or re.search(r"\bOR\s+(?:1\s*=\s*1|true|1|\d+\s*>\s*\d+|'[^']+'\s*=\s*'[^']+')", where_clause, re.IGNORECASE)
                        )
                        if is_tautology:
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
        field_name = params.get("field", "amount")
        max_val = params.get("max")
        min_val = params.get("min", 0 if any(k in field_name.lower() for k in ["amount", "price", "cost", "payment", "payout", "transfer"]) else None)

        def parse_number(val: Any) -> Optional[float]:
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str):
                cleaned = re.sub(r"[$€£¥₹,]", "", val).strip()
                try:
                    return float(cleaned)
                except ValueError:
                    return None
            return None

        val = None
        # Check direct field
        if field_name in tool_call.params:
            val = parse_number(tool_call.params[field_name])
        
        # Check semantic aliases (total, value, sum, price, payout, cost)
        if val is None:
            aliases = ["amount", "total", "value", "sum", "price", "cost", "payout", "payment", "transfer"]
            for alias in aliases:
                for k, v in tool_call.params.items():
                    if k.lower() == alias:
                        parsed = parse_number(v)
                        if parsed is not None:
                            val = parsed
                            break
                if val is not None:
                    break

        if val is None and "_args" in tool_call.params and isinstance(tool_call.params["_args"], list):
            for arg in tool_call.params["_args"]:
                parsed = parse_number(arg)
                if parsed is not None:
                    val = parsed
                    break

        if val is not None:
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

class PythonStateChecker:
    @staticmethod
    def evaluate(rule_id: str, pack_id: str, params: Dict[str, Any], tool_call: ToolCall, state: Optional[Dict[str, Any]] = None) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        current_state = state or {}

        # 1. Multi-tenant isolation check
        tenant_field = params.get("tenant_field")
        if tenant_field:
            expected_tenant = current_state.get(tenant_field)
            call_tenant = tool_call.params.get(tenant_field)
            if expected_tenant is not None and call_tenant is not None and str(expected_tenant) != str(call_tenant):
                violations.append(AegisViolation(
                    rule_id=rule_id,
                    pack_id=pack_id,
                    severity="critical",
                    message=f"Cross-tenant parameter mismatch: request tenant '{call_tenant}' != session tenant '{expected_tenant}'.",
                    suggested_fix="Align request tenant with authenticated session context.",
                ))

        # 2. Target field state assertion (e.g. order_status != 'cancelled')
        target_field = params.get("target_field")
        assertion = params.get("assertion")
        if target_field and assertion:
            target_val = tool_call.params.get(target_field)
            if target_val:
                order_status = current_state.get("order_status")
                if order_status == "cancelled" and "cancelled" in assertion:
                    violations.append(AegisViolation(
                        rule_id=rule_id,
                        pack_id=pack_id,
                        severity="critical",
                        message=f"Operation on '{target_field}={target_val}' prohibited when state is '{order_status}'.",
                        suggested_fix="Check entity status before requesting mutation.",
                    ))

        return violations

class PythonPiiTokenVault:
    def __init__(self, salt: Optional[str] = None):
        import secrets
        self.salt = salt or secrets.token_hex(16)
        self.vault: Dict[str, str] = {}
        self.reverse_vault: Dict[str, str] = {}

    def tokenize(self, value: str, token_type: str = "PII") -> str:
        if value in self.vault:
            return self.vault[value]

        import hashlib
        digest = hashlib.sha256(f"{self.salt}:{value}".encode()).hexdigest()[:16]
        token = f"<AEGIS_{token_type}_{digest}>"
        self.vault[value] = token
        self.reverse_vault[token] = value
        return token

    def detokenize(self, text: str) -> str:
        result = text
        for token, original in self.reverse_vault.items():
            result = result.replace(token, original)
        return result

