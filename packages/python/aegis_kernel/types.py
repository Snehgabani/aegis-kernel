from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Literal

@dataclass
class AegisViolation:
    rule_id: str
    pack_id: str
    severity: Literal["critical", "warning", "info"]
    message: str
    suggested_fix: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

@dataclass
class AegisVerdict:
    allowed: bool
    verdict: Literal["ALLOWED", "BLOCKED"]
    violations: List[AegisViolation] = field(default_factory=list)
    latency_ms: float = 0.0
    proof_hash: str = ""
    policy_commitment_hash: str = ""
    suggested_fix: Optional[str] = None

@dataclass
class ToolCall:
    tool: str
    params: Dict[str, Any]
