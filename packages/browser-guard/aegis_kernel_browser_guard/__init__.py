"""
Aegis Invariant Kernel — Browser Guard
Turn-key deterministic safety clearance for browser-operating agents
(Browser-Use, OpenManus, and any Playwright/CDP-driving agent loop).

Guards the three riskiest browser-agent surfaces:

1. **Navigation** — scheme allowlists, domain allow/deny lists, IP-literal and
   punycode (IDN homograph) blocking, zero-width Unicode smuggling detection,
   embedded-credential URLs.
2. **Typed input** — salted PII/secret detection (API keys, credit cards,
   SSNs) before keystrokes ever reach a page.
3. **Downloads / uploads** — executable-extension blocking and sensitive
   file-path exfiltration prevention.

Zero hard dependency on browser-use or OpenManus: all adapters are duck-typed.
"""

from .policy import BrowserPolicy
from .guard import (
    AegisBrowserGuard,
    BrowserActionBlockedError,
    guard_browser_action,
    guard_browser_use_controller,
    guard_openmanus_tool,
)
from aegis_kernel import AegisEngine, AegisVerdict, ToolCall

__all__ = [
    "BrowserPolicy",
    "AegisBrowserGuard",
    "BrowserActionBlockedError",
    "guard_browser_action",
    "guard_browser_use_controller",
    "guard_openmanus_tool",
    "AegisEngine",
    "AegisVerdict",
    "ToolCall",
]

__version__ = "1.1.0"
