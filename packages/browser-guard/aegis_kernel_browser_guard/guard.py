"""
Aegis Browser Guard — deterministic clearance for browser-agent actions.

Action taxonomy (matched by substring against the action name, covering
Browser-Use, OpenManus, and generic Playwright loops):

* navigation:  go_to_url, navigate, open_tab, search_google, goto
* typed input: input_text, type, fill, send_keys, keyboard
* download:    download, save_file
* upload:      upload, attach_file
* everything else: generic PII/secret scan across string params
"""

import hashlib
import ipaddress
import json
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from aegis_kernel import AegisEngine, ToolCall
from aegis_kernel.types import AegisVerdict, AegisViolation

from .policy import BrowserPolicy, DANGEROUS_SCHEMES

ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u2060\u00ad\ufeff\u180e]")

NAVIGATION_ACTIONS = ("go_to_url", "navigate", "open_tab", "open_url", "goto", "search", "visit")
INPUT_ACTIONS = ("input_text", "input", "type", "fill", "send_keys", "keyboard", "write")
DOWNLOAD_ACTIONS = ("download", "save_file")
UPLOAD_ACTIONS = ("upload", "attach_file")

_URL_PARAM_KEYS = ("url", "uri", "link", "href", "target_url", "page_url")
_TEXT_PARAM_KEYS = ("text", "value", "input", "keys", "content", "query")
_PATH_PARAM_KEYS = ("path", "file_path", "filepath", "file", "source", "local_path")


class BrowserActionBlockedError(Exception):
    """Raised in ``on_block='raise'`` mode when a browser action is denied."""

    def __init__(self, verdict: AegisVerdict):
        self.verdict = verdict
        v = verdict.violations[0] if verdict.violations else None
        rule = v.rule_id if v else "BROWSER-POLICY"
        msg = v.message if v else "Browser policy constraint violated."
        super().__init__(f"Aegis Browser Guard: action blocked. Rule: {rule} - {msg}")


def _violation(rule_id: str, message: str, fix: str, context: Optional[Dict[str, Any]] = None) -> AegisViolation:
    return AegisViolation(
        rule_id=rule_id,
        pack_id="browser-guard",
        severity="critical",
        message=message,
        suggested_fix=fix,
        context=context or {},
    )


class AegisBrowserGuard:
    """Evaluates browser-agent actions against a :class:`BrowserPolicy` plus
    the core Aegis engine (PII / secret / SQL invariants)."""

    def __init__(
        self,
        policy: Optional[BrowserPolicy] = None,
        engine: Optional[AegisEngine] = None,
        mode: str = "enforce",
    ):
        self.policy = policy or BrowserPolicy()
        self.engine = engine or AegisEngine(mode=mode)
        self.mode = mode
        self.policy_hash = hashlib.sha256(
            (self.policy.commitment_hash() + self.engine.policy_hash).encode()
        ).hexdigest()

    # ------------------------------------------------------------------ URLs

    def _check_url(self, url: str) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        p = self.policy

        if p.block_zero_width and ZERO_WIDTH_RE.search(url):
            violations.append(_violation(
                "BROWSER-001",
                "URL contains zero-width Unicode characters (payload-smuggling vector).",
                "Strip invisible Unicode from the URL before navigating.",
                {"url": repr(url)},
            ))
            return violations

        try:
            parts = urlsplit(url.strip())
        except ValueError:
            violations.append(_violation(
                "BROWSER-002", "URL could not be parsed.", "Provide a well-formed absolute URL.", {"url": url},
            ))
            return violations

        scheme = (parts.scheme or "").lower()
        if scheme not in [s.lower() for s in p.allowed_schemes]:
            label = "dangerous" if scheme in DANGEROUS_SCHEMES else "non-allowlisted"
            violations.append(_violation(
                "BROWSER-003",
                f"URL scheme '{scheme or '(none)'}' is {label}; only {p.allowed_schemes} permitted.",
                "Navigate via an https:// URL.",
                {"url": url, "scheme": scheme},
            ))
            return violations

        if p.block_url_credentials and (parts.username or parts.password):
            violations.append(_violation(
                "BROWSER-004",
                "URL embeds credentials (user:pass@host) — classic phishing/exfiltration vector.",
                "Remove embedded credentials from the URL.",
                {"url": url},
            ))

        host = (parts.hostname or "").lower().rstrip(".")
        if not host:
            violations.append(_violation(
                "BROWSER-002", "URL has no hostname.", "Provide a well-formed absolute URL.", {"url": url},
            ))
            return violations

        if p.block_ip_literals:
            try:
                ipaddress.ip_address(host)
                violations.append(_violation(
                    "BROWSER-005",
                    f"Navigation to raw IP literal '{host}' is prohibited (DNS-evasion vector).",
                    "Use a resolvable domain name on the approved list.",
                    {"host": host},
                ))
                return violations
            except ValueError:
                pass

        if p.block_punycode and any(label.startswith("xn--") for label in host.split(".")):
            violations.append(_violation(
                "BROWSER-006",
                f"Punycode/IDN hostname '{host}' blocked (homograph-attack vector).",
                "Navigate to the canonical ASCII domain instead.",
                {"host": host},
            ))
            return violations

        if self._domain_matches(host, p.blocked_domains):
            violations.append(_violation(
                "BROWSER-007",
                f"Domain '{host}' is on the blocked-domain list.",
                "Choose a domain that is not deny-listed.",
                {"host": host},
            ))
            return violations

        if p.allowed_domains is not None and not self._domain_matches(host, p.allowed_domains):
            violations.append(_violation(
                "BROWSER-008",
                f"Domain '{host}' is outside the navigation allowlist.",
                f"Navigate only within: {sorted(p.allowed_domains)}.",
                {"host": host},
            ))

        return violations

    def _domain_matches(self, host: str, domains: List[str]) -> bool:
        for d in domains:
            d = d.lower().lstrip("*.").rstrip(".")
            if not d:
                continue
            if host == d or (self.policy.allow_subdomains and host.endswith("." + d)):
                return True
        return False

    # ----------------------------------------------------------------- text

    def _check_typed_text(self, text: str) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        p = self.policy

        if p.max_typed_text_length is not None and len(text) > p.max_typed_text_length:
            violations.append(_violation(
                "BROWSER-009",
                f"Typed input exceeds max length {p.max_typed_text_length}.",
                "Shorten the input payload.",
            ))

        if p.block_zero_width and ZERO_WIDTH_RE.search(text):
            violations.append(_violation(
                "BROWSER-010",
                "Typed input contains zero-width Unicode characters (prompt-injection smuggling vector).",
                "Strip invisible Unicode from the input.",
            ))

        if p.scan_typed_text:
            # Delegate secret/PII detection to the core engine's data-guard rules.
            core = self.engine.evaluate(ToolCall(tool="browser_input_text", params={"text": text}))
            violations.extend(core.violations)

        return violations

    # ---------------------------------------------------------------- files

    def _check_download(self, url: str) -> List[AegisViolation]:
        violations = self._check_url(url)
        path = urlsplit(url).path.lower()
        for ext in self.policy.blocked_download_extensions:
            if path.endswith(ext.lower()):
                violations.append(_violation(
                    "BROWSER-011",
                    f"Download of executable/scriptable file type '{ext}' is prohibited.",
                    "Download only data files (e.g. .csv, .pdf, .json) from approved domains.",
                    {"url": url},
                ))
                break
        return violations

    def _check_upload(self, path: str) -> List[AegisViolation]:
        violations: List[AegisViolation] = []
        if self.policy.scan_upload_paths:
            core = self.engine.evaluate(ToolCall(tool="browser_upload_file", params={"path": path}))
            violations.extend(core.violations)
        return violations

    # ------------------------------------------------------------- verdicts

    def evaluate_url(self, url: str) -> AegisVerdict:
        return self._verdict("navigate", {"url": url}, self._check_url(url))

    def evaluate_action(self, action: str, params: Optional[Dict[str, Any]] = None) -> AegisVerdict:
        """Main entrypoint: clear a named browser action with its parameters."""
        start = time.perf_counter()
        params = params or {}
        action_l = (action or "").lower()
        violations: List[AegisViolation] = []

        url = next((str(params[k]) for k in _URL_PARAM_KEYS if params.get(k)), None)
        text = next((str(params[k]) for k in _TEXT_PARAM_KEYS if params.get(k) is not None), None)
        path = next((str(params[k]) for k in _PATH_PARAM_KEYS if params.get(k)), None)

        if any(a in action_l for a in DOWNLOAD_ACTIONS):
            if url:
                violations.extend(self._check_download(url))
        elif any(a in action_l for a in UPLOAD_ACTIONS):
            if path:
                violations.extend(self._check_upload(path))
            if url:
                violations.extend(self._check_url(url))
        elif any(a in action_l for a in NAVIGATION_ACTIONS):
            if url:
                violations.extend(self._check_url(url))
        elif any(a in action_l for a in INPUT_ACTIONS):
            if text is not None:
                violations.extend(self._check_typed_text(text))
        else:
            # Generic clearance: run every string param through the core engine.
            core = self.engine.evaluate(ToolCall(tool=f"browser_{action_l or 'action'}", params=params))
            violations.extend(core.violations)
            if url:
                violations.extend(self._check_url(url))

        return self._verdict(action, params, violations, start)

    def _verdict(
        self,
        action: str,
        params: Dict[str, Any],
        violations: List[AegisViolation],
        start: Optional[float] = None,
    ) -> AegisVerdict:
        latency = ((time.perf_counter() - start) * 1000.0) if start else 0.0
        allowed = len(violations) == 0 or self.mode in ("monitor", "shadow", "simulate")
        proof_payload = f"browser:{action}:{json.dumps(params, sort_keys=True, default=str)}:{self.policy_hash}"
        return AegisVerdict(
            allowed=allowed,
            verdict="ALLOWED" if allowed else "BLOCKED",
            violations=violations,
            latency_ms=round(latency, 3),
            proof_hash=hashlib.sha256(proof_payload.encode()).hexdigest(),
            policy_commitment_hash=self.policy_hash,
            suggested_fix=violations[0].suggested_fix if violations else None,
        )


def _format_block_feedback(verdict: AegisVerdict) -> str:
    v = verdict.violations[0] if verdict.violations else None
    rule_id = v.rule_id if v else "BROWSER-POLICY"
    message = v.message if v else "Browser policy constraint violated."
    fix = (v.suggested_fix if v else None) or "Adjust the action to comply with policy."
    return (
        "AEGIS_BLOCKED: Browser action denied by deterministic invariant. "
        f"rule_id={rule_id}; reason={message}; suggested_fix={fix}; "
        f"proof_hash={verdict.proof_hash}"
    )


def guard_browser_action(
    action_name: str,
    func: Callable[..., Any],
    guard: Optional[AegisBrowserGuard] = None,
    on_block: str = "feedback",
) -> Callable[..., Any]:
    """Wrap a single action callable (sync or async) with pre-execution clearance."""
    import asyncio
    import functools

    g = guard or AegisBrowserGuard()

    def _check(kwargs: dict) -> Optional[str]:
        verdict = g.evaluate_action(action_name, kwargs)
        if verdict.allowed:
            return None
        if on_block == "raise":
            raise BrowserActionBlockedError(verdict)
        return _format_block_feedback(verdict)

    if asyncio.iscoroutinefunction(func):
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            blocked = _check(dict(kwargs))
            if blocked is not None:
                return blocked
            return await func(*args, **kwargs)

        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        blocked = _check(dict(kwargs))
        if blocked is not None:
            return blocked
        return func(*args, **kwargs)

    return sync_wrapper


def guard_browser_use_controller(
    controller: Any,
    guard: Optional[AegisBrowserGuard] = None,
    on_block: str = "feedback",
) -> Any:
    """
    Harden a Browser-Use ``Controller`` in place: every registered action's
    implementation is wrapped with Aegis clearance. Duck-typed against
    ``controller.registry.registry.actions`` — works across browser-use versions.
    """
    g = guard or AegisBrowserGuard()
    registry = getattr(getattr(controller, "registry", None), "registry", None)
    actions = getattr(registry, "actions", None)
    if not isinstance(actions, dict):
        raise TypeError(
            "controller does not expose registry.registry.actions; "
            "pass a browser_use.Controller instance"
        )
    for name, registered in actions.items():
        fn = getattr(registered, "function", None)
        if callable(fn):
            registered.function = guard_browser_action(name, fn, guard=g, on_block=on_block)
    return controller


def guard_openmanus_tool(
    tool: Any,
    guard: Optional[AegisBrowserGuard] = None,
    on_block: str = "feedback",
) -> Any:
    """
    Harden an OpenManus ``BrowserUseTool``-style object in place by wrapping its
    ``execute`` coroutine/method. OpenManus dispatches on an ``action`` kwarg,
    which is mapped straight into Aegis' action taxonomy.
    """
    import asyncio
    import functools

    g = guard or AegisBrowserGuard()
    execute = getattr(tool, "execute", None)
    if not callable(execute):
        raise TypeError("tool does not expose execute(); pass an OpenManus tool instance")

    def _check(kwargs: dict) -> Optional[str]:
        action = str(kwargs.get("action", "browser_action"))
        verdict = g.evaluate_action(action, kwargs)
        if verdict.allowed:
            return None
        if on_block == "raise":
            raise BrowserActionBlockedError(verdict)
        return _format_block_feedback(verdict)

    if asyncio.iscoroutinefunction(execute):
        @functools.wraps(execute)
        async def async_execute(*args: Any, **kwargs: Any) -> Any:
            blocked = _check(dict(kwargs))
            if blocked is not None:
                return blocked
            return await execute(*args, **kwargs)

        tool.execute = async_execute
    else:
        @functools.wraps(execute)
        def sync_execute(*args: Any, **kwargs: Any) -> Any:
            blocked = _check(dict(kwargs))
            if blocked is not None:
                return blocked
            return execute(*args, **kwargs)

        tool.execute = sync_execute

    return tool
