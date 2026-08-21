# @aegis-kernel — Browser Guard (`aegis-kernel-browser-guard`)

Turn-key deterministic safety clearance for browser-operating agents — [Browser-Use](https://github.com/browser-use/browser-use), [OpenManus](https://github.com/FoundationAgents/OpenManus), and any Playwright/CDP agent loop — powered by the [Aegis Invariant Kernel](https://github.com/Snehgabani/aegis-kernel).

Browser agents fail at three surfaces, and all three are structural, not linguistic:

| Surface | Attack | Aegis Rule |
|---------|--------|-----------|
| **Navigation** | `javascript:`/`file:`/`data:` scheme escape | `BROWSER-003` |
| | Cloud metadata / raw IP literals (`169.254.169.254`) | `BROWSER-005` |
| | Punycode homographs (`xn--pple-43d.com`) | `BROWSER-006` |
| | Zero-width Unicode URL smuggling | `BROWSER-001` |
| | Embedded credentials (`user:pass@host`) | `BROWSER-004` |
| | Deny-listed / off-allowlist domains | `BROWSER-007/008` |
| **Typed input** | API keys, credit cards, SSNs keyed into pages | `DATA-001/002` |
| | Zero-width prompt-injection smuggling | `BROWSER-010` |
| **Files** | Executable downloads (`.exe`, `.sh`, `.apk`, …) | `BROWSER-011` |
| | Sensitive path uploads (`.ssh/id_rsa`, `.env`) | `SOC2-001` |

## Install

```bash
pip install aegis-kernel-browser-guard
```

## Browser-Use — one line

```python
from browser_use import Agent, Controller
from aegis_kernel_browser_guard import guard_browser_use_controller, AegisBrowserGuard, BrowserPolicy

controller = Controller()
guard_browser_use_controller(controller, AegisBrowserGuard(
    BrowserPolicy(allowed_domains=["wikipedia.org", "arxiv.org"])
))

agent = Agent(task="Research AST parsers", llm=llm, controller=controller)
```

Every registered action (`go_to_url`, `input_text`, `download`, …) now clears a deterministic invariant check before executing. Blocked actions return structured `AEGIS_BLOCKED:` feedback the agent can self-correct against.

## OpenManus

```python
from app.tool.browser_use_tool import BrowserUseTool
from aegis_kernel_browser_guard import guard_openmanus_tool

tool = guard_openmanus_tool(BrowserUseTool())   # wraps tool.execute(action=..., ...)
```

## Direct evaluation

```python
from aegis_kernel_browser_guard import AegisBrowserGuard

guard = AegisBrowserGuard()
verdict = guard.evaluate_action("input_text", {"text": "sk-proj-…"})
verdict.allowed            # False
verdict.violations[0]      # DATA-002 secret detected
verdict.proof_hash         # SHA-256 audit proof
```

## Policy

```python
BrowserPolicy(
    allowed_domains=None,          # None = all except blocked; list = strict allowlist
    blocked_domains=["pastebin.com"],
    allowed_schemes=["http", "https"],
    block_ip_literals=True,
    block_punycode=True,
    block_url_credentials=True,
    block_zero_width=True,
    scan_typed_text=True,          # PII/secret vault scan on keystrokes
    scan_upload_paths=True,
    blocked_download_extensions=[".exe", ".msi", ".sh", ...],
)
```

`mode="monitor"` records violations without blocking — ideal for staged rollouts.

## Links

- [Docs](https://snehgabani.github.io/aegis-kernel/docs/) · [Playground](https://snehgabani.github.io/aegis-kernel/playground/) · [Core repo](https://github.com/Snehgabani/aegis-kernel)

MIT © Sneh Gabani
