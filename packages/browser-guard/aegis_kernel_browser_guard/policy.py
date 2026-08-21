"""Declarative browser-agent policy for the Aegis Browser Guard."""

import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Optional


DEFAULT_BLOCKED_DOWNLOAD_EXTENSIONS = [
    ".exe", ".msi", ".dmg", ".pkg", ".app",
    ".bat", ".cmd", ".ps1", ".sh",
    ".scr", ".jar", ".apk", ".deb", ".rpm",
    ".vbs", ".hta", ".lnk",
]

DEFAULT_ALLOWED_SCHEMES = ["http", "https"]

# Schemes that let a page or agent escape the web sandbox entirely.
DANGEROUS_SCHEMES = [
    "javascript", "data", "file", "chrome", "chrome-extension",
    "about", "blob", "vbscript", "ws", "wss", "ftp",
]


@dataclass
class BrowserPolicy:
    """
    Deterministic policy evaluated on every browser action.

    ``allowed_domains=None`` means "allow all except blocked_domains";
    a non-empty list switches the guard to strict allowlist mode.
    """

    allowed_domains: Optional[List[str]] = None
    blocked_domains: List[str] = field(default_factory=list)
    allow_subdomains: bool = True
    allowed_schemes: List[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_SCHEMES))
    block_ip_literals: bool = True
    block_punycode: bool = True
    block_url_credentials: bool = True
    block_zero_width: bool = True
    scan_typed_text: bool = True
    scan_upload_paths: bool = True
    scan_dom_content: bool = True
    block_hidden_injections: bool = True
    block_zero_pixel_beacons: bool = True
    block_dom_script_tags: bool = True
    blocked_download_extensions: List[str] = field(
        default_factory=lambda: list(DEFAULT_BLOCKED_DOWNLOAD_EXTENSIONS)
    )
    max_typed_text_length: Optional[int] = None

    def commitment_hash(self) -> str:
        """SHA-256 commitment over the normalized policy (for audit trails)."""
        payload = json.dumps(
            {
                "allowed_domains": sorted(self.allowed_domains) if self.allowed_domains else None,
                "blocked_domains": sorted(self.blocked_domains),
                "allow_subdomains": self.allow_subdomains,
                "allowed_schemes": sorted(self.allowed_schemes),
                "block_ip_literals": self.block_ip_literals,
                "block_punycode": self.block_punycode,
                "block_url_credentials": self.block_url_credentials,
                "block_zero_width": self.block_zero_width,
                "scan_typed_text": self.scan_typed_text,
                "scan_upload_paths": self.scan_upload_paths,
                "scan_dom_content": self.scan_dom_content,
                "block_hidden_injections": self.block_hidden_injections,
                "block_zero_pixel_beacons": self.block_zero_pixel_beacons,
                "block_dom_script_tags": self.block_dom_script_tags,
                "blocked_download_extensions": sorted(self.blocked_download_extensions),
                "max_typed_text_length": self.max_typed_text_length,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

