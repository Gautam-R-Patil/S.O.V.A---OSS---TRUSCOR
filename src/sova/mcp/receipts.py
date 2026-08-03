# SPDX-License-Identifier: Apache-2.0
"""Pinned external executor receipts; locators are never treated as trust roots."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ExternalExecutorReceipt:
    name: str
    version: str
    source: str
    commit: str | None
    package_digest: str | None
    dependency_lock_digest: str | None
    license: str
    protocol: str
    status: str
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        value = asdict(self)
        value["limitations"] = list(self.limitations)
        return value


MELRA_AUDIT_RECEIPT = ExternalExecutorReceipt(
    name="melra",
    version="0.3.0-alpha.0-package-metadata",
    source="https://github.com/XAGI-Lab/melra",
    commit="a6dd6710f5ae94e8ce825ef99df9b01d7f974b95",
    package_digest=None,
    dependency_lock_digest="sha256:d0556db0883d311dcb017c34a66f68fadad70db6d58f49af09aa7d539ddda1b3",
    license="Apache-2.0",
    protocol="MCP 2025-11-25 stdio",
    status="optional-audited-with-failures",
    limitations=(
        "No matching v0.3.0-alpha.0 Git tag was present at audit time.",
        "The Windows build failed at a Unix-only chmod step.",
        "The Windows test suite failed at a symlink-permission case.",
        "Documented Windows computer input was not established.",
    ),
)

PLAYWRIGHT_MCP_RECEIPT = ExternalExecutorReceipt(
    name="microsoft-playwright-mcp",
    version="0.0.78",
    source="https://github.com/microsoft/playwright-mcp",
    commit=None,
    package_digest="sha512-XLTUeA6mEN9sQ+hJ4dfG8EIkDbxS0K3Trc2RBkUJuf02TgE2FQRNTMtq/aJfhyRMINsRl/Ybc4sxcWLtFn4/TQ==",
    dependency_lock_digest=None,
    license="Apache-2.0",
    protocol="MCP stdio",
    status="preferred-browser-backend",
    limitations=(
        "Playwright MCP is not a security boundary.",
        "Origin allowlists do not prevent redirects and must not be treated as containment.",
    ),
)

WINDOWS_MCP_RECEIPT = ExternalExecutorReceipt(
    name="windows-mcp",
    version="0.8.2",
    source="https://github.com/CursorTouch/Windows-MCP",
    commit=None,
    package_digest=None,
    dependency_lock_digest=None,
    license="MIT",
    protocol="MCP stdio",
    status="optional-high-risk-computer-backend",
    limitations=(
        "The server has full host access and can perform irreversible operations.",
        "The 0.8.2 PyPI package requires Python 3.13 or newer.",
        "SOVA disables telemetry and excludes PowerShell, Registry, FileSystem, "
        "Process, and Clipboard.",
        "Accessibility-tree targeting has documented interaction limitations.",
    ),
)


__all__ = [
    "MELRA_AUDIT_RECEIPT",
    "PLAYWRIGHT_MCP_RECEIPT",
    "WINDOWS_MCP_RECEIPT",
    "ExternalExecutorReceipt",
]
