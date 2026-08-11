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
    version="0.3.0-alpha.10",
    source="https://github.com/XAGI-Lab/melra",
    commit="b9edeb35b3749de029386c929fbe8a21cc666a08",
    package_digest=None,
    dependency_lock_digest="sha256:0c85260bc26947ac834ad2202d8c1ecb345cce245fac00e72393c9b064a17fc0",
    license="Apache-2.0",
    protocol="MCP 2025-11-25 stdio",
    status="optional-windows-live-validated-with-bounds",
    limitations=(
        "The Windows source build compiles every package but its CLI script still fails at "
        "an unconditional POSIX chmod step.",
        "MELRA's L3 conformance exercises file effects; it does not prove browser, terminal, "
        "computer, or memory conformance.",
        "Windows computer input targets the active desktop and MELRA reports that focus is "
        "not independently verified.",
        "MELRA developer mode is not a hard trust boundary and its own roadmap leaves enforced "
        "sandboxing and independent verification unfinished.",
    ),
)

CUA_DRIVER_AUDIT_RECEIPT = ExternalExecutorReceipt(
    name="cua-driver",
    version="0.12.6",
    source="https://github.com/trycua/cua",
    commit="9eb1f481b8a12cd6ffda2ad5af21653a9e5aa9e5",
    package_digest="sha256:d18a0ca02314c6dc7dfdfbb20aac8f52c7b1547308f182546a9252a991d4d0dd",
    dependency_lock_digest=None,
    license="MIT",
    protocol="MCP stdio",
    status="optional-windows-release-read-live-action-runner-blocked",
    limitations=(
        "The official Windows x86_64 release checksum was verified and bounded read-only MCP "
        "calls passed live. Fixture-owned mutation remains blocked on the current runner because "
        "it exposes no independently verifiable foreground desktop.",
        "CUA 0.12.6 UI Automation timed out on both a fixture-owned Windows Forms window and "
        "Notepad on this host; its pixel/global-input fallback was not counted without an exact "
        "foreground ownership check.",
        "The exact source build requires Microsoft's Spectre-mitigated Visual C++ libraries, "
        "which are absent on the current validation host; SOVA did not weaken that mitigation.",
        "Host-desktop automation is not isolation. Use a separately admitted VM backend for "
        "untrusted agents or applications.",
        "CUA telemetry is default-on upstream; every SOVA launch forces it off and confines "
        "its telemetry state to the admitted workspace.",
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

CHROME_DEVTOOLS_MCP_RECEIPT = ExternalExecutorReceipt(
    name="chrome-devtools-mcp",
    version="1.6.0",
    source="https://github.com/ChromeDevTools/chrome-devtools-mcp",
    commit="f621d0052fd241dca76e7f615b20e9d320ba965f",
    package_digest=(
        "sha512-VZX6f/OjQSYhy2BGGRs+y3LsrsAQAz/HwZCWKBLVyST/4r/3zjVEjjVW7gMCVbRD"
        "uspnVdcp5hQDPrQ5UFrdZw=="
    ),
    dependency_lock_digest=None,
    license="Apache-2.0",
    protocol="MCP stdio",
    status="independent-browser-conformance-backend",
    limitations=(
        "Chrome DevTools MCP is an executor and observation source, not containment or an "
        "independent truth oracle.",
        "It supports Google Chrome and Chrome for Testing; other Chromium browsers are not "
        "part of its official compatibility claim.",
        "SOVA disables upstream usage statistics, update checks, CrUX lookups, unrestricted "
        "paths, experimental vision, extensions, WebMCP, and memory-debugging categories.",
        "A persistent or already-running browser can contain sensitive authenticated state; "
        "SOVA uses isolated profiles by default and requires a separately admitted vault for "
        "persistence.",
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
    "CHROME_DEVTOOLS_MCP_RECEIPT",
    "CUA_DRIVER_AUDIT_RECEIPT",
    "MELRA_AUDIT_RECEIPT",
    "PLAYWRIGHT_MCP_RECEIPT",
    "WINDOWS_MCP_RECEIPT",
    "ExternalExecutorReceipt",
]
