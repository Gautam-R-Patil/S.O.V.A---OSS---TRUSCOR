# SPDX-License-Identifier: Apache-2.0
"""SOVA-owned MCP client, adapters, broker, and external receipts."""

from sova.mcp.adapter import (
    MCPExecutorAdapter,
    MelraExecutorAdapter,
    MelraTaskState,
    ToolMapping,
    playwright_mappings,
    windows_mcp_mappings,
)
from sova.mcp.broker import CapabilityExecutionBroker, UnavailableCapabilityExecutor
from sova.mcp.protocol import (
    MCPClient,
    MCPTool,
    MCPToolResult,
    StdioMCPClient,
    StdioServerSpec,
)
from sova.mcp.receipts import (
    MELRA_AUDIT_RECEIPT,
    PLAYWRIGHT_MCP_RECEIPT,
    WINDOWS_MCP_RECEIPT,
    ExternalExecutorReceipt,
)
from sova.mcp.specs import (
    WindowsMCPDirectories,
    playwright_stdio_spec,
    windows_mcp_stdio_spec,
)

__all__ = [
    "MELRA_AUDIT_RECEIPT",
    "PLAYWRIGHT_MCP_RECEIPT",
    "WINDOWS_MCP_RECEIPT",
    "CapabilityExecutionBroker",
    "ExternalExecutorReceipt",
    "MCPClient",
    "MCPExecutorAdapter",
    "MCPTool",
    "MCPToolResult",
    "MelraExecutorAdapter",
    "MelraTaskState",
    "StdioMCPClient",
    "StdioServerSpec",
    "ToolMapping",
    "UnavailableCapabilityExecutor",
    "WindowsMCPDirectories",
    "playwright_mappings",
    "playwright_stdio_spec",
    "windows_mcp_mappings",
    "windows_mcp_stdio_spec",
]
