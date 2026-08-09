# SPDX-License-Identifier: Apache-2.0
"""SOVA-owned MCP client, adapters, broker, and external receipts."""

from sova.mcp.adapter import (
    CuaDriverExecutorAdapter,
    MCPExecutorAdapter,
    MelraExecutorAdapter,
    MelraTaskState,
    ToolMapping,
    playwright_mappings,
    windows_mcp_mappings,
)
from sova.mcp.broker import CapabilityExecutionBroker, UnavailableCapabilityExecutor
from sova.mcp.cua_driver import CuaDriverService
from sova.mcp.protocol import (
    MCPClient,
    MCPTool,
    MCPToolResult,
    StdioMCPClient,
    StdioServerSpec,
)
from sova.mcp.receipts import (
    CUA_DRIVER_AUDIT_RECEIPT,
    MELRA_AUDIT_RECEIPT,
    PLAYWRIGHT_MCP_RECEIPT,
    WINDOWS_MCP_RECEIPT,
    ExternalExecutorReceipt,
)
from sova.mcp.specs import (
    CuaDriverDirectories,
    MelraDirectories,
    WindowsMCPDirectories,
    cua_driver_stdio_spec,
    melra_stdio_spec,
    playwright_stdio_spec,
    windows_mcp_stdio_spec,
)

__all__ = [
    "CUA_DRIVER_AUDIT_RECEIPT",
    "MELRA_AUDIT_RECEIPT",
    "PLAYWRIGHT_MCP_RECEIPT",
    "WINDOWS_MCP_RECEIPT",
    "CapabilityExecutionBroker",
    "CuaDriverDirectories",
    "CuaDriverExecutorAdapter",
    "CuaDriverService",
    "ExternalExecutorReceipt",
    "MCPClient",
    "MCPExecutorAdapter",
    "MCPTool",
    "MCPToolResult",
    "MelraDirectories",
    "MelraExecutorAdapter",
    "MelraTaskState",
    "StdioMCPClient",
    "StdioServerSpec",
    "ToolMapping",
    "UnavailableCapabilityExecutor",
    "WindowsMCPDirectories",
    "cua_driver_stdio_spec",
    "melra_stdio_spec",
    "playwright_mappings",
    "playwright_stdio_spec",
    "windows_mcp_mappings",
    "windows_mcp_stdio_spec",
]
