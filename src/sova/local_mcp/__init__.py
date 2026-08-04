# SPDX-License-Identifier: Apache-2.0
"""Local-first SOVA MCP server and control channel."""

from sova.local_mcp.approval import LocalApprovalStore, create_control_key, load_control_key
from sova.local_mcp.model import (
    MCP_PROTOCOL_VERSION,
    SOVA_MCP_MANIFEST_VERSION,
    InvocationDescriptor,
    LocalToolDefinition,
    manifest_document,
)
from sova.local_mcp.server import LocalSOVAMCPServer, serve_stdio
from sova.local_mcp.tools import (
    LOCAL_TOOL_DEFINITIONS,
    PINNED_TOOL_MANIFEST_DIGEST,
    LocalToolContext,
    dispatch_local_tool,
    manifest_self_check,
    tool_manifest,
)

__all__ = [
    "LOCAL_TOOL_DEFINITIONS",
    "MCP_PROTOCOL_VERSION",
    "PINNED_TOOL_MANIFEST_DIGEST",
    "SOVA_MCP_MANIFEST_VERSION",
    "InvocationDescriptor",
    "LocalApprovalStore",
    "LocalSOVAMCPServer",
    "LocalToolContext",
    "LocalToolDefinition",
    "create_control_key",
    "dispatch_local_tool",
    "load_control_key",
    "manifest_document",
    "manifest_self_check",
    "serve_stdio",
    "tool_manifest",
]
