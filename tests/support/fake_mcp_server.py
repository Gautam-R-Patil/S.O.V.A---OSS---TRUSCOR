# SPDX-License-Identifier: Apache-2.0
"""Tiny deterministic MCP stdio server used only by offline conformance tests."""

from __future__ import annotations

import json
import sys
from typing import Any


def _send(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def main() -> int:
    for line in sys.stdin:
        message = json.loads(line)
        method = message.get("method")
        request_id = message.get("id")
        if method == "notifications/initialized":
            if "--malformed-after-initialize" in sys.argv:
                sys.stdout.write("{malformed-json\n")
                sys.stdout.flush()
                return 0
            continue
        result: dict[str, Any]
        if method == "initialize":
            result = {
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "sova-fake-mcp", "version": "0.1.0"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "fixture_echo",
                        "description": "Echo a bounded fixture value",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                            "required": ["value"],
                            "additionalProperties": False,
                        },
                        "annotations": {"readOnlyHint": True},
                    }
                ]
            }
        elif method == "tools/call":
            params = message.get("params", {})
            if params.get("name") != "fixture_echo":
                _send(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "error": {"code": -32601, "message": "unknown tool"},
                    }
                )
                continue
            value = params.get("arguments", {}).get("value")
            result = {
                "content": [{"type": "text", "text": str(value)}],
                "structuredContent": {"echo": value},
                "isError": False,
            }
        else:
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "unknown method"},
                }
            )
            continue
        _send({"jsonrpc": "2.0", "id": request_id, "result": result})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
