# SPDX-License-Identifier: Apache-2.0
"""Protocol-only extension fixture intentionally outside the SOVA package."""

from __future__ import annotations

import json
import sys

request = json.loads(sys.stdin.buffer.readline())
response = {
    "protocol": "sova.extension-jsonl/0.1",
    "manifestDigest": request["manifestDigest"],
    "operation": request["operation"],
    "accepted": request["operation"] in {"describe", "self-test", "invoke"},
    "capabilities": ["oracle.fixture"] if request["operation"] == "describe" else [],
}
sys.stdout.write(json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n")
