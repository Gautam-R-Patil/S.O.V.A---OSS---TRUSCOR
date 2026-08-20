# SPDX-License-Identifier: Apache-2.0
"""Public contained-agent example protocol checks."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

from sova.runtime import oci_agent_runtime_from_mapping


def _call(operation: str, payload: dict[str, object]) -> dict[str, object]:
    root = Path("examples/agents/oci")
    runtime = oci_agent_runtime_from_mapping(
        json.loads((root / "runtime.json").read_text(encoding="utf-8"))
    )
    request = json.dumps(
        {
            "protocol": "sova.oci-agent/0.1",
            "runtimeDigest": runtime.digest,
            "operation": operation,
            "payload": payload,
        },
        separators=(",", ":"),
    )
    completed = subprocess.run(
        [sys.executable, str(root / "agent.py"), "--sova-request-stdin"],
        check=True,
        capture_output=True,
        input=request,
        text=True,
        shell=False,
        timeout=10,
    )
    assert completed.stderr == ""
    assert len(completed.stdout.splitlines()) == 1
    parsed: object = json.loads(completed.stdout)
    assert isinstance(parsed, dict)
    return cast("dict[str, object]", parsed)


def test_public_oci_agent_example_describes_self_tests_and_returns_typed_plan() -> None:
    described = _call("describe", {})
    assert described["accepted"] is True
    assert described["response"]["agentId"] == "example-contained-agent"  # type: ignore[index]
    assert _call("self-test", {})["response"] == {"status": "pass"}
    prompt = json.dumps({"contract": "sova.semantic-browser-planner/0.1.0"})
    responded = _call("respond", {"prompt": prompt})
    assert responded["response"]["structured"]["status"] == "blocked"  # type: ignore[index]
