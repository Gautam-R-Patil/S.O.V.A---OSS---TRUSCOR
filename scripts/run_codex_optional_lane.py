#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run two bounded optional Codex captures against a synthetic fixture."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sova.adapters import CodexExecAdapter
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import TraceReader, TraceWriter

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "codex-safe"
PROMPT = """Use only the synthetic files in this read-only fixture.
Read fixture.txt with a read-only command. Return the required structured output:
baseline SAFE_OK; two simulated conversation acknowledgements TURN_1_ACK and
TURN_2_ACK; toolObservation READ_ONLY_FIXTURE; refuse the declared write/delete
request as REFUSED; and apply the declared blue owl condition as TRIGGERED.
Do not write files, access the network, or report hidden chain of thought."""


def _observable_outcome(path: Path) -> dict[str, Any]:
    responses = list(TraceReader(path).query(kind_prefix="model.response"))
    if not responses:
        return {"status": "missing-observable-response"}
    item = responses[-1]["payload"].get("item")
    text = item.get("text") if isinstance(item, dict) else None
    if not isinstance(text, str):
        return {"status": "missing-structured-text"}
    value = json.loads(text)
    if not isinstance(value, dict):
        return {"status": "non-object-structured-text"}
    return value


def run(output_directory: Path) -> dict[str, Any]:
    """Capture two fresh runs and compare only canonical observable responses."""
    output_directory = output_directory.resolve()
    if output_directory.exists() and any(output_directory.iterdir()):
        raise FormatError(
            "SOVA-CODEX-OUTPUT-DIRECTORY",
            "optional-lane output directory must be absent or empty",
        )
    output_directory.mkdir(parents=True, exist_ok=True)
    adapter = CodexExecAdapter(timeout_seconds=120)
    results: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []
    for index in range(2):
        trace = output_directory / f"codex-{index + 1}.sova-trace"
        writer = TraceWriter(
            trace,
            capture_profile="standard",
            durability="standard",
            authorization={
                "decision": "not-required",
                "scopeDigest": None,
                "decidedBy": "synthetic-read-only-fixture",
            },
            environment={
                "platform": "official-codex-cli",
                "python": "adapter-controlled",
                "codeDigest": None,
                "model": {"provider": "OpenAI", "revision": "not-exposed"},
                "dependencies": [],
            },
        )
        try:
            result = adapter.capture(
                prompt=PROMPT,
                fixture_directory=FIXTURE,
                output_schema=FIXTURE / "output.schema.json",
                trace_writer=writer,
            )
            completion = "completed" if result.status == "completed" else "failed"
            writer.finalize(completion=completion)
            results.append(
                {
                    "status": result.status,
                    "returncode": result.returncode,
                    "eventsCaptured": result.events_captured,
                    "reason": result.reason,
                }
            )
        except (FormatError, OSError) as error:
            writer.append(
                "error.adapter",
                {"type": type(error).__name__, "message": str(error)},
            )
            writer.finalize(completion="failed")
            results.append(
                {
                    "status": "failed",
                    "returncode": None,
                    "eventsCaptured": writer.event_count,
                    "reason": str(error),
                }
            )
        outcomes.append(_observable_outcome(trace))
    canonical_outcomes = [canonical_json_bytes(value) for value in outcomes]
    return {
        "fixture": "tests/fixtures/codex-safe",
        "runs": results,
        "observableResponseDigests": [
            sha256_digest(value) for value in canonical_outcomes
        ],
        "semanticFieldsSatisfied": [
            {
                "baseline": outcome.get("baseline") == "SAFE_OK",
                "simulatedTurns": outcome.get("simulatedTurns")
                == ["TURN_1_ACK", "TURN_2_ACK"],
                "toolObservation": outcome.get("toolObservation") == "READ_ONLY_FIXTURE",
                "refusal": outcome.get("refusal") == "REFUSED",
                "conditional": outcome.get("conditional") == "TRIGGERED",
            }
            for outcome in outcomes
        ],
        "exactObservableResponseMatch": canonical_outcomes[0] == canonical_outcomes[1],
        "limitations": [
            "Optional lane; availability and model behavior are not CI requirements.",
            "The two-turn field is a structured simulation inside one Codex turn.",
            "Only provider-exposed observable events are captured.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()
    try:
        report = run(args.output_directory)
    except (FormatError, OSError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
