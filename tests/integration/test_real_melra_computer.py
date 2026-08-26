# SPDX-License-Identifier: Apache-2.0
"""Opt-in live conformance for the narrowed MELRA computer-use wrapper.

`tests/integration/test_melra_live_optional.py` already exercises the raw
`MelraExecutorAdapter` (browser/terminal/`computer.capabilities`) against a
pinned MELRA build. This module instead drives the SOVA-narrowed surface this
session built (`melra_computer_lazy_executor` / `MelraComputerSnapshotSource`,
`sova.runtime.melra_computer`), whose `computer.inspect` provider-output shape
is explicitly flagged as provisional in that module's docstring -- this is the
one place that assumption gets checked against a real MELRA instance instead
of the fake-transport unit tests in `tests/unit/test_melra_computer.py`.

Reuses the same env-var convention as `test_melra_live_optional.py`
(`SOVA_RUN_MELRA=1`, `SOVA_MELRA_NODE`, `SOVA_MELRA_CLI`).
`MelraComputerSnapshotSource` calls `computer.inspect` with no pid/window
arguments (those only apply to click/type/scroll mutation calls, per
`ComputerActionCodec._bound_inputs`), so no extra window setup is required
here.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from sova.runtime.computer_surface import ComputerSurfaceSnapshot
from sova.runtime.melra_computer import (
    MelraComputerSnapshotSource,
    _parse_inspect_elements,
    melra_computer_lazy_executor,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("SOVA_RUN_MELRA") != "1",
    reason="set SOVA_RUN_MELRA=1 with the audited MELRA source paths",
)


def _policy_factory(tmp_path: Path) -> Path:
    policy = tmp_path / "melra-policy.json"
    policy.write_text(
        json.dumps(
            {
                "version": "sova-live-conformance",
                "workspaceRoot": str(tmp_path.resolve()),
                "allowedCommands": [],
                "allowedDomains": [],
                "allowLocalhost": True,
                "mutations": "confirm",
                "approvalTtlMs": 300_000,
                "maxFileBytes": 1_000_000,
            }
        ),
        encoding="utf-8",
    )
    return policy


@pytest.mark.integration
def test_optional_real_melra_computer_inspect_matches_the_pinned_contract(
    tmp_path: Path,
) -> None:
    node = Path(os.environ["SOVA_MELRA_NODE"])
    cli = Path(os.environ["SOVA_MELRA_CLI"])

    lazy_executor = melra_computer_lazy_executor(
        node_executable=node,
        cli_entrypoint=cli,
        policy_factory=lambda _workspace: _policy_factory(tmp_path),
        mutations=("computer.click", "computer.type", "computer.scroll"),
    )
    try:
        outcome = lazy_executor.trusted_observe(
            workspace=tmp_path,
            action="computer.inspect",
            inputs={},
        )
        assert outcome.status.value == "succeeded"
        provider_output = outcome.output["providerOutput"]
        assert isinstance(provider_output["elements"], list)

        targets = _parse_inspect_elements(
            provider_output, ("computer.click", "computer.type", "computer.scroll")
        )
        assert isinstance(targets, tuple)
        for target in targets:
            assert target.reference.startswith("melra-")
            assert set(target.locator) == {"x", "y"}
            assert set(target.actions) <= {"computer.click", "computer.type", "computer.scroll"}
    finally:
        lazy_executor.close()


@pytest.mark.integration
def test_optional_real_melra_snapshot_source_builds_a_redacted_snapshot(
    tmp_path: Path,
) -> None:
    """Exercise the actual `ComputerSnapshotCallback` a live engine run would call."""
    node = Path(os.environ["SOVA_MELRA_NODE"])
    cli = Path(os.environ["SOVA_MELRA_CLI"])

    lazy_executor = melra_computer_lazy_executor(
        node_executable=node,
        cli_entrypoint=cli,
        policy_factory=lambda _workspace: _policy_factory(tmp_path),
    )
    source = MelraComputerSnapshotSource(lazy_executor)
    source.bind_workspace(tmp_path)
    try:
        snapshot = source()
        assert isinstance(snapshot, ComputerSurfaceSnapshot)
        assert snapshot.projection["melra"]["elementCount"] == len(snapshot.reviewed_targets)
        names = {capability.name for capability in lazy_executor.capabilities()}
        assert names == {"computer.inspect", "computer.click", "computer.type"}
    finally:
        lazy_executor.close()
