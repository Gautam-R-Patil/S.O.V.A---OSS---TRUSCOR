# SPDX-License-Identifier: Apache-2.0
"""Contracts that prevent Topic 02 sentinels from becoming accidental schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict, cast

import pytest


class _Sentinel(TypedDict):
    fixtureExpected: str
    fixtureStatus: str
    kind: str
    specVersion: str


@pytest.mark.compat
@pytest.mark.parametrize(
    ("relative_path", "kind"),
    [
        ("golden/scenario/unsupported-pre-schema.sova", "sova.scenario"),
        ("golden/trace/unsupported-pre-schema.sova-trace", "sova.trace"),
    ],
)
def test_pre_schema_golden_is_explicitly_unsupported(
    relative_path: str,
    kind: str,
) -> None:
    fixture_root = Path(__file__).parents[2] / "fixtures"
    data = cast(
        "_Sentinel",
        json.loads((fixture_root / relative_path).read_text(encoding="utf-8")),
    )

    assert data == {
        "fixtureExpected": "reject",
        "fixtureStatus": "topic-02-pre-schema-sentinel",
        "kind": kind,
        "specVersion": "0.0.0",
    }
