# SPDX-License-Identifier: Apache-2.0
"""Fast/reference JSON Schema acceptance-parity contract."""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sova.formats import schema as schema_module

ARTIFACT_TYPES = ("sova.capsule", "sova.scenario", "sova.trace", "sova.event")
JSON_VALUES = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(1 << 53) + 1, max_value=(1 << 53) - 1)
    | st.text(max_size=24),
    lambda children: (
        st.lists(children, max_size=6) | st.dictionaries(st.text(max_size=16), children, max_size=6)
    ),
    max_leaves=24,
)


@pytest.mark.compat
@pytest.mark.parametrize("artifact_type", ARTIFACT_TYPES)
@settings(max_examples=100, deadline=None)
@given(document=JSON_VALUES)
def test_fast_validator_matches_reference_acceptance(
    artifact_type: str,
    document: object,
) -> None:
    fast_valid = not list(schema_module._validator(artifact_type).iter_errors(document))
    reference_valid = not list(
        schema_module._reference_validator(artifact_type).iter_errors(document)
    )
    assert fast_valid == reference_valid
