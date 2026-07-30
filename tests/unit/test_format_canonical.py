# SPDX-License-Identifier: Apache-2.0
"""Strict JSON and canonical-byte contracts."""

from __future__ import annotations

import json
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.canonical import MAX_IJSON_INTEGER
from sova.formats.errors import FormatError


def test_duplicate_keys_are_rejected() -> None:
    with pytest.raises(FormatError, match="duplicate JSON"):
        strict_json_loads(b'{"a":1,"a":2}')


def test_invalid_utf8_and_nonfinite_numbers_are_rejected() -> None:
    with pytest.raises(FormatError) as utf8:
        strict_json_loads(b'{"value":"\xff"}')
    assert utf8.value.issue.code == "SOVA-FORMAT-INVALID-UTF8"

    with pytest.raises(FormatError) as number:
        strict_json_loads(b'{"value":NaN}')
    assert number.value.issue.code == "SOVA-FORMAT-NONFINITE-NUMBER"


def test_canonical_profile_rejects_binary_floats() -> None:
    with pytest.raises(FormatError) as error:
        canonical_json_bytes({"threshold": 0.1})
    assert error.value.issue.code == "SOVA-FORMAT-CANONICAL-FLOAT"


def test_canonical_profile_uses_utf16_order_and_ijson_integer_bounds() -> None:
    rendered = canonical_json_bytes({"\ue000": 2, "\U00010000": 1})
    assert rendered == '{"𐀀":1,"\ue000":2}'.encode()
    assert canonical_json_bytes({"n": MAX_IJSON_INTEGER})
    with pytest.raises(FormatError) as too_large:
        canonical_json_bytes({"n": MAX_IJSON_INTEGER + 1})
    assert too_large.value.issue.code == "SOVA-FORMAT-IJSON-INTEGER"
    with pytest.raises(FormatError) as surrogate:
        canonical_json_bytes({"bad": "\ud800"})
    assert surrogate.value.issue.code == "SOVA-FORMAT-INVALID-UNICODE"
    with pytest.raises(FormatError) as key_type:
        canonical_json_bytes({1: "invalid"})
    assert key_type.value.issue.code == "SOVA-FORMAT-NONSTRING-KEY"


@given(
    st.dictionaries(
        st.text(
            alphabet=string.ascii_letters + string.digits + "_-",
            min_size=1,
            max_size=12,
        ),
        st.one_of(st.none(), st.booleans(), st.integers(-(2**31), 2**31), st.text(max_size=24)),
        max_size=20,
    )
)
def test_canonical_round_trip_is_idempotent(value: dict[str, object]) -> None:
    encoded = canonical_json_bytes(value)
    reparsed = strict_json_loads(encoded)
    assert canonical_json_bytes(reparsed) == encoded
    assert sha256_digest(encoded) == sha256_digest(canonical_json_bytes(reparsed))
    assert json.loads(encoded) == value
