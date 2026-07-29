# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for versions, fingerprints, and interpretation context."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from sova.contracts import (
    AbsenceReason,
    ContentDigest,
    ContractError,
    ExplicitAbsence,
    FingerprintedReference,
    InterpretationContext,
    ModelReference,
    SemanticVersion,
    VersionedReference,
)

if TYPE_CHECKING:
    from collections.abc import Callable

_DIGEST = ContentDigest(f"sha256:{'a' * 64}")
_ABSENT = ExplicitAbsence(AbsenceReason.NOT_APPLICABLE, "not used by this run")


@pytest.mark.parametrize(
    "value",
    ["0.1.0", "1.0.0", "2.7.3-alpha.1", "10.20.30+build.5"],
)
def test_exact_semantic_versions_round_trip(value: str) -> None:
    assert str(SemanticVersion.parse(value)) == value


@pytest.mark.parametrize(
    "value",
    ["1", "1.2", "01.2.3", "1.02.3", "1.2.03", "v1.2.3", "1.2.3-01", "1.2.3 "],
)
def test_malformed_versions_fail_without_coercion(value: str) -> None:
    with pytest.raises(ContractError) as caught:
        SemanticVersion.parse(value)
    assert caught.value.code == "SOVA-CONTRACT-INVALID-VERSION"


def test_digest_requires_canonical_sha256() -> None:
    assert _DIGEST.algorithm == "sha256"
    assert _DIGEST.hex_digest == "a" * 64
    with pytest.raises(ContractError) as caught:
        ContentDigest(f"SHA256:{'A' * 64}")
    assert caught.value.code == "SOVA-CONTRACT-INVALID-DIGEST"


def test_explicit_absence_requires_an_explanation() -> None:
    with pytest.raises(ContractError) as caught:
        ExplicitAbsence(AbsenceReason.NOT_RECORDED, " ")
    assert caught.value.code == "SOVA-CONTRACT-MISSING-CONTEXT"


@pytest.mark.parametrize(
    ("factory", "expected_field"),
    [
        (
            lambda: VersionedReference("Invalid Name", SemanticVersion.parse("0.1.0"), _DIGEST),
            "name",
        ),
        (lambda: FingerprintedReference("", _DIGEST), "name"),
        (lambda: ModelReference("Example", "model", _DIGEST, "revision"), "provider"),
        (lambda: ModelReference("example", "", _DIGEST, "revision"), "model"),
        (lambda: ModelReference("example", "model", _DIGEST, ""), "provider_revision"),
    ],
)
def test_context_names_and_presence_fail_closed(
    factory: Callable[[], object],
    expected_field: str,
) -> None:
    with pytest.raises(ContractError) as caught:
        factory()
    assert caught.value.field == expected_field


def test_interpretation_context_retains_every_axis() -> None:
    version = SemanticVersion.parse("0.1.0")
    contract = VersionedReference("sova.domain", version, _DIGEST)
    context = InterpretationContext(
        schema=contract,
        taxonomy=VersionedReference("sova.attack", version, _DIGEST),
        methodology=VersionedReference("sova.example-method", version, _DIGEST),
        executor=VersionedReference("sova.scripted-executor", version, _DIGEST),
        adapter=_ABSENT,
        model=ModelReference("example", "model-1", _DIGEST, _ABSENT),
        target=FingerprintedReference("example-target", _DIGEST),
        environment=FingerprintedReference("example-environment", _DIGEST),
        judge=_ABSENT,
        oracle=VersionedReference("sova.example-oracle", version, _DIGEST),
        registry_snapshot=_ABSENT,
    )

    assert tuple(context.as_mapping()) == (
        "schema",
        "taxonomy",
        "methodology",
        "executor",
        "adapter",
        "model",
        "target",
        "environment",
        "judge",
        "oracle",
        "registry_snapshot",
    )
    assert isinstance(context.model, ModelReference)
    assert context.model.configuration_fingerprint == _DIGEST
