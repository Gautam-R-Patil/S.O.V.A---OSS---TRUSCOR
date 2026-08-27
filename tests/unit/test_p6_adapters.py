# SPDX-License-Identifier: Apache-2.0
"""External benchmark adapter positive and adverse tests."""

from __future__ import annotations

import pytest

from sova.formats import FormatError, validate_document
from sova.validation import BenchmarkSource, benchmark_adapter_catalog, normalize_external_case
from tests.support.p6 import digest


@pytest.mark.parametrize(
    ("source", "document"),
    [
        (
            BenchmarkSource.INSPECT_AI,
            {
                "id": "sample",
                "input": "task",
                "target": "answer",
                "metadata": {"targetClass": "api"},
            },
        ),
        (
            BenchmarkSource.AGENTDOJO,
            {
                "suite": "workspace",
                "userTaskId": "user_task_0",
                "injectionTaskId": "injection_task_0",
                "groundTruth": {"safe": True},
            },
        ),
        (
            BenchmarkSource.OASB,
            {
                "controlId": "OASB-1.1",
                "category": "identity",
                "requirement": "require auth",
                "auditProcedure": ["inspect config"],
            },
        ),
        (
            BenchmarkSource.XBEN,
            {
                "id": "XBEN-090",
                "name": "fixture",
                "objective": "find issue",
                "groundTruth": {"class": "CWE-79"},
            },
        ),
        (
            BenchmarkSource.ETHIBENCH,
            {
                "targetId": "fixture",
                "targetClass": "package",
                "targetInput": {"repo": "pinned"},
                "groundTruth": [{"id": "gt-1"}],
            },
        ),
    ],
)
def test_external_benchmark_adapters_bind_content_without_raw_data(
    source: BenchmarkSource, document: dict[str, object]
) -> None:
    case = normalize_external_case(
        source,
        document,
        source_revision_digest=digest("revision"),
        authorization_receipt_digest=digest("authority"),
        license_accepted=True,
    )
    mapping = case.to_mapping()
    validate_document(mapping)
    assert mapping["rawInputEmbedded"] is False
    assert mapping["rawAnswerKeyEmbedded"] is False
    assert "find issue" not in str(mapping)


def test_adapter_catalog_is_unique_and_candidate_scoped() -> None:
    catalog = benchmark_adapter_catalog()
    assert {item.source for item in catalog} == set(BenchmarkSource)
    assert all("candidate" in item.compatibility for item in catalog)


def test_adapters_reject_unaccepted_license_bad_digest_and_shape() -> None:
    document = {
        "id": "sample",
        "input": "task",
        "target": "answer",
        "metadata": {"targetClass": "api"},
    }
    with pytest.raises(FormatError, match="license"):
        normalize_external_case(
            BenchmarkSource.INSPECT_AI,
            document,
            source_revision_digest=digest("revision"),
            authorization_receipt_digest=digest("authority"),
            license_accepted=False,
        )
    with pytest.raises(FormatError, match="SHA-256"):
        normalize_external_case(
            BenchmarkSource.INSPECT_AI,
            document,
            source_revision_digest="bad",
            authorization_receipt_digest=digest("authority"),
            license_accepted=True,
        )
    with pytest.raises(FormatError, match="SHA-256"):
        normalize_external_case(
            BenchmarkSource.INSPECT_AI,
            document,
            source_revision_digest="sha256:" + ("z" * 64),
            authorization_receipt_digest=digest("authority"),
            license_accepted=True,
        )
    with pytest.raises(FormatError, match="metadata"):
        normalize_external_case(
            BenchmarkSource.INSPECT_AI,
            {"id": "sample", "input": "task", "target": "answer", "metadata": []},
            source_revision_digest=digest("revision"),
            authorization_receipt_digest=digest("authority"),
            license_accepted=True,
        )
    with pytest.raises(FormatError, match="requires"):
        normalize_external_case(
            BenchmarkSource.XBEN,
            {"id": "missing"},
            source_revision_digest=digest("revision"),
            authorization_receipt_digest=digest("authority"),
            license_accepted=True,
        )


def test_adapters_reject_invalid_text_target_class_and_injection_identifier() -> None:
    common = {
        "source_revision_digest": digest("revision"),
        "authorization_receipt_digest": digest("authority"),
        "license_accepted": True,
    }
    with pytest.raises(FormatError, match="non-empty"):
        normalize_external_case(
            BenchmarkSource.INSPECT_AI,
            {"id": "", "input": "task", "target": "answer", "metadata": {"targetClass": "api"}},
            **common,  # type: ignore[arg-type]
        )
    with pytest.raises(FormatError, match="unsupported"):
        normalize_external_case(
            BenchmarkSource.INSPECT_AI,
            {
                "id": "id",
                "input": "task",
                "target": "answer",
                "metadata": {"targetClass": "unknown"},
            },
            **common,  # type: ignore[arg-type]
        )
    with pytest.raises(FormatError, match="non-empty"):
        normalize_external_case(
            BenchmarkSource.AGENTDOJO,
            {
                "suite": "workspace",
                "userTaskId": "task",
                "injectionTaskId": "",
                "groundTruth": {},
            },
            **common,  # type: ignore[arg-type]
        )
