# SPDX-License-Identifier: Apache-2.0
"""Loss-reporting adapters for selected external security-evaluation case formats."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.validation.contracts import TargetClass

_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class BenchmarkSource(StrEnum):
    INSPECT_AI = "inspect-ai"
    AGENTDOJO = "agentdojo"
    OASB = "oasb"
    XBEN = "xben"
    ETHIBENCH = "ethibench"


@dataclass(frozen=True, slots=True)
class BenchmarkAdapterSpec:
    source: BenchmarkSource
    upstream: str
    license_identifier: str
    compatibility: str
    case_shape: str
    safety_boundary: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "source": self.source.value,
            "upstream": self.upstream,
            "licenseIdentifier": self.license_identifier,
            "compatibility": self.compatibility,
            "caseShape": self.case_shape,
            "safetyBoundary": self.safety_boundary,
        }


_CATALOG = (
    BenchmarkAdapterSpec(
        BenchmarkSource.INSPECT_AI,
        "https://github.com/UKGovernmentBEIS/inspect_evals",
        "MIT",
        "sample-json-v0-candidate",
        "Sample id/input/target/metadata",
        "import only; caller supplies an authorized sandbox",
    ),
    BenchmarkAdapterSpec(
        BenchmarkSource.AGENTDOJO,
        "https://github.com/ethz-spylab/agentdojo",
        "MIT",
        "suite-task-v0-candidate",
        "suite plus user-task and optional injection-task identifiers",
        "synthetic tool environments only",
    ),
    BenchmarkAdapterSpec(
        BenchmarkSource.OASB,
        "https://github.com/opena2a-org/oasb",
        "Apache-2.0",
        "control-v0.4-candidate",
        "control id/category/requirement/audit procedure",
        "control import is not an OASB certification",
    ),
    BenchmarkAdapterSpec(
        BenchmarkSource.XBEN,
        "https://github.com/xbow-engineering/validation-benchmarks",
        "Apache-2.0",
        "benchmark-yaml-v2025-candidate",
        "benchmark id/name/category/objective",
        "canary-marked evaluation data; isolated targets only",
    ),
    BenchmarkAdapterSpec(
        BenchmarkSource.ETHIBENCH,
        "https://github.com/ethiack/ethibench",
        "MIT",
        "dataset-ground-truth-v2026-candidate",
        "target id/class plus input and ground-truth records",
        "LLM matching is proposal evidence until independently calibrated",
    ),
)


@dataclass(frozen=True, slots=True)
class ExternalBenchmarkCase:
    identifier: str
    source: BenchmarkSource
    target_class: TargetClass
    source_revision_digest: str
    authorization_receipt_digest: str
    input_digest: str
    answer_key_commitment: str
    license_identifier: str
    losses: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.external-benchmark-case",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "source": self.source.value,
            "targetClass": self.target_class.value,
            "sourceRevisionDigest": self.source_revision_digest,
            "authorizationReceiptDigest": self.authorization_receipt_digest,
            "inputDigest": self.input_digest,
            "answerKeyCommitment": self.answer_key_commitment,
            "licenseIdentifier": self.license_identifier,
            "losses": list(self.losses),
            "rawInputEmbedded": False,
            "rawAnswerKeyEmbedded": False,
            "upstreamScoreImportedAsTruth": False,
        }


def benchmark_adapter_catalog() -> tuple[BenchmarkAdapterSpec, ...]:
    return _CATALOG


def _required(document: Mapping[str, Any], name: str) -> Any:
    try:
        return document[name]
    except KeyError as error:
        raise FormatError("SOVA-P6-ADAPTER-FIELD", f"external case requires {name}") from error


def _text(value: Any, role: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FormatError("SOVA-P6-ADAPTER-TYPE", f"{role} must be non-empty text")
    return value


def _target_class(value: Any) -> TargetClass:
    try:
        return TargetClass(_text(value, "target class"))
    except ValueError as error:
        raise FormatError("SOVA-P6-ADAPTER-CLASS", "target class is unsupported") from error


def _digest(value: str, role: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise FormatError("SOVA-P6-ADAPTER-DIGEST", f"{role} must be a SHA-256 digest")


def _case_parts(
    source: BenchmarkSource, document: Mapping[str, Any]
) -> tuple[str, TargetClass, Any, Any, tuple[str, ...]]:
    if source is BenchmarkSource.INSPECT_AI:
        metadata = _required(document, "metadata")
        if not isinstance(metadata, Mapping):
            raise FormatError("SOVA-P6-ADAPTER-TYPE", "Inspect metadata must be an object")
        return (
            _text(_required(document, "id"), "Inspect sample id"),
            _target_class(_required(metadata, "targetClass")),
            _required(document, "input"),
            _required(document, "target"),
            ("Inspect sandbox and scorer configuration require separate bindings",),
        )
    if source is BenchmarkSource.AGENTDOJO:
        suite = _text(_required(document, "suite"), "AgentDojo suite")
        user_task = _text(_required(document, "userTaskId"), "AgentDojo user task")
        injection = document.get("injectionTaskId")
        if injection is not None:
            _text(injection, "AgentDojo injection task")
        return (
            f"{suite}:{user_task}" + ("" if injection is None else f":{injection}"),
            TargetClass.AI_AGENT,
            {"suite": suite, "userTaskId": user_task, "injectionTaskId": injection},
            _required(document, "groundTruth"),
            ("Upstream utility and security scorers are not imported as SOVA truth",),
        )
    if source is BenchmarkSource.OASB:
        identifier = _text(_required(document, "controlId"), "OASB control id")
        return (
            identifier,
            TargetClass.AI_AGENT,
            {
                "category": _required(document, "category"),
                "requirement": _required(document, "requirement"),
            },
            _required(document, "auditProcedure"),
            ("Control conformance does not imply product certification",),
        )
    if source is BenchmarkSource.XBEN:
        identifier = _text(_required(document, "id"), "XBEN id")
        return (
            identifier,
            TargetClass.WEB,
            {"name": _required(document, "name"), "objective": _required(document, "objective")},
            _required(document, "groundTruth"),
            ("Canary-marked case content must remain evaluation-only",),
        )
    identifier = _text(_required(document, "targetId"), "EthiBench target id")
    return (
        identifier,
        _target_class(_required(document, "targetClass")),
        _required(document, "targetInput"),
        _required(document, "groundTruth"),
        ("Semantic matching output requires calibration and human adjudication",),
    )


def normalize_external_case(
    source: BenchmarkSource,
    document: Mapping[str, Any],
    *,
    source_revision_digest: str,
    authorization_receipt_digest: str,
    license_accepted: bool,
) -> ExternalBenchmarkCase:
    """Bind external case content without copying raw tasks or treating scores as truth."""
    if not license_accepted:
        raise FormatError("SOVA-P6-ADAPTER-LICENSE", "external benchmark license was not accepted")
    _digest(source_revision_digest, "source revision")
    _digest(authorization_receipt_digest, "authorization receipt")
    spec = next(item for item in _CATALOG if item.source is source)
    identifier, target_class, input_value, answer_value, losses = _case_parts(source, document)
    return ExternalBenchmarkCase(
        identifier=f"{source.value}:{identifier}",
        source=source,
        target_class=target_class,
        source_revision_digest=source_revision_digest,
        authorization_receipt_digest=authorization_receipt_digest,
        input_digest=sha256_digest(canonical_json_bytes(input_value)),
        answer_key_commitment=sha256_digest(canonical_json_bytes(answer_value)),
        license_identifier=spec.license_identifier,
        losses=losses,
    )


__all__ = [
    "BenchmarkAdapterSpec",
    "BenchmarkSource",
    "ExternalBenchmarkCase",
    "benchmark_adapter_catalog",
    "normalize_external_case",
]
