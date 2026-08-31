# SPDX-License-Identifier: Apache-2.0
"""Deterministic, non-executing work orders for a frozen P6 evaluation protocol."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest

if TYPE_CHECKING:
    from sova.validation.contracts import EvaluationProtocol

_MAX_IJSON_SEED = (1 << 53) - 1


def _derived_seed(
    protocol: EvaluationProtocol, lane_id: str, target_id: str, repetition: int
) -> int:
    material = canonical_json_bytes(
        {
            "protocolDigest": protocol.digest,
            "protocolSeed": protocol.seed,
            "laneId": lane_id,
            "targetId": target_id,
            "repetition": repetition,
        }
    )
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big") & _MAX_IJSON_SEED


def build_evaluation_work_orders(protocol: EvaluationProtocol) -> dict[str, Any]:
    """Expand the complete frozen matrix without granting execution or answer-key access."""
    orders: list[dict[str, Any]] = []
    for lane in sorted(protocol.lanes, key=lambda item: item.identifier):
        for target in sorted(protocol.targets, key=lambda item: item.identifier):
            for repetition in range(protocol.repetitions):
                identity = {
                    "protocolDigest": protocol.digest,
                    "laneId": lane.identifier,
                    "targetId": target.identifier,
                    "repetition": repetition,
                }
                orders.append(
                    {
                        "id": "run:" + sha256_digest(canonical_json_bytes(identity))[7:],
                        **identity,
                        "releaseCommit": protocol.release_commit,
                        "lane": lane.to_mapping(),
                        "target": {
                            "id": target.identifier,
                            "targetClass": target.target_class.value,
                            "inputDigest": target.input_digest,
                            "authorizationReceiptDigest": target.authorization_receipt_digest,
                            "sourceRevision": target.source_revision,
                            "licenseIdentifier": target.license_identifier,
                            "containmentBackend": target.containment_backend,
                        },
                        "derivedSeed": _derived_seed(
                            protocol, lane.identifier, target.identifier, repetition
                        ),
                        "budget": protocol.budget.to_mapping(),
                        "controls": {
                            "answerKeyAvailable": False,
                            "automaticExecutionAuthorized": False,
                            "automaticPublicationAuthorized": False,
                        },
                    }
                )
    body: dict[str, Any] = {
        "artifactType": "sova.evaluation-work-order-set",
        "schemaVersion": "0.1.0",
        "protocolDigest": protocol.digest,
        "releaseCommit": protocol.release_commit,
        "expectedRuns": protocol.run_count,
        "workOrders": orders,
        "claims": {
            "completeProtocolMatrixExpanded": len(orders) == protocol.run_count,
            "answerKeyEmbedded": False,
            "targetExecutionPerformed": False,
            "publicationPerformed": False,
        },
    }
    body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    return body


__all__ = ["build_evaluation_work_orders"]
