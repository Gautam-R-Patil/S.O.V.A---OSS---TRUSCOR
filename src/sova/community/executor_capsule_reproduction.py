# SPDX-License-Identifier: Apache-2.0
"""Build a deterministic fresh-run chamber document from an engine `.sova` capsule."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from sova.community.executor_chamber_config import validate_executor_chamber_document
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_CONTRACT_TYPE = "sova.executor-chamber-reproduction-contract"
_PLAN_TYPE = "sova.executor-chamber-reproduction-plan"
_MAX_WORKERS = 8
_MAX_ROUNDS = 64
_MAX_ACTIONS = 512
_BROWSER_CODEC = "sova.action-codec.browser/0.1.0"
_COMPUTER_CODEC = "sova.action-codec.computer/0.1.0"
_OBSERVATION_DIGEST_PLACEHOLDER = "$SOVA_OBSERVATION_DIGEST"
_COMPUTER_BINDING_PLACEHOLDER = "$SOVA_COMPUTER_BINDING"


def _json_artifacts(capsule: Path) -> dict[str, list[dict[str, Any]]]:
    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    result: dict[str, list[dict[str, Any]]] = {}
    for descriptor in descriptors:
        if descriptor.role != "attachment" or descriptor.mediaType != "application/json":
            continue
        value = strict_json_loads(reader.read_object(descriptor))
        if not isinstance(value, dict):
            continue
        artifact_type = value.get("artifactType")
        if isinstance(artifact_type, str):
            result.setdefault(artifact_type, []).append(value)
    return result


def _exact_artifact(
    artifacts: dict[str, list[dict[str, Any]]],
    artifact_type: str,
) -> dict[str, Any]:
    matches = artifacts.get(artifact_type, [])
    if len(matches) != 1:
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            f"capsule must contain exactly one {artifact_type} attachment",
        )
    return matches[0]


def _source_document(contract: dict[str, Any]) -> dict[str, Any]:
    if contract.get("schemaVersion") != "0.1.0":
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "engine reproduction contract version is unsupported",
        )
    document = contract.get("document")
    if not isinstance(document, dict):
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "engine reproduction contract has no chamber document",
        )
    if contract.get("sourceDocumentDigest") != sha256_digest(canonical_json_bytes(document)):
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "engine reproduction contract document digest does not match",
        )
    authorization = document.get("authorization")
    if not isinstance(authorization, dict):
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "source chamber authorization is malformed",
        )
    validate_executor_chamber_document(
        document,
        provider_calls_authorized=authorization.get("providerCalls") is True,
        offensive=authorization.get("offensive") is True,
    )
    return document


def _validated_actions(
    plan: dict[str, Any],
    source: dict[str, Any],
    trace_digests: frozenset[str],
) -> list[dict[str, Any]]:
    if (
        plan.get("schemaVersion") != "0.1.0"
        or plan.get("freshTargetAndSessionRequired") is not True
        or plan.get("freshAuthorizationRequired") is not True
        or plan.get("credentialMaterialIncluded") is not False
        or plan.get("sourceTraceDigest") not in trace_digests
    ):
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "reproduction plan is not bound to a contained fresh authorized run",
        )
    source_case = source.get("case")
    if not isinstance(source_case, dict) or plan.get("caseId") != source_case.get("id"):
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "reproduction plan case does not match its chamber contract",
        )
    grants = source.get("grants")
    if not isinstance(grants, list):
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "source chamber grants are malformed",
        )
    grant_by_id = {
        item.get("id"): item
        for item in grants
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    actions = plan.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > _MAX_ACTIONS:
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "reproduction plan must contain 1..512 exact actions",
        )
    validated: list[dict[str, Any]] = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict) or action.get("order") != index:
            raise FormatError(
                "SOVA-ENGINE-CAPSULE-REPRODUCTION",
                "reproduction plan action order is malformed",
            )
        grant = grant_by_id.get(action.get("grantId"))
        arguments = action.get("plannerArguments")
        if (
            not isinstance(grant, dict)
            or not isinstance(arguments, dict)
            or action.get("codecId") != grant.get("codecId")
            or action.get("bindingId") != grant.get("bindingId")
            or action.get("argumentSchemaDigest")
            != sha256_digest(canonical_json_bytes(grant.get("argumentSchema")))
            or ("action" in arguments and action.get("action") != arguments.get("action"))
        ):
            raise FormatError(
                "SOVA-ENGINE-CAPSULE-REPRODUCTION",
                "reproduction action does not match its exact admitted grant",
                details={"order": index},
            )
        validated.append(action)
    return validated


def _fresh_planner_arguments(action: dict[str, Any]) -> dict[str, Any]:
    arguments = strict_json_loads(canonical_json_bytes(action["plannerArguments"]))
    if not isinstance(arguments, dict):  # validated before this conversion
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "recorded planner arguments are malformed",
        )
    codec_id = action["codecId"]
    if codec_id == _BROWSER_CODEC:
        if set(arguments) != {"action", "arguments", "observationDigest"}:
            raise FormatError(
                "SOVA-ENGINE-CAPSULE-REPRODUCTION",
                "recorded browser action cannot be safely rebound to a fresh observation",
            )
        arguments["observationDigest"] = _OBSERVATION_DIGEST_PLACEHOLDER
    elif codec_id == _COMPUTER_CODEC:
        if set(arguments) != {"action", "arguments", "binding", "observationDigest"}:
            raise FormatError(
                "SOVA-ENGINE-CAPSULE-REPRODUCTION",
                "recorded computer action cannot be safely rebound to a fresh identity",
            )
        arguments["binding"] = _COMPUTER_BINDING_PLACEHOLDER
        arguments["observationDigest"] = _OBSERVATION_DIGEST_PLACEHOLDER
    return arguments


def build_executor_capsule_reproduction_document(capsule: Path) -> dict[str, Any]:
    """Return an offline scripted chamber document for a fresh authorized runtime.

    The returned document contains no provider calls or credentials. It preserves
    the exact recorded planner arguments, grant bindings, typed oracle, budgets,
    and authority target. Actual execution still requires a newly admitted target,
    a fresh control proof, and normal human approvals.
    """
    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    trace_digests = frozenset(item.digest for item in descriptors if item.role == "trace")
    artifacts = _json_artifacts(capsule)
    contract = _exact_artifact(artifacts, _CONTRACT_TYPE)
    plan = _exact_artifact(artifacts, _PLAN_TYPE)
    source = _source_document(contract)
    actions = _validated_actions(plan, source, trace_digests)

    worker_count = max(2, math.ceil(len(actions) / _MAX_ROUNDS))
    if worker_count > _MAX_WORKERS:
        raise FormatError(
            "SOVA-ENGINE-CAPSULE-REPRODUCTION",
            "reproduction plan exceeds the bounded chamber worker schedule",
        )
    rounds = math.ceil(len(actions) / worker_count)
    used_grants = sorted({str(item["grantId"]) for item in actions})
    participants: list[dict[str, Any]] = []
    for worker_index in range(worker_count):
        turns: list[dict[str, Any]] = []
        for round_index in range(rounds):
            action_index = round_index * worker_count + worker_index
            scheduled = actions[action_index : action_index + 1]
            turns.append(
                {
                    "expectedContains": "sova.executor-chamber-planner/0.1.0",
                    "responseText": "",
                    "structured": {
                        "status": "continue",
                        "message": "execute exact capsule-bound reproduction action",
                        "actions": [
                            {
                                "grantId": item["grantId"],
                                "arguments": _fresh_planner_arguments(item),
                            }
                            for item in scheduled
                        ],
                        "coverage": ["capsule-bound-fresh-reproduction"],
                        "reason": "reproduce signed independently verified engine evidence",
                    },
                    "tokenCount": 1,
                }
            )
        identifier = f"capsule-reproducer-{worker_index + 1:02d}"
        participants.append(
            {
                "id": identifier,
                "objective": "Reproduce only the exact capsule-recorded authorized actions.",
                "allowedGrants": used_grants,
                "model": {
                    "adapter": "scripted",
                    "modelId": f"sova-capsule-reproducer/{worker_index + 1}",
                    "turns": turns,
                },
            }
        )

    source_authorization = source["authorization"]
    source_case = source["case"]
    budget = strict_json_loads(canonical_json_bytes(source["budget"]))
    if not isinstance(budget, dict):  # defensive: source validation already establishes this
        raise FormatError("SOVA-ENGINE-CAPSULE-REPRODUCTION", "source budget is malformed")
    budget["rounds"] = rounds
    budget["maxActionsPerTurn"] = 1
    budget["maxTotalActions"] = len(actions)
    document = {
        "artifactType": "sova.executor-chamber",
        "schemaVersion": "0.1.0",
        "authorization": {
            "authorityTarget": source_authorization["authorityTarget"],
            "providerCalls": False,
            "offensive": source_authorization["offensive"],
        },
        "case": {
            "id": source_case["id"],
            "title": source_case["title"],
            "objective": "Fresh authorized reproduction of exact signed capsule actions.",
        },
        "budget": budget,
        "grants": strict_json_loads(canonical_json_bytes(source["grants"])),
        "participants": participants,
        "oracle": strict_json_loads(canonical_json_bytes(source["oracle"])),
    }
    if not isinstance(document["grants"], list) or not isinstance(document["oracle"], dict):
        raise FormatError("SOVA-ENGINE-CAPSULE-REPRODUCTION", "source contract is malformed")
    validate_executor_chamber_document(
        document,
        provider_calls_authorized=False,
        offensive=document["authorization"]["offensive"] is True,
    )
    return document


__all__ = ["build_executor_capsule_reproduction_document"]
