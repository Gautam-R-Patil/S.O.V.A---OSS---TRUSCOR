# SPDX-License-Identifier: Apache-2.0
"""Typed contracts for safe real-task rehearsal."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|authorization|cookie|credential|password|secret|token)",
    re.IGNORECASE,
)
_OPAQUE_SECRET = re.compile(r"^sova-secret:[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_EMBEDDED_SECRET = re.compile(
    r"(?im)(api[_-]?key|authorization|cookie|credential|password|secret|token)"
    r"\s*[:=]\s*(?![\"']?<SOVA-REDACTED:)[\"']?[^\s,;\"']{8,}"
)
_MAX_ACTIONS = 4096


class RehearsalActionKind(StrEnum):
    FILE_WRITE = "file.write"
    FILE_DELETE = "file.delete"
    PROCESS = "process"
    DATABASE = "database"
    API = "api"
    NETWORK = "network"
    BROWSER = "browser"
    COMPUTER = "computer"


class ReviewState(StrEnum):
    PROPOSED = "proposed"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPORTED = "exported"


def _validate_secret_free(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise FormatError("SOVA-REHEARSE-FIELD", "action object keys must be strings")
            if _SENSITIVE_KEY.search(key) and (
                not isinstance(child, str)
                or (
                    _OPAQUE_SECRET.fullmatch(child) is None
                    and not child.startswith("<SOVA-REDACTED:")
                )
            ):
                raise FormatError(
                    "SOVA-REHEARSE-SECRET",
                    "Credential fields require an opaque reference or redacted placeholder.",
                    path=f"{path}.{key}",
                )
            _validate_secret_free(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_secret_free(child, f"{path}[{index}]")
    elif isinstance(value, str):
        if _OPAQUE_SECRET.fullmatch(value) is not None or value.startswith("<SOVA-REDACTED:"):
            return
        private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
        if private_key_marker in value:
            raise FormatError(
                "SOVA-REHEARSE-SECRET",
                "private-key material is forbidden in rehearsal actions",
                path=path,
            )
        if _EMBEDDED_SECRET.search(value):
            raise FormatError(
                "SOVA-REHEARSE-SECRET",
                "credential-shaped material is forbidden in rehearsal action content",
                path=path,
            )


@dataclass(frozen=True, slots=True)
class RehearsalAction:
    action_id: str
    actor_id: str
    kind: RehearsalActionKind
    target: str
    operation: str
    parameters: dict[str, Any]
    material_step: bool = False

    def __post_init__(self) -> None:
        if _IDENTIFIER.fullmatch(self.action_id) is None:
            raise FormatError("SOVA-REHEARSE-ACTION-ID", "action id is invalid")
        if _IDENTIFIER.fullmatch(self.actor_id) is None:
            raise FormatError("SOVA-REHEARSE-ACTOR-ID", "actor id is invalid")
        if not self.target or not self.operation:
            raise FormatError("SOVA-REHEARSE-ACTION", "target and operation are required")
        _validate_secret_free(self.parameters)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.action_id,
            "actorId": self.actor_id,
            "kind": self.kind.value,
            "target": self.target,
            "operation": self.operation,
            "parameters": self.parameters,
            "materialStep": self.material_step,
        }


@dataclass(frozen=True, slots=True)
class RehearsalSpecification:
    task: str
    agent_id: str
    actions: tuple[RehearsalAction, ...]
    authorization_confirmed: bool
    with_attack: bool = False
    attack_profile: str | None = None
    substitutes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.task.strip() or _IDENTIFIER.fullmatch(self.agent_id) is None:
            raise FormatError("SOVA-REHEARSE-SPEC", "task and valid agent id are required")
        if len(self.actions) > _MAX_ACTIONS:
            raise FormatError("SOVA-REHEARSE-ACTION-LIMIT", "rehearsal action limit exceeded")
        action_ids = [action.action_id for action in self.actions]
        if len(action_ids) != len(set(action_ids)):
            raise FormatError("SOVA-REHEARSE-DUPLICATE", "action ids must be unique")
        if any(action.actor_id != self.agent_id for action in self.actions):
            raise FormatError(
                "SOVA-REHEARSE-ACTOR",
                "normal rehearsal actions must belong to the declared user agent",
            )
        if self.with_attack and not self.attack_profile:
            raise FormatError(
                "SOVA-REHEARSE-ATTACK-PROFILE",
                "adversarial rehearsal requires an explicit attack profile",
            )


@dataclass(frozen=True, slots=True)
class EnvironmentPreparation:
    workspace: str
    source_fingerprint: str
    cloned_file_count: int
    sanitized_file_count: int
    omitted: tuple[dict[str, str], ...]
    substitutes: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "workspace": self.workspace,
            "sourceFingerprint": self.source_fingerprint,
            "clonedFileCount": self.cloned_file_count,
            "sanitizedFileCount": self.sanitized_file_count,
            "omitted": list(self.omitted),
            "substitutes": list(self.substitutes),
            "disposable": True,
            "productionCredentialsImported": False,
            "productionServicesReachable": False,
            "isolationClaim": "filesystem-scoped-substitute-workspace-not-a-security-sandbox",
        }


@dataclass(frozen=True, slots=True)
class ProposedChange:
    change_id: str
    action_id: str
    kind: str
    target: str
    before_digest: str | None
    after_digest: str | None
    preview: str
    state: ReviewState = ReviewState.PROPOSED

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.change_id,
            "actionId": self.action_id,
            "kind": self.kind,
            "target": self.target,
            "beforeDigest": self.before_digest,
            "afterDigest": self.after_digest,
            "preview": self.preview,
            "reviewState": self.state.value,
        }


@dataclass(frozen=True, slots=True)
class RehearsalReport:
    task: str
    agent_id: str
    trace_path: str
    trace_digest: str
    environment: EnvironmentPreparation
    changes: tuple[ProposedChange, ...]
    capability_reach: tuple[str, ...]
    material_captures: tuple[str, ...]
    with_attack: bool
    completed: bool
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        document = {
            "artifactType": "sova.rehearsal-report",
            "schemaVersion": "0.1.0",
            "task": self.task,
            "agentId": self.agent_id,
            "trace": {"path": self.trace_path, "digest": self.trace_digest, "signed": True},
            "environment": self.environment.to_mapping(),
            "changes": [change.to_mapping() for change in self.changes],
            "capabilityReach": list(self.capability_reach),
            "materialCaptures": list(self.material_captures),
            "withAttack": self.with_attack,
            "completed": self.completed,
            "allEffectsConfinedToSubstitutes": True,
            "productionEffects": False,
            "selectiveExportRequired": True,
            "limitations": list(self.limitations),
        }
        document["reportDigest"] = sha256_digest(canonical_json_bytes(document))
        return document


def _required_string(value: Mapping[str, Any], name: str) -> str:
    member = value.get(name)
    if not isinstance(member, str) or not member:
        raise FormatError("SOVA-REHEARSE-FIELD", f"{name} must be a non-empty string")
    return member


def specification_from_mapping(value: Mapping[str, Any]) -> RehearsalSpecification:
    raw_actions = value.get("actions")
    if not isinstance(raw_actions, list):
        raise FormatError("SOVA-REHEARSE-FIELD", "actions must be an array")
    actions: list[RehearsalAction] = []
    for row in raw_actions:
        if not isinstance(row, Mapping):
            raise FormatError("SOVA-REHEARSE-FIELD", "actions must contain objects")
        parameters = row.get("parameters", {})
        if not isinstance(parameters, dict):
            raise FormatError("SOVA-REHEARSE-FIELD", "parameters must be an object")
        material = row.get("materialStep", False)
        if not isinstance(material, bool):
            raise FormatError("SOVA-REHEARSE-FIELD", "materialStep must be boolean")
        try:
            kind = RehearsalActionKind(_required_string(row, "kind"))
        except ValueError as error:
            raise FormatError("SOVA-REHEARSE-KIND", "unsupported rehearsal action kind") from error
        actions.append(
            RehearsalAction(
                action_id=_required_string(row, "id"),
                actor_id=_required_string(row, "actorId"),
                kind=kind,
                target=_required_string(row, "target"),
                operation=_required_string(row, "operation"),
                parameters=parameters,
                material_step=material,
            )
        )
    authorized = value.get("authorizationConfirmed")
    with_attack = value.get("withAttack", False)
    if not isinstance(authorized, bool) or not isinstance(with_attack, bool):
        raise FormatError(
            "SOVA-REHEARSE-FIELD",
            "authorizationConfirmed and withAttack must be boolean",
        )
    substitutes = value.get("substitutes", [])
    if not isinstance(substitutes, list) or any(not isinstance(item, str) for item in substitutes):
        raise FormatError("SOVA-REHEARSE-FIELD", "substitutes must contain strings")
    attack_profile = value.get("attackProfile")
    if attack_profile is not None and not isinstance(attack_profile, str):
        raise FormatError("SOVA-REHEARSE-FIELD", "attackProfile must be a string or null")
    return RehearsalSpecification(
        task=_required_string(value, "task"),
        agent_id=_required_string(value, "agentId"),
        actions=tuple(actions),
        authorization_confirmed=authorized,
        with_attack=with_attack,
        attack_profile=attack_profile,
        substitutes=tuple(sorted(set(substitutes))),
    )


__all__ = [
    "EnvironmentPreparation",
    "ProposedChange",
    "RehearsalAction",
    "RehearsalActionKind",
    "RehearsalReport",
    "RehearsalSpecification",
    "ReviewState",
    "specification_from_mapping",
]
