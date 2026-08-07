# SPDX-License-Identifier: Apache-2.0
"""Execute user-agent proposals only inside a prepared substitute workspace."""

from __future__ import annotations

import difflib
import platform
from collections.abc import Collection, Mapping
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.rehearsal.model import (
    EnvironmentPreparation,
    ProposedChange,
    RehearsalAction,
    RehearsalActionKind,
    RehearsalReport,
    RehearsalSpecification,
)
from sova.trace import TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from sova.trace.integrity import Ed25519Keypair


def _safe_relative(value: str) -> Path:
    if "\\" in value or "\x00" in value or value.startswith("/"):
        raise FormatError("SOVA-REHEARSE-PATH", "target must be a normalized relative POSIX path")
    candidate = PurePosixPath(value)
    if str(candidate) != value or any(part in {"", ".", ".."} for part in candidate.parts):
        raise FormatError("SOVA-REHEARSE-PATH", "target must be a normalized relative POSIX path")
    if candidate.parts and candidate.parts[0] == ".sova-rehearsal":
        raise FormatError("SOVA-REHEARSE-CONTROL", "actions cannot mutate rehearsal controls")
    return Path(*candidate.parts)


def _workspace_marker(workspace: Path) -> dict[str, Any]:
    marker = workspace / ".sova-rehearsal" / "workspace.json"
    if not marker.is_file():
        raise FormatError("SOVA-REHEARSE-WORKSPACE", "workspace is not prepared by SOVA")
    value = strict_json_loads(marker.read_bytes())
    if not isinstance(value, dict) or value.get("disposable") is not True:
        raise FormatError("SOVA-REHEARSE-WORKSPACE", "workspace marker is malformed")
    return value


def _digest_or_none(path: Path) -> str | None:
    return sha256_digest(path.read_bytes()) if path.is_file() else None


def _text_or_empty(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def _change_id(action: RehearsalAction, before: str | None, after: str | None) -> str:
    return sha256_digest(
        canonical_json_bytes({"action": action.to_mapping(), "before": before, "after": after})
    )


def _event_prefix(kind: RehearsalActionKind) -> str:
    if kind in {RehearsalActionKind.FILE_WRITE, RehearsalActionKind.FILE_DELETE}:
        return "filesystem"
    return kind.value


def _file_change(workspace: Path, action: RehearsalAction) -> ProposedChange:
    relative = _safe_relative(action.target)
    target = workspace / relative
    resolved_parent = target.parent.resolve()
    if (
        workspace.resolve() != resolved_parent
        and workspace.resolve() not in resolved_parent.parents
    ):
        raise FormatError("SOVA-REHEARSE-PATH", "target escaped rehearsal workspace")
    if target.is_symlink():
        raise FormatError("SOVA-REHEARSE-PATH", "file action target cannot be a symbolic link")
    before_digest = _digest_or_none(target)
    before_text = _text_or_empty(target)
    if action.kind == RehearsalActionKind.FILE_WRITE:
        content = action.parameters.get("content")
        if not isinstance(content, str):
            raise FormatError("SOVA-REHEARSE-CONTENT", "file.write requires string content")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
        after_digest = _digest_or_none(target)
        preview = "".join(
            difflib.unified_diff(
                before_text.splitlines(keepends=True),
                content.splitlines(keepends=True),
                fromfile=f"before/{relative.as_posix()}",
                tofile=f"after/{relative.as_posix()}",
            )
        )
    else:
        if target.exists() and (not target.is_file() or target.is_symlink()):
            raise FormatError("SOVA-REHEARSE-DELETE", "file.delete accepts ordinary files only")
        target.unlink(missing_ok=True)
        after_digest = None
        preview = "".join(
            difflib.unified_diff(
                before_text.splitlines(keepends=True),
                [],
                fromfile=f"before/{relative.as_posix()}",
                tofile="/dev/null",
            )
        )
    return ProposedChange(
        change_id=_change_id(action, before_digest, after_digest),
        action_id=action.action_id,
        kind=action.kind.value,
        target=relative.as_posix(),
        before_digest=before_digest,
        after_digest=after_digest,
        preview=preview[:64_000],
    )


def _substitute_change(
    workspace: Path, action: RehearsalAction
) -> tuple[ProposedChange, str | None]:
    effects = workspace / ".sova-rehearsal" / "effects"
    effects.mkdir(exist_ok=True)
    record = {
        "action": action.to_mapping(),
        "executedAgainstProduction": False,
        "substituteOutcome": "recorded",
    }
    payload = canonical_json_bytes(record)
    path = effects / f"{action.action_id}.json"
    path.write_bytes(payload + b"\n")
    screenshot: str | None = None
    if action.material_step or action.kind in {
        RehearsalActionKind.BROWSER,
        RehearsalActionKind.COMPUTER,
    }:
        screenshots = workspace / ".sova-rehearsal" / "screenshots"
        screenshots.mkdir(exist_ok=True)
        screenshot_path = screenshots / f"{action.action_id}.svg"
        escaped = action.operation.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        screenshot_path.write_text(
            "<svg xmlns='http://www.w3.org/2000/svg' width='960' height='540'>"
            "<rect width='100%' height='100%' fill='#07182d'/>"
            "<text x='48' y='80' fill='white' font-family='monospace' font-size='24'>"
            "SOVA substitute-state capture</text>"
            "<text x='48' y='130' fill='#73d5ff' font-family='monospace' "
            f"font-size='18'>{escaped}</text>"
            "<text x='48' y='180' fill='#b9c7d8' font-family='monospace' font-size='16'>"
            "No production browser or computer was contacted.</text></svg>",
            encoding="utf-8",
        )
        screenshot = screenshot_path.relative_to(workspace).as_posix()
    change = ProposedChange(
        change_id=_change_id(action, None, sha256_digest(payload)),
        action_id=action.action_id,
        kind=action.kind.value,
        target=action.target,
        before_digest=None,
        after_digest=sha256_digest(payload),
        preview="Substitute ledger entry only; no production effect.",
    )
    return change, screenshot


def _require_prepared_substitute(
    action: RehearsalAction, substitute_names: Collection[str]
) -> None:
    if action.kind.value not in substitute_names:
        raise FormatError(
            "SOVA-REHEARSE-SUBSTITUTE",
            "action has no prepared inert substitute",
            details={"kind": action.kind.value},
        )


def run_rehearsal(
    specification: RehearsalSpecification,
    workspace: Path,
    trace_path: Path,
    *,
    signing_key: Ed25519Keypair | None = None,
) -> RehearsalReport:
    """Run one authorized plan in a disposable workspace and return review material."""
    workspace = workspace.resolve()
    marker = _workspace_marker(workspace)
    if not specification.authorization_confirmed:
        raise FormatError(
            "SOVA-REHEARSE-AUTHORIZATION",
            "rehearsal requires an explicit human authorization confirmation",
        )
    substitutes_value = strict_json_loads(
        (workspace / ".sova-rehearsal" / "substitutes.json").read_bytes()
    )
    substitute_names = (
        tuple(str(item) for item in substitutes_value.get("services", []))
        if isinstance(substitutes_value, Mapping)
        else ()
    )
    missing_declared = sorted(set(specification.substitutes) - set(substitute_names))
    if missing_declared:
        raise FormatError(
            "SOVA-REHEARSE-SUBSTITUTE",
            "required rehearsal substitutes are not prepared",
            details={"missing": missing_declared},
        )
    key = signing_key or generate_ed25519_keypair()
    changes: list[ProposedChange] = []
    captures: list[str] = []
    reach: set[str] = set()
    writer = TraceWriter(
        trace_path,
        capture_profile="forensic",
        signing_key=key,
        authorization={
            "decision": "allowed",
            "scopeDigest": sha256_digest(canonical_json_bytes(specification.task)),
            "decidedBy": "explicit-human-confirmation",
        },
        environment={
            "platform": "prepared-rehearsal-workspace",
            "python": platform.python_version(),
            "codeDigest": marker.get("sourceFingerprint"),
            "model": None,
            "dependencies": [],
        },
        executor={
            "id": "sova:executor:rehearsal-substitutes",
            "name": "substitute-only-rehearsal",
            "version": "0.1.0",
            "capabilityDigest": None,
        },
    )
    actor = {"id": specification.agent_id, "kind": "user-agent", "name": specification.agent_id}
    attacker = {
        "id": "sova:actor:rehearsal-attacker",
        "kind": "attacker",
        "name": "SOVA adversarial profile",
    }
    start = writer.append("run.started", {"task": specification.task}, actor=actor)
    if specification.with_attack:
        writer.append(
            "prompt.received",
            {
                "profile": specification.attack_profile,
                "injectedInto": "substitute-only-rehearsal",
                "productionEffect": False,
            },
            phase="adversarial-rehearsal",
            actor=attacker,
            parents=[start] if start else [],
        )
    parent = start
    for action in specification.actions:
        event_prefix = _event_prefix(action.kind)
        requested = writer.append(
            f"{event_prefix}.requested",
            {
                "actionId": action.action_id,
                "target": action.target,
                "operation": action.operation,
                "substituteOnly": True,
            },
            phase="user-agent-task",
            actor=actor,
            parents=[parent] if parent else [],
        )
        try:
            if action.kind in {RehearsalActionKind.FILE_WRITE, RehearsalActionKind.FILE_DELETE}:
                change = _file_change(workspace, action)
            else:
                _require_prepared_substitute(action, substitute_names)
                change, capture = _substitute_change(workspace, action)
                if capture is not None:
                    captures.append(capture)
        except (FormatError, OSError) as error:
            error_code = error.issue.code if isinstance(error, FormatError) else "SOVA-IO-ERROR"
            failed = writer.append(
                "error.recorded",
                {
                    "actionId": action.action_id,
                    "errorCode": error_code,
                    "messageRecorded": False,
                    "productionEffect": False,
                },
                phase="user-agent-task",
                actor=actor,
                parents=[requested] if requested else [],
            )
            writer.append(
                "run.failed",
                {"failedActionId": action.action_id, "productionEffects": 0},
                actor=actor,
                parents=[failed] if failed else [],
            )
            writer.finalize(completion="failed")
            raise
        changes.append(change)
        reach.add(action.kind.value)
        parent = writer.append(
            f"{event_prefix}.completed",
            {
                "actionId": action.action_id,
                "changeId": change.change_id,
                "productionEffect": False,
                "reviewState": change.state.value,
            },
            phase="user-agent-task",
            actor=actor,
            parents=[requested] if requested else [],
        )
    writer.append(
        "run.completed",
        {"proposedChanges": len(changes), "productionEffects": 0},
        actor=actor,
        parents=[parent] if parent else [],
    )
    trace_digest = writer.finalize()
    environment = EnvironmentPreparation(
        workspace=str(workspace),
        source_fingerprint=str(marker["sourceFingerprint"]),
        cloned_file_count=int(marker.get("clonedFileCount", 0)),
        sanitized_file_count=int(marker.get("sanitizedFileCount", 0)),
        omitted=tuple(
            dict(item) for item in marker.get("omitted", []) if isinstance(item, Mapping)
        ),
        substitutes=substitute_names,
    )
    return RehearsalReport(
        task=specification.task,
        agent_id=specification.agent_id,
        trace_path=str(trace_path.resolve()),
        trace_digest=trace_digest,
        environment=environment,
        changes=tuple(changes),
        capability_reach=tuple(sorted(reach)),
        material_captures=tuple(captures),
        with_attack=specification.with_attack,
        completed=True,
        limitations=(
            "Ordinary host filesystem scoping is not a security sandbox.",
            "Database, API, network, browser, computer, and command effects use inert substitutes.",
            "Export writes to a separate staging tree and never patches production automatically.",
        ),
    )


def export_approved_changes(
    report: Mapping[str, Any],
    workspace: Path,
    destination: Path,
    approved_change_ids: frozenset[str],
) -> dict[str, Any]:
    """Export explicitly approved file changes into a separate staging directory."""
    workspace = workspace.resolve()
    destination = destination.resolve()
    _workspace_marker(workspace)
    if destination.exists() or destination == workspace or workspace in destination.parents:
        raise FormatError(
            "SOVA-REHEARSE-EXPORT",
            "export destination must be a new directory outside the rehearsal workspace",
        )
    raw_changes = report.get("changes")
    if not isinstance(raw_changes, list):
        raise FormatError("SOVA-REHEARSE-REPORT", "report changes must be an array")
    known_ids = {
        str(row.get("id"))
        for row in raw_changes
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    unknown = sorted(approved_change_ids - known_ids)
    if unknown:
        raise FormatError(
            "SOVA-REHEARSE-APPROVAL",
            "approval referenced an unknown change",
            details={"unknown": unknown},
        )
    destination.mkdir(parents=True)
    exported: list[dict[str, Any]] = []
    rejected: list[str] = []
    deletions: list[dict[str, str]] = []
    for row in raw_changes:
        if not isinstance(row, Mapping):
            raise FormatError("SOVA-REHEARSE-REPORT", "change entries must be objects")
        change_id = str(row.get("id"))
        if change_id not in approved_change_ids:
            rejected.append(change_id)
            continue
        kind = str(row.get("kind"))
        target_value = row.get("target")
        if not isinstance(target_value, str):
            raise FormatError("SOVA-REHEARSE-REPORT", "change target must be a string")
        file_kinds = {
            RehearsalActionKind.FILE_WRITE.value,
            RehearsalActionKind.FILE_DELETE.value,
        }
        if kind not in file_kinds:
            raise FormatError(
                "SOVA-REHEARSE-EXPORT-KIND",
                "only reviewed file changes can be exported",
            )
        relative = _safe_relative(target_value)
        if kind == RehearsalActionKind.FILE_DELETE.value:
            deletions.append({"id": change_id, "path": relative.as_posix()})
            exported.append(
                {"id": change_id, "path": relative.as_posix(), "mode": "deletion-record"}
            )
            continue
        source = workspace / relative
        if not source.is_file() or source.is_symlink():
            raise FormatError("SOVA-REHEARSE-EXPORT-SOURCE", "approved file is missing or unsafe")
        digest = sha256_digest(source.read_bytes())
        if digest != row.get("afterDigest"):
            raise FormatError("SOVA-REHEARSE-EXPORT-DRIFT", "approved file changed after review")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(source.read_bytes())
        exported.append({"id": change_id, "path": relative.as_posix(), "mode": "file"})
    if deletions:
        (destination / "sova-deletions.json").write_bytes(
            canonical_json_bytes({"deletions": deletions, "automaticDeletionPerformed": False})
            + b"\n"
        )
    result = {
        "artifactType": "sova.rehearsal-export",
        "schemaVersion": "0.1.0",
        "exported": exported,
        "rejected": sorted(rejected),
        "productionPatched": False,
        "destination": str(destination),
    }
    (destination / "sova-export-manifest.json").write_bytes(canonical_json_bytes(result) + b"\n")
    return result


__all__ = ["export_approved_changes", "run_rehearsal"]
