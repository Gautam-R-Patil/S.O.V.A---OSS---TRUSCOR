# SPDX-License-Identifier: Apache-2.0
"""Hostile-input and refusal branches for provider-assisted rehearsal."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.rehearsal import (
    ProviderRehearsalRequest,
    RehearsalAction,
    RehearsalActionKind,
    RehearsalSpecification,
    WorkspaceDisclosurePolicy,
    prepare_rehearsal_environment,
    preview_provider_rehearsal,
    provider_rehearsal_request_from_mapping,
    run_provider_rehearsal,
    run_rehearsal,
)
from sova.rehearsal.provider import _disclosure_record
from sova.runtime import ModelRouter, RoleKind

if TYPE_CHECKING:
    from pathlib import Path

    from sova.rehearsal import ProviderRehearsalApproval


def _workspace(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    (source / "a.txt").write_text("fixture\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    prepare_rehearsal_environment(source, workspace)
    return workspace


def _request() -> ProviderRehearsalRequest:
    return ProviderRehearsalRequest(
        "Write a fixture result.",
        "edge-agent",
        2,
        WorkspaceDisclosurePolicy(
            include_text_content=False,
            max_files=8,
            max_content_bytes=0,
        ),
    )


def _plan() -> dict[str, Any]:
    return {
        "actions": [
            {
                "id": "write",
                "kind": "file.write",
                "target": "result.txt",
                "operation": "write",
                "parameters": {"content": "safe\n"},
                "materialStep": False,
            }
        ]
    }


def _router(*, tokens: int | None = 1) -> ModelRouter:
    model = ScriptedModel(
        [
            ScriptedTurn(
                "sova.provider-rehearsal-planner/0.1.0",
                json.dumps(_plan()),
                _plan(),
                token_count=tokens,
            )
        ]
    )
    return ModelRouter({RoleKind.STRATEGIST: (model,)})


def _approve(challenge: ProviderRehearsalApproval) -> str:
    return challenge.exact_phrase


@pytest.mark.parametrize("max_files", [True, 0, 513])
def test_disclosure_policy_rejects_invalid_file_limits(max_files: int) -> None:
    with pytest.raises(FormatError, match="file limit"):
        WorkspaceDisclosurePolicy(
            include_text_content=False,
            max_files=max_files,
            max_content_bytes=0,
        )


@pytest.mark.parametrize("max_bytes", [True, -1, 1024 * 1024 + 1])
def test_disclosure_policy_rejects_invalid_byte_limits(max_bytes: int) -> None:
    with pytest.raises(FormatError, match="byte limit"):
        WorkspaceDisclosurePolicy(
            include_text_content=True,
            max_files=1,
            max_content_bytes=max_bytes,
        )


def test_metadata_only_policy_canonicalizes_content_budget() -> None:
    assert (
        WorkspaceDisclosurePolicy(
            include_text_content=False,
            max_files=1,
            max_content_bytes=100,
        ).max_content_bytes
        == 0
    )


@pytest.mark.parametrize(
    ("task", "max_actions", "message"),
    [
        ("", 1, "task is invalid"),
        ("x", True, "action limit is invalid"),
        ("x", 65, "action limit is invalid"),
    ],
)
def test_request_rejects_invalid_task_and_action_limits(
    task: str,
    max_actions: int,
    message: str,
) -> None:
    with pytest.raises(FormatError, match=message):
        ProviderRehearsalRequest(
            task,
            "edge-agent",
            max_actions,
            WorkspaceDisclosurePolicy(
                include_text_content=False,
                max_files=1,
                max_content_bytes=0,
            ),
        )


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ({"schemaVersion": "9.0.0"}, "SOVA-REHEARSE-PROVIDER-REQUEST"),
        ({"workspaceDisclosure": []}, "SOVA-REHEARSE-DISCLOSURE"),
        (
            {
                "workspaceDisclosure": {
                    "includeTextContent": "yes",
                    "maxFiles": 1,
                    "maxContentBytes": 0,
                }
            },
            "SOVA-REHEARSE-DISCLOSURE",
        ),
        (
            {
                "workspaceDisclosure": {
                    "includeTextContent": False,
                    "maxFiles": True,
                    "maxContentBytes": 0,
                }
            },
            "SOVA-REHEARSE-DISCLOSURE",
        ),
        (
            {
                "workspaceDisclosure": {
                    "includeTextContent": False,
                    "maxFiles": 1,
                    "maxContentBytes": True,
                }
            },
            "SOVA-REHEARSE-DISCLOSURE",
        ),
        ({"maxActions": True}, "SOVA-REHEARSE-PROVIDER-REQUEST"),
        ({"withAttack": "no"}, "SOVA-REHEARSE-PROVIDER-REQUEST"),
        ({"attackProfile": 7}, "SOVA-REHEARSE-PROVIDER-REQUEST"),
        ({"task": []}, "SOVA-REHEARSE-PROVIDER-REQUEST"),
    ],
)
def test_request_parser_rejects_malformed_typed_fields(
    mutation: dict[str, Any],
    code: str,
) -> None:
    value = _request().to_mapping()
    value.update(mutation)
    with pytest.raises(FormatError) as captured:
        provider_rehearsal_request_from_mapping(value)
    assert captured.value.issue.code == code


def test_preview_rejects_missing_and_malformed_workspace_markers(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    missing.mkdir()
    with pytest.raises(FormatError, match="not prepared"):
        preview_provider_rehearsal(_request(), missing)

    workspace = _workspace(tmp_path / "malformed")
    marker = workspace / ".sova-rehearsal/workspace.json"
    marker.write_text('{"disposable":false}', encoding="utf-8")
    with pytest.raises(FormatError, match="marker is malformed"):
        preview_provider_rehearsal(_request(), workspace)


def test_preview_reports_all_bounded_omission_reasons(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    (workspace / "b-big.txt").write_bytes(b"x" * (256 * 1024 + 1))
    (workspace / "c-binary.bin").write_bytes(b"\xff\xfe")
    link = workspace / "d-link.txt"
    link.write_text("link-shaped", encoding="utf-8")
    original = type(link).is_symlink
    monkeypatch.setattr(
        type(link),
        "is_symlink",
        lambda path: path == link or original(path),
    )
    preview = preview_provider_rehearsal(
        ProviderRehearsalRequest(
            "Inspect fixture.",
            "edge-agent",
            1,
            WorkspaceDisclosurePolicy(
                include_text_content=True,
                max_files=8,
                max_content_bytes=1,
            ),
        ),
        workspace,
    )
    reasons = {row["reason"] for row in preview["inventory"]["omitted"]}
    assert reasons >= {
        "single-file-content-limit",
        "non-utf8-content",
        "symbolic-link",
        "total-content-limit",
    }

    count_limited = preview_provider_rehearsal(
        ProviderRehearsalRequest(
            "Inspect fixture.",
            "edge-agent",
            1,
            WorkspaceDisclosurePolicy(
                include_text_content=False,
                max_files=1,
                max_content_bytes=0,
            ),
        ),
        workspace,
    )
    assert "file-count-limit" in {row["reason"] for row in count_limited["inventory"]["omitted"]}


def test_disclosure_record_rejects_internal_shape_errors() -> None:
    with pytest.raises(FormatError, match="inventory is invalid"):
        _disclosure_record({"inventory": []})
    with pytest.raises(FormatError, match="file list is invalid"):
        _disclosure_record({"inventory": {"files": None}})


def test_runtime_refuses_empty_budget_existing_destination_and_token_overage(
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    with pytest.raises(FormatError, match="model-turn budget"):
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "turns",
            router=_router(),
            max_model_turns=0,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=_approve,
        )

    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "occupied.txt").write_text("occupied", encoding="utf-8")
    with pytest.raises(FormatError, match="destination is not empty"):
        run_provider_rehearsal(
            _request(),
            workspace,
            existing,
            router=_router(),
            max_model_turns=1,
            max_total_tokens=None,
            provider_calls_authorized=True,
            approval_prompt=_approve,
        )

    with pytest.raises(FormatError, match="token budget exhausted"):
        run_provider_rehearsal(
            _request(),
            workspace,
            tmp_path / "tokens",
            router=_router(tokens=101),
            max_model_turns=1,
            max_total_tokens=100,
            provider_calls_authorized=True,
            approval_prompt=_approve,
        )


def test_runner_refuses_symbolic_link_file_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = _workspace(tmp_path)
    target = workspace / "result.txt"
    target.write_text("existing", encoding="utf-8")
    original = type(target).is_symlink
    monkeypatch.setattr(
        type(target),
        "is_symlink",
        lambda path: path == target or original(path),
    )
    specification = RehearsalSpecification(
        task="refuse link target",
        agent_id="edge-agent",
        actions=(
            RehearsalAction(
                "write",
                "edge-agent",
                RehearsalActionKind.FILE_WRITE,
                "result.txt",
                "write",
                {"content": "blocked"},
            ),
        ),
        authorization_confirmed=True,
    )
    with pytest.raises(FormatError, match="symbolic link"):
        run_rehearsal(specification, workspace, tmp_path / "link.sova-trace")
