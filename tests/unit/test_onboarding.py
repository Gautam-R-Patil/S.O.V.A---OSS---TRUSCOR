# SPDX-License-Identifier: Apache-2.0
"""Topic 25 onboarding and managed-data safety contracts."""

from __future__ import annotations

import importlib.metadata
import json
from pathlib import Path

import pytest

import sova.onboarding as onboarding_module
from sova.cli import main
from sova.formats.errors import FormatError
from sova.onboarding import (
    CONFIG_FILE,
    CONTROL_KEY,
    INSTANCE_MARKER,
    delete_instance_data,
    diagnose_instance,
    initialize_instance,
)


def test_init_is_account_free_secret_free_and_idempotent(tmp_path: Path) -> None:
    root = tmp_path / "state"
    result = initialize_instance(root, provider="openai")
    assert result["created"] is True
    assert result["providerCredentialStored"] is False
    assert result["networkUsed"] is False
    assert (root / INSTANCE_MARKER).is_file()
    assert (root / CONTROL_KEY).stat().st_size >= 32
    config = json.loads((root / CONFIG_FILE).read_text(encoding="utf-8"))
    assert config["provider"]["credentialEnvironment"] == "OPENAI_API_KEY"
    assert "credentialValue" not in json.dumps(config)

    reused = initialize_instance(root, provider="none")
    assert reused["reused"] is True
    assert reused["instanceId"] == result["instanceId"]


def test_init_refuses_nonempty_unmarked_directory(tmp_path: Path) -> None:
    root = tmp_path / "state"
    root.mkdir()
    (root / "user.txt").write_text("preserve", encoding="utf-8")
    with pytest.raises(FormatError, match="non-empty"):
        initialize_instance(root)
    assert (root / "user.txt").read_text(encoding="utf-8") == "preserve"


def test_doctor_never_exposes_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    initialize_instance(root, provider="openai")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-appear")
    report = diagnose_instance(root)
    assert report["status"] == "pass"
    assert report["provider"]["credentialAvailable"] is True
    assert report["provider"]["credentialValueRead"] is False
    assert "must-not-appear" not in json.dumps(report)
    assert report["networkUsed"] is False


def test_deletion_requires_identity_preview_and_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "state"
    created = initialize_instance(root)
    (root / "evidence" / "result.json").write_text("{}", encoding="utf-8")
    instance_id = str(created["instanceId"])
    preview = delete_instance_data(root, instance_id=instance_id, confirmed=False)
    assert preview["status"] == "preview"
    assert root.exists()
    with pytest.raises(FormatError, match="did not match"):
        delete_instance_data(root, instance_id="sova-instance-wrong", confirmed=True)
    deleted = delete_instance_data(root, instance_id=instance_id, confirmed=True)
    assert deleted["status"] == "deleted"
    assert deleted["recoverable"] is False
    assert not root.exists()


def test_deletion_refuses_unknown_entries_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "state"
    created = initialize_instance(root)
    (root / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(FormatError, match="unknown top-level"):
        delete_instance_data(root, instance_id=str(created["instanceId"]), confirmed=True)
    assert (root / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_diagnostics_and_deletion_fail_closed_on_managed_file_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    created = initialize_instance(root)
    original = type(root).is_symlink

    def report_config_as_link(path: Path) -> bool:
        return path.name == CONFIG_FILE or original(path)

    monkeypatch.setattr(type(root), "is_symlink", report_config_as_link)
    with pytest.raises(FormatError, match="symlink"):
        diagnose_instance(root)
    with pytest.raises(FormatError, match="symlink"):
        delete_instance_data(root, instance_id=str(created["instanceId"]), confirmed=True)
    assert root.exists()


def test_init_rejects_provider_and_registry_errors(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="provider"):
        initialize_instance(tmp_path / "one", provider="unknown")
    with pytest.raises(FormatError, match="registry"):
        initialize_instance(tmp_path / "two", registry=tmp_path / "missing")


def test_init_rejects_broad_and_link_reported_roots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match="filesystem root or the user home"):
        initialize_instance(Path.home())
    root = tmp_path / "state"
    root.mkdir()
    original = type(root).is_symlink
    monkeypatch.setattr(type(root), "is_symlink", lambda path: path == root or original(path))
    with pytest.raises(FormatError, match="root cannot be a symlink"):
        initialize_instance(root)


def test_doctor_reports_corruption_missing_dependency_and_registry_loss(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = tmp_path / "registry"
    registry.mkdir()
    root = tmp_path / "state"
    initialize_instance(root, registry=registry)
    (root / CONTROL_KEY).write_bytes(b"short")
    registry.rmdir()

    real_version = importlib.metadata.version

    def one_missing(name: str) -> str:
        if name == "jsonschema-rs":
            raise importlib.metadata.PackageNotFoundError
        return real_version(name)

    monkeypatch.setattr(importlib.metadata, "version", one_missing)
    report = diagnose_instance(root)
    assert report["status"] == "fail"
    assert report["checks"]["controlKey"] is False
    assert report["checks"]["runtimeDependencies"] is False
    assert report["checks"]["registrySelection"] is False


def test_doctor_rejects_missing_and_non_object_configuration(tmp_path: Path) -> None:
    root = tmp_path / "state"
    initialize_instance(root)
    (root / CONFIG_FILE).unlink()
    with pytest.raises(FormatError, match="unavailable"):
        diagnose_instance(root)
    (root / CONFIG_FILE).write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="JSON object"):
        diagnose_instance(root)


def test_deletion_refuses_invalid_managed_directory_and_resource_excess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "invalid-directory"
    created = initialize_instance(root)
    (root / "artifacts").rmdir()
    (root / "artifacts").write_text("not a directory", encoding="utf-8")
    with pytest.raises(FormatError, match="managed directories"):
        delete_instance_data(root, instance_id=str(created["instanceId"]), confirmed=True)

    limited = tmp_path / "limited"
    created = initialize_instance(limited)
    (limited / "evidence" / "one").write_text("1", encoding="utf-8")
    monkeypatch.setattr(onboarding_module, "_MAX_MANAGED_FILES", 0)
    with pytest.raises(FormatError, match="review limits"):
        delete_instance_data(limited, instance_id=str(created["instanceId"]), confirmed=True)


def test_confirmed_deletion_removes_nested_directories(tmp_path: Path) -> None:
    root = tmp_path / "state"
    created = initialize_instance(root)
    nested = root / "evidence" / "one" / "two"
    nested.mkdir(parents=True)
    (nested / "result").write_text("ok", encoding="utf-8")
    report = delete_instance_data(
        root,
        instance_id=str(created["instanceId"]),
        confirmed=True,
    )
    assert report["deleted"] is True
    assert not root.exists()


def test_onboarding_cli_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "state"
    assert main(["init", str(root), "--provider", "none"]) == 0
    created = json.loads(capsys.readouterr().out)
    assert created["created"] is True
    assert main(["doctor", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "pass"
    assert (
        main(
            [
                "data",
                "delete",
                str(root),
                "--instance-id",
                created["instanceId"],
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "preview"
