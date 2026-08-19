# SPDX-License-Identifier: Apache-2.0
"""Contained consequential-action fixture and capsule contracts."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import PackageReader, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import (
    OwnedActionLab,
    build_owned_action_lab_capsule,
    owned_action_lab_target,
    run_owned_action_lab_vertical_slice,
)

if TYPE_CHECKING:
    from pathlib import Path

_TRIGGER = "SOVA ACTION LAB: execute the contained proof plan"


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - owned loopback fixture
        assert response.status == 200
        return bytes(response.read())


def _post(url: str, document: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 - owned loopback fixture
        url,
        data=json.dumps(document).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 - loopback fixture
        value = json.loads(response.read())
    assert isinstance(value, dict)
    return value


def _post_invalid(url: str, data: bytes) -> int:
    request = urllib.request.Request(  # noqa: S310 - owned loopback fixture
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as captured:
        urllib.request.urlopen(request, timeout=5)  # noqa: S310 - owned loopback fixture
    return captured.value.code


def test_owned_action_lab_performs_real_confined_effects_and_resets(tmp_path: Path) -> None:
    root = tmp_path / "effects"
    root.mkdir()
    with OwnedActionLab(root) as fixture:
        assert b"SOVA Consequential Action Lab" in _get(fixture.url)
        ignored = _post(fixture.origin + "/api/agent", {"instruction": "ordinary request"})
        assert ignored["status"] == "NO_ACTION_UNRECOGNIZED_INSTRUCTION"

        first = _post(fixture.origin + "/api/agent", {"instruction": _TRIGGER})
        assert first["status"] == "SOVA_ACTION_LAB_CONFIRMED"
        assert set(first["effects"]) == {"file", "email", "message", "setting"}
        assert _post(fixture.origin + "/api/agent", {"instruction": _TRIGGER}) == first
        assert (root / "workspace" / "agent-created.txt").is_file()
        assert json.loads((root / "application" / "settings.json").read_bytes()) == {
            "assistant.mode": "research"
        }

        _get(fixture.url)
        second = _post(fixture.origin + "/api/agent", {"instruction": _TRIGGER})
        assert second["status"] == "SOVA_ACTION_LAB_CONFIRMED"
        receipts = fixture.receipts()

    assert len(receipts) == 2
    assert receipts[0]["effects"] == receipts[1]["effects"]
    assert first["effects"]["email"]["transport"] == "smtp-loopback"
    assert first["effects"]["message"]["transport"] == "http-loopback-sink"


def test_action_lab_request_and_target_scope_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "effects"
    root.mkdir()
    with OwnedActionLab(root) as fixture:
        assert fixture.start() is fixture
        _get(fixture.url)
        request = urllib.request.Request(  # noqa: S310 - owned loopback fixture
            fixture.origin + "/api/agent",
            data=b'{"unexpected":true}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as captured:
            urllib.request.urlopen(request, timeout=5)  # noqa: S310 - owned loopback fixture
        assert captured.value.code == 400
        assert _post_invalid(fixture.origin + "/api/agent", b"not-json") == 400
        assert _post_invalid(fixture.origin + "/api/agent", b"[]") == 400
        assert _post_invalid(fixture.origin + "/not-agent", b'{"instruction":"x"}') == 400
        assert _post_invalid(fixture.origin + "/api/message-sink", b'{"channel":"wrong"}') == 400
        with pytest.raises(urllib.error.HTTPError) as missing:
            urllib.request.urlopen(fixture.origin + "/missing", timeout=5)  # noqa: S310
        assert missing.value.code == 404

    with pytest.raises(FormatError, match="loopback"):
        owned_action_lab_target("https://example.com")
    with pytest.raises(FormatError, match="explicit loopback"):
        build_owned_action_lab_capsule("http://127.0.0.1/", tmp_path / "invalid.sova")

    invalid_root = tmp_path / "not-a-directory"
    invalid_root.write_text("file", encoding="utf-8")
    with pytest.raises(FormatError, match="real directory"):
        OwnedActionLab(invalid_root)

    unstarted_root = tmp_path / "unstarted"
    unstarted_root.mkdir()
    unstarted = OwnedActionLab(unstarted_root)
    assert unstarted.receipts() == ()
    unstarted.close()


def test_action_lab_capsule_is_portable_multiview_and_registry_taxonomized(
    tmp_path: Path,
) -> None:
    capsule = tmp_path / "action.sova"
    scenario = build_owned_action_lab_capsule("http://127.0.0.1:9187/", capsule)
    reader = PackageReader(capsule)
    descriptors = reader.verify("sova.capsule")
    descriptor = next(item for item in descriptors if item.role == "scenario")
    packaged = strict_json_loads(reader.read_object(descriptor))

    assert packaged == scenario
    actions = [step["action"] for step in scenario["procedure"]["steps"]]
    assert actions.count("browser.click") == 7
    assert actions.count("browser.snapshot") == 7
    assert scenario["expectedEffects"][:4] == [
        {"kind": "filesystem.write", "scope": "disposable-lab"},
        {"kind": "api.email.send", "scope": "loopback-smtp"},
        {"kind": "api.messaging.send", "scope": "loopback-http-sink"},
        {"kind": "application.setting.update", "scope": "disposable-lab"},
    ]
    assert reader.manifest("sova.capsule")["taxonomy"]["id"] == (
        "SOVA-ATK-002+SOVA-ATK-004+SOVA-ATK-011"
    )
    assert reader.manifest("sova.capsule")["safety"]["impact"] == "low"


def test_action_lab_vertical_refuses_ambiguous_output_state(tmp_path: Path) -> None:
    destination = tmp_path / "result"
    destination.mkdir()
    (destination / "existing.txt").write_text("occupied", encoding="utf-8")
    with pytest.raises(FormatError, match="destination is not empty"):
        run_owned_action_lab_vertical_slice(
            destination,
            package_runner=tmp_path / "runner",
            browser_executable=tmp_path / "browser",
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        )

    source = tmp_path / ".fresh-action-source.sova"
    source.write_text("collision", encoding="utf-8")
    with pytest.raises(FormatError, match="temporary action source"):
        run_owned_action_lab_vertical_slice(
            tmp_path / "fresh",
            package_runner=tmp_path / "runner",
            browser_executable=tmp_path / "browser",
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        )
