# SPDX-License-Identifier: Apache-2.0
"""Cross-input controls for the authorization-gated live executor engine."""

from __future__ import annotations

import time
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import pytest

import sova.community.live_executor_engine as live_engine
from sova.community.executor_chamber import (
    CompositeProjectionOracle,
    ExecutorChamberArtifacts,
    ProjectionFieldOracle,
    ProjectionPredicateOracle,
)
from sova.community.executor_surfaces import workspace_surface_generation
from sova.community.live_executor_engine import (
    _validate_chamber_oracle_binding,
    _validate_controls,
    _validate_mission_oracle_binding,
)
from sova.formats.errors import FormatError
from sova.live import owned_web_target
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime.sessions import BrowserProfileLease

if TYPE_CHECKING:
    from pathlib import Path


def _mission() -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="owned-oracle-binding-fixture",
        title="Owned oracle binding fixture",
        entry_url="http://127.0.0.1:8080/",
        objective="Exercise one harmless owned fixture and observe its marker.",
        allowed_actions=("browser.click",),
        seed_inputs=("bounded fixture input",),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA-OWNED-FIXTURE-OBSERVED",
        max_planner_turns=1,
        max_actions=1,
        max_actions_per_plan=1,
        max_duration_seconds=30,
        max_pages=1,
        max_mutations=1,
        max_consecutive_failures=1,
        max_generated_text_characters=128,
        max_total_tokens=None,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def test_live_engine_requires_exact_mission_oracle_binding() -> None:
    mission = _mission()
    _validate_mission_oracle_binding(
        mission,
        field_path=("browser", "snapshot"),
        contains=mission.oracle_contains,
    )


def test_live_engine_accepts_strengthening_all_oracle_and_rejects_unrelated_any() -> None:
    mission = _mission()
    browser = ProjectionFieldOracle(
        ("browser", "snapshot"),
        mission.oracle_contains,
        "sova.oracle.browser-marker/0.1",
    )
    workspace = ProjectionPredicateOracle(
        ("workspace", "documents"),
        "count-gte",
        1,
        "sova.oracle.workspace-count/0.1",
    )
    _validate_chamber_oracle_binding(
        mission,
        CompositeProjectionOracle("all", (browser, workspace)),
    )
    with pytest.raises(FormatError, match="must exactly match"):
        _validate_chamber_oracle_binding(
            mission,
            CompositeProjectionOracle("any", (browser, workspace)),
        )


def test_live_engine_recording_control_is_admitted_for_signed_cue_pipeline() -> None:
    _validate_controls(
        _mission(),
        provider_calls_authorized=False,
        target_observation_disclosure_authorized=True,
        offensive=False,
        headless=True,
        record_video=True,
        approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        secret_resolver=lambda _name: None,
        event_observer=None,
    )


@pytest.mark.parametrize(
    ("field_path", "contains"),
    [
        (("browser", "url"), "SOVA-OWNED-FIXTURE-OBSERVED"),
        (("browser", "snapshot"), "UNRELATED-PASS-CONDITION"),
    ],
)
def test_live_engine_rejects_unrelated_chamber_oracle(
    field_path: tuple[str, ...],
    contains: str,
) -> None:
    with pytest.raises(FormatError, match="must exactly match") as raised:
        _validate_mission_oracle_binding(
            _mission(),
            field_path=field_path,
            contains=contains,
        )
    assert raised.value.issue.code == "SOVA-EXECUTOR-ENGINE-ORACLE-BINDING"
    assert "SOVA-OWNED-FIXTURE-OBSERVED" not in str(raised.value.issue.details)


def _control_options(**changes: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "provider_calls_authorized": False,
        "target_observation_disclosure_authorized": True,
        "offensive": False,
        "headless": True,
        "record_video": False,
        "approval_prompt": lambda challenge, _intents: challenge.exact_phrase,
        "secret_resolver": lambda _name: None,
        "event_observer": None,
    }
    values.update(changes)
    return values


def test_live_engine_controls_reject_wrong_types_callbacks_disclosure_and_offense() -> None:
    for changes in (
        {"provider_calls_authorized": 1},
        {"headless": "yes"},
        {"approval_prompt": None},
        {"secret_resolver": None},
        {"event_observer": "not-callable"},
        {"target_observation_disclosure_authorized": False},
        {"offensive": True},
    ):
        with pytest.raises(FormatError):
            _validate_controls(_mission(), **_control_options(**changes))


def test_live_engine_codec_and_surface_registries_are_non_replaceable() -> None:
    mission = _mission()
    builtins = live_engine._merged_codec_factories(mission, None)
    assert set(builtins) == {
        "sova.action-codec.browser/0.1.0",
        "sova.action-codec.workspace/0.1.0",
    }
    with pytest.raises(FormatError, match="malformed"):
        live_engine._merged_codec_factories(mission, cast("Any", []))
    with pytest.raises(FormatError, match="replace"):
        live_engine._merged_codec_factories(
            mission,
            cast("Any", {"sova.action-codec.browser/0.1.0": lambda _observation: None}),
        )
    for additional in (
        cast("Any", {"": lambda _observation: None}),
        cast("Any", {"fixture": None}),
    ):
        with pytest.raises(FormatError, match="malformed"):
            live_engine._merged_codec_factories(mission, additional)
    merged = live_engine._merged_codec_factories(
        mission,
        cast("Any", {"fixture/0.1": lambda _observation: None}),
    )
    assert "fixture/0.1" in merged

    live_engine._validate_additional_configuration(None, None, None)
    with pytest.raises(FormatError, match="requires an additional"):
        live_engine._validate_additional_configuration(None, {}, None)
    for values in (
        (object(), {"fixture": lambda _observation: None}, "sha256:" + "1" * 64),
        (lambda _phase: (), {}, "sha256:" + "1" * 64),
        (lambda _phase: (), {"fixture": lambda _observation: None}, "bad"),
    ):
        with pytest.raises(FormatError, match="exact codec"):
            live_engine._validate_additional_configuration(*cast("Any", values))


def test_live_engine_destination_profile_and_surface_helpers_fail_closed(
    tmp_path: Path,
) -> None:
    live_engine._destination_admissible(tmp_path / "missing")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "file").write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="empty real directory"):
        live_engine._destination_admissible(occupied)

    assert live_engine._profile_evidence(None, "sha256:" + "1" * 64) is None
    with pytest.raises(FormatError, match="exact browser profile"):
        live_engine._profile_evidence(cast("Any", object()), "sha256:" + "1" * 64)
    now = time.time_ns() // 1_000_000
    profile = tmp_path / "profile"
    profile.mkdir()
    lease_file = tmp_path / "lease.json"
    lease = BrowserProfileLease(
        "lease:fixture",
        "profile:" + "1" * 32,
        "identity:fixture",
        "sha256:" + "1" * 64,
        "owner:fixture",
        now - 100,
        now + 10_000,
        profile,
        lease_file,
    )
    evidence = live_engine._profile_evidence(lease, lease.target)
    assert evidence is not None and evidence["profilePathPresent"] is False
    expired = replace(lease, expires_unix_ms=now - 1)
    with pytest.raises(FormatError, match="admitted lifetime"):
        live_engine._profile_evidence(expired, expired.target)

    surface = workspace_surface_generation()
    digest = live_engine._surface_contract_digest((surface,))
    assert live_engine._validated_additional_surfaces((surface,), digest) == (surface,)
    with pytest.raises(FormatError, match="malformed generation"):
        live_engine._validated_additional_surfaces([], digest)
    with pytest.raises(FormatError, match="differs"):
        live_engine._validated_additional_surfaces((surface,), "sha256:" + "0" * 64)
    live_engine._close_surfaces((surface,))
    failing = replace(surface, close=lambda: (_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(FormatError, match="could not be closed"):
        live_engine._close_surfaces((failing,))


def test_live_web_admission_rejects_target_mission_origin_authority_and_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission = _mission()
    target = owned_web_target(mission.entry_origin)
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    base: dict[str, Any] = {
        "package_runner": executable,
        "browser_executable": executable,
        "approval_prompt": lambda challenge, _intents: challenge.exact_phrase,
        "secret_resolver": lambda _name: None,
        "provider_calls_authorized": False,
        "target_observation_disclosure_authorized": True,
    }
    with pytest.raises(FormatError, match="browser-agent"):
        live_engine.run_live_web_executor_engine(
            cast("Any", object()), mission, {}, tmp_path / "bad-target", **base
        )
    with pytest.raises(FormatError, match="semantic browser mission"):
        live_engine.run_live_web_executor_engine(
            target, cast("Any", object()), {}, tmp_path / "bad-mission", **base
        )
    with pytest.raises(FormatError, match="attachment provider is malformed"):
        live_engine.run_live_web_executor_engine(
            target,
            mission,
            {},
            tmp_path / "bad-attachment-provider",
            additional_capsule_attachment_provider=cast("Any", object()),
            **base,
        )

    validated = SimpleNamespace(
        oracle=object(),
        authority=SimpleNamespace(authority_target="127.0.0.1"),
    )
    monkeypatch.setattr(
        live_engine,
        "validate_executor_chamber_document",
        lambda *_args, **_kwargs: validated,
    )
    monkeypatch.setattr(live_engine, "_validate_chamber_oracle_binding", lambda *_args: None)
    proof = SimpleNamespace(digest="sha256:" + "2" * 64)
    monkeypatch.setattr(
        live_engine,
        "verified_browser_control",
        lambda *_args: (("http://127.0.0.1:9999",), "127.0.0.1", proof, "verified"),
    )
    with pytest.raises(FormatError, match="outside the authorized"):
        live_engine.run_live_web_executor_engine(
            target, mission, {}, tmp_path / "bad-origin", **base
        )

    validated.authority.authority_target = "different.example"
    monkeypatch.setattr(
        live_engine,
        "verified_browser_control",
        lambda *_args: ((mission.entry_origin,), "127.0.0.1", proof, "verified"),
    )
    with pytest.raises(FormatError, match="must equal"):
        live_engine.run_live_web_executor_engine(
            target, mission, {}, tmp_path / "bad-authority", **base
        )

    validated.authority.authority_target = "127.0.0.1"
    with pytest.raises(FormatError, match="supplied together"):
        live_engine.run_live_web_executor_engine(
            target,
            mission,
            {},
            tmp_path / "partial-process",
            additional_target_process_id=1,
            **base,
        )
    with pytest.raises(FormatError, match="additional process-generation"):
        live_engine.run_live_web_executor_engine(
            target,
            mission,
            {},
            tmp_path / "window-without-process",
            additional_target_window_handle_digest="sha256:" + "3" * 64,
            **base,
        )


def test_live_web_engine_composes_fresh_primary_and_reproduction_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission = _mission()
    target = owned_web_target(mission.entry_origin)
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    validated = SimpleNamespace(
        oracle=object(),
        authority=SimpleNamespace(authority_target="127.0.0.1"),
    )
    proof = SimpleNamespace(digest="sha256:" + "2" * 64)
    monkeypatch.setattr(
        live_engine,
        "validate_executor_chamber_document",
        lambda *_args, **_kwargs: validated,
    )
    monkeypatch.setattr(live_engine, "_validate_chamber_oracle_binding", lambda *_args: None)
    monkeypatch.setattr(
        live_engine,
        "verified_browser_control",
        lambda *_args: ((mission.entry_origin,), "127.0.0.1", proof, "verified"),
    )

    class _Browser:
        def __init__(self, **_kwargs: object) -> None:
            self.visual_replays: tuple[Path, ...] = ()
            self.replay_cues: Path | None = None
            self.events: list[tuple[str, dict[str, Any]]] = []
            self.closed = False

        def observe_recording_event(self, channel: str, event: dict[str, Any]) -> None:
            self.events.append((channel, event))

        def close(self) -> None:
            self.closed = True

    browsers: list[_Browser] = []

    def browser_factory(**kwargs: object) -> _Browser:
        browser = _Browser(**kwargs)
        browsers.append(browser)
        return browser

    monkeypatch.setattr(live_engine, "ManagedPlaywrightBrowserSurface", browser_factory)
    monkeypatch.setattr(
        live_engine,
        "browser_surface_generation",
        lambda browser: SimpleNamespace(name="browser", close=browser.close),
    )
    monkeypatch.setattr(
        live_engine,
        "workspace_surface_generation",
        lambda: SimpleNamespace(name="workspace", close=lambda: None),
    )
    monkeypatch.setattr(
        live_engine,
        "ExecutorEngineRuntime",
        SimpleNamespace,
    )

    observed: list[tuple[str, dict[str, Any]]] = []

    def run_document(
        _document: object,
        destination: Path,
        **kwargs: Any,
    ) -> ExecutorChamberArtifacts:
        runtime = kwargs["runtime"]
        assert [item.name for item in runtime.surface_factory("primary")] == [
            "browser",
            "workspace",
        ]
        assert [item.name for item in runtime.surface_factory("reproduction")] == [
            "browser",
            "workspace",
        ]
        kwargs["event_observer"]("primary", {"kind": "tool.completed"})
        return ExecutorChamberArtifacts(
            "passed",
            destination / "report.json",
            destination / "primary.sova-trace",
            destination / "reproduction.sova-trace",
            destination / "finding.sova",
            destination / "live-events.jsonl",
        )

    monkeypatch.setattr(live_engine, "run_executor_engine_document", run_document)
    artifacts = live_engine.run_live_web_executor_engine(
        target,
        mission,
        {},
        tmp_path / "engine",
        package_runner=executable,
        browser_executable=executable,
        approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        target_observation_disclosure_authorized=True,
        event_observer=lambda channel, event: observed.append((channel, event)),
    )
    assert artifacts.status == "passed"
    assert len(browsers) == 2
    assert browsers[0].events == [("primary", {"kind": "tool.completed"})]
    assert observed == [("primary", {"kind": "tool.completed"})]
    assert artifacts.visual_replays == ()
    assert artifacts.replay_cues == ()


def test_live_web_engine_packages_decisive_recordings_and_exact_additional_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mission = _mission()
    target = owned_web_target(mission.entry_origin)
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    validated = SimpleNamespace(
        oracle=object(),
        authority=SimpleNamespace(authority_target="127.0.0.1"),
    )
    proof = SimpleNamespace(digest="sha256:" + "2" * 64)
    monkeypatch.setattr(
        live_engine,
        "validate_executor_chamber_document",
        lambda *_args, **_kwargs: validated,
    )
    monkeypatch.setattr(live_engine, "_validate_chamber_oracle_binding", lambda *_args: None)
    monkeypatch.setattr(
        live_engine,
        "verified_browser_control",
        lambda *_args: ((mission.entry_origin,), "127.0.0.1", proof, "verified"),
    )

    class _RecordedBrowser:
        def __init__(self, **kwargs: object) -> None:
            phase = str(kwargs["recording_label"])
            media = tmp_path / f"{phase}.webm"
            cues = tmp_path / f"{phase}-cues.json"
            media.write_bytes(f"{phase}-video".encode())
            cues.write_bytes(f"{phase}-cues".encode())
            self.visual_replays = (media,)
            self.replay_cues = cues

        def observe_recording_event(self, _channel: str, _event: dict[str, Any]) -> None:
            return None

        def close(self) -> None:
            return None

    monkeypatch.setattr(live_engine, "ManagedPlaywrightBrowserSurface", _RecordedBrowser)
    monkeypatch.setattr(
        live_engine,
        "browser_surface_generation",
        lambda browser: SimpleNamespace(name="browser", close=browser.close),
    )
    monkeypatch.setattr(live_engine, "ExecutorEngineRuntime", SimpleNamespace)
    extra = workspace_surface_generation()
    extra_digest = live_engine._surface_contract_digest((extra,))
    captured_attachments: dict[str, bytes] = {}

    def run_document(
        _document: object,
        destination: Path,
        **kwargs: Any,
    ) -> ExecutorChamberArtifacts:
        runtime = kwargs["runtime"]
        assert len(runtime.surface_factory("primary")) == 3
        assert len(runtime.surface_factory("reproduction")) == 3
        captured_attachments.update(kwargs["capsule_attachment_provider"]())
        return ExecutorChamberArtifacts(
            "passed",
            destination / "report.json",
            destination / "primary.sova-trace",
            destination / "reproduction.sova-trace",
            destination / "finding.sova",
            destination / "live-events.jsonl",
        )

    monkeypatch.setattr(live_engine, "run_executor_engine_document", run_document)
    artifacts = live_engine.run_live_web_executor_engine(
        target,
        mission,
        {},
        tmp_path / "recorded-engine",
        package_runner=executable,
        browser_executable=executable,
        approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        secret_resolver=lambda _name: None,
        provider_calls_authorized=False,
        target_observation_disclosure_authorized=True,
        record_video=True,
        additional_surface_factory=lambda _phase: (extra,),
        additional_codec_factories=cast("Any", {"fixture/0.1": lambda _observation: None}),
        additional_surface_contract_digest=extra_digest,
        additional_capsule_attachment_provider=lambda: {
            "computer-visual-replay-01.sovaframes": b"computer-media",
            "computer-replay-cues.json": b"computer-cues",
        },
    )
    assert set(captured_attachments) == {
        "visual-replay-01.webm",
        "reproduction-visual-replay-01.webm",
        "replay-cues.json",
        "reproduction-replay-cues.json",
        "computer-visual-replay-01.sovaframes",
        "computer-replay-cues.json",
    }
    assert len(artifacts.visual_replays) == 2
    assert len(artifacts.replay_cues) == 2

    with pytest.raises(FormatError, match="attempted to replace browser recording"):
        live_engine.run_live_web_executor_engine(
            target,
            mission,
            {},
            tmp_path / "recorded-engine-collision",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            target_observation_disclosure_authorized=True,
            record_video=True,
            additional_surface_factory=lambda _phase: (extra,),
            additional_codec_factories=cast("Any", {"fixture/0.1": lambda _observation: None}),
            additional_surface_contract_digest=extra_digest,
            additional_capsule_attachment_provider=lambda: {"replay-cues.json": b"replacement"},
        )
