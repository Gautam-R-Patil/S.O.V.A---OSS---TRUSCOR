# SPDX-License-Identifier: Apache-2.0
"""Hostile trust-boundary tests for the managed Playwright browser surface."""

from __future__ import annotations

import shutil
from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar, cast

import pytest

import sova.runtime.browser_surface as browser_surface_module
from sova.executors import (
    ActionOutcome,
    ActionRequest,
    CancellationToken,
    Capability,
    ExecutionContext,
    Executor,
    OutcomeStatus,
    SideEffect,
)
from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.live.semantic_workflow import SemanticBrowserMission
from sova.runtime.browser_surface import ManagedPlaywrightBrowserSurface
from sova.runtime.sessions import BrowserProfileVault

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

    from sova.mcp import MCPClient, StdioServerSpec


def _digest(value: str) -> str:
    return sha256_digest(value.encode())


def _mission(
    *,
    allowed_actions: tuple[str, ...] = (
        "browser.navigate",
        "browser.click",
        "browser.type",
    ),
) -> SemanticBrowserMission:
    return SemanticBrowserMission(
        identifier="sova:surface:test",
        title="Owned browser fixture",
        entry_url="http://127.0.0.1:9187/start",
        objective="Exercise the explicitly authorized owned browser fixture.",
        allowed_actions=allowed_actions,
        seed_inputs=(),
        setup_actions=(),
        reset_actions=(),
        oracle_contains="SOVA_SURFACE_TRIGGERED",
        max_planner_turns=4,
        max_actions=8,
        max_actions_per_plan=2,
        max_duration_seconds=60,
        max_pages=4,
        max_mutations=8,
        max_consecutive_failures=2,
        max_generated_text_characters=512,
        max_total_tokens=100,
        offensive=False,
        provider_observation_disclosure="redacted-accessibility-snapshot",
    )


def _snapshot(text: str) -> ActionOutcome:
    return ActionOutcome(
        "trusted-observation:browser-snapshot",
        OutcomeStatus.SUCCEEDED,
        SideEffect.READ,
        {"text": [text]},
        verification="direct-read-observation",
    )


class _FakeLazyStdioExecutor:
    created: ClassVar[list[_FakeLazyStdioExecutor]] = []

    def __init__(
        self,
        *,
        name: str,
        capabilities: tuple[Capability, ...],
        spec_factory: Callable[[Path], StdioServerSpec],
        adapter_factory: Callable[[MCPClient], Executor],
    ) -> None:
        self.name = name
        self.inventory = capabilities
        self.spec_factory = spec_factory
        self.adapter_factory = adapter_factory
        self.execute_calls: list[tuple[ActionRequest, ExecutionContext]] = []
        self.snapshot_calls: list[tuple[Path, str, dict[str, Any], float]] = []
        self.snapshot_outcomes: list[ActionOutcome] = []
        self.execute_status = OutcomeStatus.SUCCEEDED
        self.execute_error_code: str | None = None
        self.observe_error: Exception | None = None
        self.close_error: Exception | None = None
        self.close_calls = 0
        self.closed_state = False
        self.cleanup_state = False
        type(self).created.append(self)

    @property
    def cleanup_complete(self) -> bool:
        return self.cleanup_state

    def capabilities(self) -> tuple[Capability, ...]:
        return self.inventory

    def execute(
        self,
        request: ActionRequest,
        context: ExecutionContext,
        cancellation: CancellationToken,
    ) -> ActionOutcome:
        del cancellation
        self.execute_calls.append((request, context))
        capability = next(item for item in self.inventory if item.name == request.action)
        return ActionOutcome(
            request.id,
            self.execute_status,
            capability.side_effect,
            {},
            error_code=self.execute_error_code,
        )

    def trusted_observe(
        self,
        *,
        workspace: Path,
        action: str,
        inputs: Mapping[str, Any],
        timeout_seconds: float,
    ) -> ActionOutcome:
        self.snapshot_calls.append((workspace, action, dict(inputs), timeout_seconds))
        if self.observe_error is not None:
            raise self.observe_error
        if self.snapshot_outcomes:
            return self.snapshot_outcomes.pop(0)
        return _snapshot(
            "- Page URL: http://127.0.0.1:9187/start\n"
            '- Page Title: Fixture\n- button "Continue" [ref=next_2]'
        )

    def close(self) -> None:
        self.close_calls += 1
        self.closed_state = True
        if self.close_error is not None:
            raise self.close_error
        self.cleanup_state = True


@pytest.fixture(autouse=True)
def _fake_lazy_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeLazyStdioExecutor.created.clear()
    monkeypatch.setattr(
        browser_surface_module,
        "LazyStdioExecutor",
        _FakeLazyStdioExecutor,
    )


def _runtime_files(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    runner = tmp_path / "package-runner.exe"
    browser = tmp_path / "browser.exe"
    runner.write_bytes(b"fixture runner")
    browser.write_bytes(b"fixture browser")
    package_cache = tmp_path / "package-cache"
    browser_cache = tmp_path / "browser-cache"
    workspace = tmp_path / "workspace"
    package_cache.mkdir()
    browser_cache.mkdir()
    workspace.mkdir()
    return runner, browser, package_cache, browser_cache, workspace


def _surface(
    tmp_path: Path,
    *,
    mission: SemanticBrowserMission | None = None,
    target_digest: str | None = None,
    headless: bool = True,
    record_video: bool = False,
) -> tuple[ManagedPlaywrightBrowserSurface, Path, Path, Path, Path, Path]:
    runner, browser, package_cache, browser_cache, workspace = _runtime_files(tmp_path)
    surface = ManagedPlaywrightBrowserSurface(
        mission=_mission() if mission is None else mission,
        target_digest=_digest("target") if target_digest is None else target_digest,
        package_runner=runner,
        browser_executable=browser,
        package_cache=package_cache,
        browser_cache=browser_cache,
        headless=headless,
        record_video=record_video,
    )
    return surface, runner, browser, package_cache, browser_cache, workspace


def _fake() -> _FakeLazyStdioExecutor:
    assert _FakeLazyStdioExecutor.created
    return _FakeLazyStdioExecutor.created[-1]


def _bind(surface: ManagedPlaywrightBrowserSurface, workspace: Path) -> str:
    session = _digest("session")
    surface.bind(workspace=workspace, session_digest=session)
    return session


def test_exposes_only_mission_actions_and_snapshot_while_coordinator_can_initialize(
    tmp_path: Path,
) -> None:
    mission = _mission(allowed_actions=("browser.click",))
    surface, *_paths, workspace = _surface(tmp_path, mission=mission)
    fake = _fake()
    exposed = {item.name for item in surface.capabilities()}
    backend = {item.name for item in fake.capabilities()}

    assert exposed == {"browser.click", "browser.snapshot"}
    assert backend == {"browser.click", "browser.navigate", "browser.snapshot"}
    assert surface.executor.capabilities() == surface.capabilities()
    assert surface.executor is not fake

    session = _bind(surface, workspace)
    observation = surface.observe()
    assert observation["url"] == mission.entry_url
    assert len(fake.execute_calls) == 1
    request, context = fake.execute_calls[0]
    assert request.action == "browser.navigate"
    assert request.inputs == {"url": mission.entry_url}
    assert context.authorization == {
        "decision": "allowed",
        "scopeDigest": mission.digest,
        "decidedBy": "sova.browser-surface-initializer/0.1",
        "coordinatorInitialization": True,
        "executionGrant": {},
    }
    assert context.environment == {"sessionDigest": session}

    with pytest.raises(FormatError, match="outside the mission-exposed"):
        surface.executor.execute(
            ActionRequest("planner:navigate", "browser.navigate", {"url": mission.entry_url}, 5),
            ExecutionContext(
                workspace,
                {"decision": "allowed", "executionGrant": {}},
                environment={"sessionDigest": session},
            ),
            CancellationToken(),
        )
    assert surface.closed
    assert len(fake.execute_calls) == 1


def test_observe_navigates_once_and_returns_fresh_bounded_detached_projection(
    tmp_path: Path,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path)
    fake = _fake()
    _bind(surface, workspace)
    fake.snapshot_outcomes = [
        _snapshot(
            "- Page URL: http://127.0.0.1:9187/start\n"
            '- button "First" [ref=b2]\n- link "Earlier" [ref=a1]\n'
            '- button "Duplicate" [ref=b2]'
        ),
        _snapshot(
            '- Page URL: http://127.0.0.1:9187/second?mode=owned\n- heading "Second" [ref=h1]'
        ),
    ]

    first = surface.observe()
    second = surface.observe()

    assert first["missionDigest"] == surface.mission_digest
    assert first["locatorRefs"] == ["a1", "b2"]
    assert first["snapshotTruncated"] is False
    assert second["url"] == "http://127.0.0.1:9187/second?mode=owned"
    assert second["locatorRefs"] == ["h1"]
    assert len(fake.execute_calls) == 1
    assert len(fake.snapshot_calls) == 2
    first["locatorRefs"].append("caller-mutation")
    assert second["locatorRefs"] == ["h1"]


def test_authorized_execution_preserves_context_and_denial_never_reaches_backend(
    tmp_path: Path,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path)
    fake = _fake()
    session = _bind(surface, workspace)
    surface.observe()
    request = ActionRequest(
        "planner:click",
        "browser.click",
        {"element": "Continue", "ref": "next_2"},
        5,
    )
    context = ExecutionContext(
        workspace,
        {"decision": "allowed", "executionGrant": {"grantId": "grant:click"}},
        environment={"sessionDigest": session},
    )

    outcome = surface.executor.execute(request, context, CancellationToken())
    assert outcome.status == OutcomeStatus.SUCCEEDED
    assert fake.execute_calls[-1] == (request, context)
    calls = len(fake.execute_calls)

    with pytest.raises(FormatError, match="allowed grant"):
        surface.executor.execute(
            replace(request, id="planner:denied"),
            ExecutionContext(
                workspace,
                {"decision": "denied", "executionGrant": {"grantId": "grant:click"}},
                environment={"sessionDigest": session},
            ),
            CancellationToken(),
        )
    assert len(fake.execute_calls) == calls
    assert surface.closed
    assert fake.cleanup_complete


def test_binding_and_dispatch_reject_session_or_workspace_substitution(
    tmp_path: Path,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path)
    fake = _fake()
    session = _bind(surface, workspace)
    surface.observe()
    other = tmp_path / "other-workspace"
    other.mkdir()

    with pytest.raises(FormatError, match="workspace, session"):
        surface.executor.execute(
            ActionRequest(
                "planner:click",
                "browser.click",
                {"element": "Continue", "ref": "next_2"},
                5,
            ),
            ExecutionContext(
                other,
                {"decision": "allowed", "executionGrant": {}},
                environment={"sessionDigest": session},
            ),
            CancellationToken(),
        )
    assert surface.closed
    assert len(fake.execute_calls) == 1

    second, *_paths, second_workspace = _surface(tmp_path / "second")
    _bind(second, second_workspace)
    substitute = tmp_path / "second" / "substitute"
    substitute.mkdir()
    with pytest.raises(FormatError, match="cannot move"):
        second.bind(workspace=substitute, session_digest=_digest("other-session"))
    assert second.closed


@pytest.mark.parametrize(
    ("snapshot_text", "code"),
    [
        (
            '- Page URL: http://127.0.0.1:9999/drift\n- heading "Wrong origin"',
            "SOVA-BROWSER-SURFACE-ORIGIN-DRIFT",
        ),
        ('- Page Title: Missing URL\n- heading "Missing"', "SOVA-BROWSER-SURFACE-URL"),
        (
            "- Page URL: http://127.0.0.1:9187/start\n- Page URL: http://127.0.0.1:9187/other",
            "SOVA-BROWSER-SURFACE-URL",
        ),
        (
            "- Page URL: http://127.0.0.1:9187/start\n- textbox value=sk-abcdefghijklmnop",
            "SOVA-BROWSER-SURFACE-SENSITIVE",
        ),
    ],
)
def test_untrusted_snapshot_origin_url_and_secret_fail_closed(
    tmp_path: Path,
    snapshot_text: str,
    code: str,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path)
    fake = _fake()
    _bind(surface, workspace)
    fake.snapshot_outcomes = [_snapshot(snapshot_text)]

    with pytest.raises(FormatError) as caught:
        surface.observe()
    assert caught.value.issue.code == code
    assert surface.closed
    assert fake.cleanup_complete


def test_snapshot_is_bounded_and_capability_drift_fails_before_dispatch(tmp_path: Path) -> None:
    surface, *_paths, workspace = _surface(tmp_path)
    fake = _fake()
    _bind(surface, workspace)
    fake.snapshot_outcomes = [
        _snapshot(
            '- Page URL: http://127.0.0.1:9187/start\n- heading "Large" [ref=h1]\n' + "x" * 70_000
        )
    ]
    projection = surface.observe()
    assert projection["snapshotTruncated"] is True
    assert len(projection["snapshot"].encode()) <= 64 * 1024

    drifting, *_paths, drifting_workspace = _surface(tmp_path / "drifting")
    drifting_fake = _fake()
    _bind(drifting, drifting_workspace)
    drifting_fake.inventory = tuple(reversed(drifting_fake.inventory))
    with pytest.raises(FormatError, match="changed after admission"):
        drifting.observe()
    assert not drifting_fake.execute_calls
    assert drifting.closed


def test_launch_spec_binds_exact_paths_origin_profile_display_and_video(tmp_path: Path) -> None:
    runner, browser, package_cache, browser_cache, workspace = _runtime_files(tmp_path)
    target_digest = _digest("manifest")
    vault = BrowserProfileVault(tmp_path / "opaque-vault")
    handle = "profile:" + "a" * 32
    vault.provision(handle, identity_id="fixture-identity", target=target_digest)
    lease = vault.acquire(handle, owner_id="surface-test")
    try:
        surface = ManagedPlaywrightBrowserSurface(
            mission=_mission(),
            target_digest=target_digest,
            package_runner=runner,
            browser_executable=browser,
            package_cache=package_cache,
            browser_cache=browser_cache,
            profile_lease=lease,
            headless=True,
            record_video=True,
            recording_destination=tmp_path / "recordings",
            recording_label="primary",
        )
        fake = _fake()
        spec = fake.spec_factory(workspace)
        argv = spec.argv

        assert surface.allowed_origin == "http://127.0.0.1:9187"
        assert surface.target_digest == target_digest
        assert "--headless" in argv
        assert (
            argv[argv.index("--viewport-size")],
            argv[argv.index("--viewport-size") + 1],
        ) == ("--viewport-size", "1280x720")
        assert argv[argv.index("--allowed-origins") + 1] == surface.allowed_origin
        assert argv[argv.index("--user-data-dir") + 1] == str(lease.path_for_executor())
        assert argv[argv.index("--executable-path") + 1] == str(browser.resolve())
        assert spec.environment["PLAYWRIGHT_BROWSERS_PATH"] == str(browser_cache.resolve())
        assert str(package_cache.resolve()) in argv
        assert "--isolated" not in argv
        public_names = {name for name in dir(surface) if not name.startswith("_")}
        assert "profile_lease" not in public_names
        assert handle not in repr(surface)
        assert str(lease.path_for_executor()) not in repr(surface.executor)
        surface.close()
    finally:
        lease.release()


def test_profile_target_digest_and_runtime_path_links_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, browser, package_cache, browser_cache, _workspace = _runtime_files(tmp_path)
    vault = BrowserProfileVault(tmp_path / "vault")
    handle = "profile:" + "b" * 32
    vault.provision(handle, identity_id="fixture-identity", target=_digest("other-target"))
    lease = vault.acquire(handle, owner_id="surface-test")
    try:
        with pytest.raises(FormatError, match="different target"):
            ManagedPlaywrightBrowserSurface(
                mission=_mission(),
                target_digest=_digest("expected-target"),
                package_runner=runner,
                browser_executable=browser,
                package_cache=package_cache,
                browser_cache=browser_cache,
                profile_lease=lease,
            )
    finally:
        lease.release()

    original_is_link = browser_surface_module._is_link

    def runner_is_link(path: Path) -> bool:
        return path == runner.absolute() or original_is_link(path)

    monkeypatch.setattr(browser_surface_module, "_is_link", runner_is_link)
    with pytest.raises(FormatError, match="symbolic link or junction"):
        ManagedPlaywrightBrowserSurface(
            mission=_mission(),
            target_digest=_digest("target"),
            package_runner=runner,
            browser_executable=browser,
            package_cache=package_cache,
            browser_cache=browser_cache,
        )
    assert not _FakeLazyStdioExecutor.created


@pytest.mark.parametrize("target_digest", ["", "sha256:abcd", "SHA256:" + "a" * 64])
def test_invalid_target_digest_and_overlapping_caches_are_rejected(
    tmp_path: Path,
    target_digest: str,
) -> None:
    runner, browser, package_cache, browser_cache, _workspace = _runtime_files(tmp_path)
    with pytest.raises(FormatError, match="canonical target digest"):
        ManagedPlaywrightBrowserSurface(
            mission=_mission(),
            target_digest=target_digest,
            package_runner=runner,
            browser_executable=browser,
            package_cache=package_cache,
            browser_cache=browser_cache,
        )

    with pytest.raises(FormatError, match="must be distinct"):
        ManagedPlaywrightBrowserSurface(
            mission=_mission(),
            target_digest=_digest("target"),
            package_runner=runner,
            browser_executable=browser,
            package_cache=package_cache,
            browser_cache=package_cache,
        )


def test_backend_errors_and_cleanup_failure_are_normalized_and_fail_closed(
    tmp_path: Path,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path)
    fake = _fake()
    _bind(surface, workspace)
    fake.observe_error = RuntimeError("backend-secret-detail")
    with pytest.raises(FormatError) as caught:
        surface.observe()
    assert caught.value.issue.code == "SOVA-BROWSER-SURFACE-OBSERVATION"
    assert "backend-secret-detail" not in str(caught.value)
    assert surface.closed

    failing, *_paths, _failing_workspace = _surface(tmp_path / "cleanup")
    failing_fake = _fake()
    failing_fake.close_error = RuntimeError("private-process-detail")
    with pytest.raises(FormatError) as cleanup:
        failing.close()
    assert cleanup.value.issue.code == "SOVA-BROWSER-SURFACE-CLEANUP"
    assert "private-process-detail" not in str(cleanup.value)
    assert failing.closed
    assert not failing.cleanup_complete


def test_path_and_origin_helpers_reject_wrong_missing_and_unsafe_values(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="must be a filesystem path"):
        browser_surface_module._absolute(cast("Any", "not-a-path"), "fixture")
    with pytest.raises(FormatError, match="existing file"):
        browser_surface_module._existing_file(tmp_path / "missing", "fixture")
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(FormatError, match="existing file"):
        browser_surface_module._existing_file(directory, "fixture")
    file = tmp_path / "file"
    file.write_text("x", encoding="utf-8")
    with pytest.raises(FormatError, match="existing directory"):
        browser_surface_module._existing_directory(tmp_path / "missing-dir", "fixture")
    with pytest.raises(FormatError, match="existing directory"):
        browser_surface_module._existing_directory(file, "fixture")
    with pytest.raises(FormatError, match="existing directory ancestor"):
        browser_surface_module._cache_directory(file, "fixture cache")
    assert browser_surface_module._cache_directory(None, "fixture") is None

    for value in (
        "",
        "x" * 9000,
        "ftp://example.com/path",
        "https://user:password@example.com/path",
        "https://example.com/path#fragment",
        "https://example.com:bad/path",
    ):
        with pytest.raises(FormatError, match="URL is missing or malformed"):
            browser_surface_module._exact_origin(value)
    assert browser_surface_module._exact_origin("http://Example.com/path") == "http://example.com"
    assert (
        browser_surface_module._exact_origin("https://Example.com:8443/path")
        == "https://example.com:8443"
    )


def test_snapshot_projection_rejects_status_text_raw_url_and_projection_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    origin = "http://127.0.0.1:9187"
    mission = _digest("mission")
    failed = ActionOutcome(
        "snapshot", OutcomeStatus.FAILED, SideEffect.READ, {}, error_code="failure"
    )
    with pytest.raises(FormatError, match="did not succeed"):
        browser_surface_module._snapshot_projection(failed, origin=origin, mission_digest=mission)
    origin_drift = replace(failed, error_code="SOVA-MCP-BROWSER-ORIGIN-DRIFT")
    with pytest.raises(FormatError) as caught:
        browser_surface_module._snapshot_projection(
            origin_drift, origin=origin, mission_digest=mission
        )
    assert caught.value.issue.code == "SOVA-BROWSER-SURFACE-ORIGIN-DRIFT"

    invalid_outputs: tuple[dict[str, object], ...] = ({}, {"text": []}, {"text": [1]})
    for output in invalid_outputs:
        with pytest.raises(FormatError, match="bounded text"):
            browser_surface_module._snapshot_projection(
                ActionOutcome("snapshot", OutcomeStatus.SUCCEEDED, SideEffect.READ, output),
                origin=origin,
                mission_digest=mission,
            )
    with pytest.raises(FormatError, match="malformed or exceeds"):
        browser_surface_module._snapshot_projection(
            _snapshot("- Page URL: http://127.0.0.1:9187/start\n\x00"),
            origin=origin,
            mission_digest=mission,
        )
    monkeypatch.setattr(browser_surface_module, "_MAX_RAW_SNAPSHOT_BYTES", 20)
    with pytest.raises(FormatError, match="malformed or exceeds"):
        browser_surface_module._snapshot_projection(
            _snapshot("- Page URL: http://127.0.0.1:9187/start\nlong"),
            origin=origin,
            mission_digest=mission,
        )
    monkeypatch.setattr(browser_surface_module, "_MAX_RAW_SNAPSHOT_BYTES", 256 * 1024)
    monkeypatch.setattr(browser_surface_module, "_MAX_PROJECTION_BYTES", 10)
    with pytest.raises(FormatError, match="projection exceeds"):
        browser_surface_module._snapshot_projection(
            _snapshot("- Page URL: http://127.0.0.1:9187/start\n- heading fixture"),
            origin=origin,
            mission_digest=mission,
        )


def test_surface_constructor_rejects_mission_control_profile_recording_and_capability_gaps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, browser, package_cache, browser_cache, _workspace = _runtime_files(tmp_path)
    base: dict[str, Any] = {
        "mission": _mission(),
        "target_digest": _digest("target"),
        "package_runner": runner,
        "browser_executable": browser,
        "package_cache": package_cache,
        "browser_cache": browser_cache,
    }
    with pytest.raises(FormatError, match="exact SemanticBrowserMission"):
        ManagedPlaywrightBrowserSurface(**{**base, "mission": cast("Any", object())})
    with pytest.raises(FormatError, match="controls must be booleans"):
        ManagedPlaywrightBrowserSurface(**base, headless=cast("Any", 1))
    with pytest.raises(FormatError, match="exact opaque lease"):
        ManagedPlaywrightBrowserSurface(**base, profile_lease=cast("Any", object()))
    with pytest.raises(FormatError, match="trusted destination and label"):
        ManagedPlaywrightBrowserSurface(**base, record_video=True, recording_label="bad label")

    monkeypatch.setattr(browser_surface_module, "playwright_mappings", lambda **_kwargs: ())
    with pytest.raises(FormatError, match="not implemented"):
        ManagedPlaywrightBrowserSurface(**base)


def test_surface_binding_unbound_initialization_and_missing_workspace_fail_closed(
    tmp_path: Path,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path / "invalid-session")
    with pytest.raises(FormatError, match="canonical session digest"):
        surface.bind(workspace=workspace, session_digest="invalid")
    surface.close()
    with pytest.raises(FormatError, match="already closed"):
        surface.bind(workspace=workspace, session_digest=_digest("session"))

    unbound, *_paths, _unbound_workspace = _surface(tmp_path / "unbound")
    with pytest.raises(FormatError, match="must be bound"):
        unbound.observe()
    assert unbound.closed

    uninitialized, *_paths, uninitialized_workspace = _surface(tmp_path / "uninitialized")
    session = _bind(uninitialized, uninitialized_workspace)
    request = ActionRequest("planner:click", "browser.click", {"ref": "a1"}, 5)
    context = ExecutionContext(
        uninitialized_workspace,
        {"decision": "allowed", "executionGrant": {}},
        environment={"sessionDigest": session},
    )
    with pytest.raises(FormatError, match="trusted initial observation"):
        uninitialized.executor.execute(request, context, CancellationToken())
    assert uninitialized.closed

    missing, *_paths, missing_workspace = _surface(tmp_path / "missing")
    missing_session = _bind(missing, missing_workspace)
    missing.observe()
    missing_context = ExecutionContext(
        missing_workspace,
        {"decision": "allowed", "executionGrant": {}},
        environment={"sessionDigest": missing_session},
    )
    shutil.rmtree(missing_workspace)
    with pytest.raises(FormatError, match="must resolve to an existing directory"):
        missing.executor.execute(request, missing_context, CancellationToken())
    assert missing.closed


def test_surface_initialization_failure_origin_code_and_repeated_close(
    tmp_path: Path,
) -> None:
    surface, *_paths, workspace = _surface(tmp_path / "failure")
    fake = _fake()
    _bind(surface, workspace)
    fake.execute_status = OutcomeStatus.FAILED
    with pytest.raises(FormatError) as failed:
        surface.observe()
    assert failed.value.issue.code == "SOVA-BROWSER-SURFACE-INITIALIZATION"

    drift, *_paths, drift_workspace = _surface(tmp_path / "drift")
    drift_fake = _fake()
    _bind(drift, drift_workspace)
    drift_fake.execute_status = OutcomeStatus.FAILED
    drift_fake.execute_error_code = "SOVA-MCP-BROWSER-ORIGIN-DRIFT"
    with pytest.raises(FormatError) as caught:
        drift.observe()
    assert caught.value.issue.code == "SOVA-BROWSER-SURFACE-ORIGIN-DRIFT"

    repeated, *_paths, _repeated_workspace = _surface(tmp_path / "repeated")
    repeated_fake = _fake()
    repeated.close()
    repeated_fake.cleanup_state = False
    repeated.close()
    assert repeated_fake.close_calls == 2
