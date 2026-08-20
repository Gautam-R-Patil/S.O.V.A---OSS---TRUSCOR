# SPDX-License-Identifier: Apache-2.0
"""Self-hosted community and durable monitoring service contracts."""

from __future__ import annotations

import base64
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sova.cli import main
from sova.community import (
    STANDARD_ARENA_PROFILE,
    ArenaCase,
    ArenaMatch,
    LeaderboardSubmission,
    run_local_arena,
)
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.models import ScriptedModel, ScriptedTurn
from sova.monitoring import ContinuousMonitorService, monitoring_jobs_from_document
from sova.registry import (
    CommunityHTTPService,
    CommunityRegistryStore,
    CommunityServiceConfig,
    CommunityServiceLimits,
    check_community_service_health,
    verify_community_service_index,
)
from sova.trace import TraceReader


def _arena(tmp_path: Path) -> tuple[Path, Path, str, int, int]:
    case = ArenaCase("conditional-marker", "produce safe fixture", "evaluate", "OBSERVED")
    models = {
        "attacker": ScriptedModel([ScriptedTurn("produce safe fixture", "fixture")]),
        "defender": ScriptedModel([ScriptedTurn("evaluate\nATTACK:\nfixture", "OBSERVED")]),
    }
    report = run_local_arena(
        STANDARD_ARENA_PROFILE,
        (ArenaMatch("attacker", "defender", case),),
        models,
        tmp_path / "arena",
    )
    attempt = report["attempts"][0]
    return (
        Path(attempt["artifact"]),
        Path(attempt["trace"]),
        report["signingKeyId"],
        report["score"],
        report["possibleScore"],
    )


def _upload(  # noqa: PLR0913 - evidence identity fields are independently relevant
    artifact: Path,
    trace: Path,
    key_id: str,
    score: int,
    possible: int,
    *,
    kind: str = "leaderboard",
) -> dict[str, Any]:
    files = []
    for source in (artifact, trace):
        data = source.read_bytes()
        files.append(
            {
                "name": source.name,
                "digest": sha256_digest(data),
                "size": len(data),
                "data": base64.b64encode(data).decode(),
            }
        )
    metadata: dict[str, Any] = {"requiredKeyId": key_id}
    if kind == "leaderboard":
        metadata.update(
            {
                "category": "model",
                "component": "fixture-defender",
                "version": "1.0.0",
                "profileId": STANDARD_ARENA_PROFILE.identifier,
                "profileDigest": STANDARD_ARENA_PROFILE.digest,
                "score": score,
                "possibleScore": possible,
            }
        )
    return {
        "artifactType": "sova.community-submission",
        "schemaVersion": "0.1.0",
        "kind": kind,
        "metadata": metadata,
        "files": files,
    }


def _service_config(root: Path, key_id: str, *, port: int = 0) -> CommunityServiceConfig:
    return CommunityServiceConfig(
        root,
        "synthetic-local-service-token",
        frozenset({key_id}),
        "sova-arena-methodology/0.1",
        port=port,
    )


def test_registry_store_stages_verifies_promotes_and_recovers(tmp_path: Path) -> None:
    artifact, trace, key_id, score, possible = _arena(tmp_path)
    config = _service_config(tmp_path / "service", key_id)
    store = CommunityRegistryStore(config)
    queued = store.submit(_upload(artifact, trace, key_id, score, possible))
    assert queued["status"] == "queued"
    assert store.submit(_upload(artifact, trace, key_id, score, possible))["id"] == queued["id"]
    accepted = store.process_next()
    assert accepted is not None and accepted["status"] == "accepted"
    assert store.process_next() is None
    index = store.signed_index()
    assert index["index"]["entries"][0]["verification"]["contentExecuted"] is False
    verified_index = verify_community_service_index(
        index, trusted_service_key_ids=frozenset({store.key_id})
    )
    assert verified_index["identityTrusted"] is True
    with pytest.raises(FormatError, match="older than trusted state"):
        verify_community_service_index(
            index,
            trusted_service_key_ids=frozenset({store.key_id}),
            minimum_sequence=verified_index["sequence"] + 1,
        )
    with pytest.raises(FormatError, match="not explicitly trusted"):
        verify_community_service_index(
            index,
            trusted_service_key_ids=frozenset({"sha256:" + "f" * 64}),
        )
    assert store.leaderboard()["entries"][0]["rank"] == 1
    assert store.events_after(0)[-1]["status"] == "accepted"
    digest = index["index"]["entries"][0]["files"][0]["digest"]
    assert store.object_path(digest[7:]).is_file()
    orphan = config.root / "objects" / "sha256" / ("e" * 64)
    orphan.write_bytes(b"not-published")
    with pytest.raises(FormatError, match="does not exist"):
        store.object_path("e" * 64)

    duplicate = _upload(artifact, trace, key_id, score, possible)
    duplicate["metadata"]["component"] = "renamed-fixture"
    duplicate_queued = store.submit(duplicate)
    duplicate_result = store.process_next()
    assert duplicate_result is not None and duplicate_result["status"] == "rejected"
    assert store.status(duplicate_queued["id"])["error"]["code"] == "SOVA-SERVICE-DUPLICATE"

    state_path = config.root / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["submissions"][queued["id"]]["status"] = "verifying"
    state_path.write_bytes(canonical_json_bytes(state) + b"\n")
    recovered = CommunityRegistryStore(config)
    assert recovered.status(queued["id"])["status"] == "queued"
    assert recovered.status(queued["id"])["recoveredAfterRestart"] is True


def test_registry_store_rejects_untrusted_tampered_and_hostile_uploads(tmp_path: Path) -> None:
    artifact, trace, key_id, score, possible = _arena(tmp_path)
    store = CommunityRegistryStore(_service_config(tmp_path / "service", "sha256:" + "f" * 64))
    queued = store.submit(_upload(artifact, trace, key_id, score, possible))
    assert store.process_next()["status"] == "rejected"  # type: ignore[index]
    assert store.status(queued["id"])["error"]["code"] == "SOVA-SERVICE-TRUST"

    document = _upload(artifact, trace, key_id, score, possible)
    document["files"][0]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(FormatError, match="digest or size"):
        store.submit(document)

    hostile = _upload(artifact, trace, key_id, score, possible)
    hostile["files"][0]["name"] = "../escape.sova"
    with pytest.raises(FormatError, match="unsafe"):
        store.submit(hostile)
    metadata_secret = _upload(artifact, trace, key_id, score, possible)
    metadata_secret["metadata"]["apiKey"] = "synthetic-" + "credential-value"
    with pytest.raises(FormatError, match="credential-shaped metadata"):
        store.submit(metadata_secret)


def _request(
    url: str, *, token: str | None = None, document: dict[str, Any] | None = None
) -> tuple[int, bytes, str]:
    headers = {}
    data = None
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    if document is not None:
        data = canonical_json_bytes(document)
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(  # noqa: S310 - caller supplies a loopback test URL
        url, data=data, headers=headers, method="POST" if data else "GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - loopback fixture
            return response.status, response.read(), response.headers.get_content_type()
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers.get_content_type()


def test_loopback_http_service_upload_queue_sse_and_restart(tmp_path: Path) -> None:
    artifact, trace, key_id, score, possible = _arena(tmp_path)
    config = _service_config(tmp_path / "service", key_id)
    service = CommunityHTTPService(config)
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    host, port = service.address
    base = f"http://{host}:{port}"
    try:
        status, _, _ = _request(base + "/v1/health")
        assert status == 200
        health = check_community_service_health(base + "/v1/health")
        assert health["status"] == "ready"
        assert health["loopbackVerified"] is True
        status, _, _ = _request(
            base + "/v1/submissions",
            token="wrong-" + "synthetic-service-token",
            document=_upload(artifact, trace, key_id, score, possible),
        )
        assert status == 401
        status, body, _ = _request(
            base + "/v1/submissions",
            token=config.token,
            document=_upload(artifact, trace, key_id, score, possible),
        )
        assert status == 202
        submission_id = json.loads(body)["id"]
        deadline = time.monotonic() + 10
        result: dict[str, Any] = {}
        while time.monotonic() < deadline:
            status, body, _ = _request(base + f"/v1/submissions/{submission_id}")
            result = json.loads(body)
            if result["status"] in {"accepted", "rejected"}:
                break
            time.sleep(0.02)
        assert result["status"] == "accepted"
        live_index = json.loads(_request(base + "/v1/index")[1])
        assert live_index["index"]["entries"]
        object_digest = live_index["index"]["entries"][0]["files"][0]["digest"][7:]
        assert _request(base + "/v1/objects/sha256/" + object_digest)[0] == 200
        assert json.loads(_request(base + "/v1/leaderboard")[1])["entries"][0]["rank"] == 1
        _, events, media = _request(base + "/v1/events?after=0")
        assert media == "text/event-stream"
        assert b"submission.accepted" in events
    finally:
        service.close()
        thread.join(timeout=10)
    assert not thread.is_alive()
    assert CommunityRegistryStore(config).status(submission_id)["status"] == "accepted"


def _snapshot(identity: str, marker: str) -> dict[str, Any]:
    return {
        "id": identity,
        "target": {"kind": "fixture", "version": "1"},
        "environment": {"platform": "test"},
        "methodology": {"profile": "standard"},
        "observedEffects": [{"marker": marker}],
        "reproductionRates": {"marker": "1/1"},
        "findings": [],
        "approvalSurface": {"mode": "explicit"},
        "registrySnapshot": {"digest": "sha256:" + "0" * 64},
    }


def _monitor_jobs(tmp_path: Path, *, retention: int = 2) -> tuple[Any, ...]:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    (workspace / "baseline.json").write_bytes(canonical_json_bytes(_snapshot("base", "safe")))
    (workspace / "current.json").write_bytes(canonical_json_bytes(_snapshot("current", "changed")))
    document = {
        "artifactType": "sova.monitor-service-spec",
        "schemaVersion": "0.1.0",
        "jobs": [
            {
                "id": "fixture-drift",
                "baseline": "baseline.json",
                "current": "current.json",
                "policy": None,
                "intervalSeconds": 1,
                "retentionRuns": retention,
            }
        ],
    }
    return monitoring_jobs_from_document(document, workspace=workspace)


def test_monitor_service_schedules_signs_retains_cancels_and_recovers(tmp_path: Path) -> None:
    jobs = _monitor_jobs(tmp_path)
    root = tmp_path / "monitor"
    service = ContinuousMonitorService(jobs, root)
    first_at = datetime(2026, 8, 9, 12, tzinfo=UTC)
    with service:
        first = service.run_due(now=first_at)
        assert len(first) == 1 and first[0]["status"] == "failed"
        assert (
            TraceReader(Path(first[0]["trace"])).verify(require_signature=True).completion
            == "completed"
        )
        assert service.run_due(now=first_at + timedelta(milliseconds=500)) == ()
        second = service.run_due(now=first_at + timedelta(seconds=1))
        third = service.run_due(now=first_at + timedelta(seconds=2))
        assert second and third
    run_dirs = list((root / "runs" / "fixture-drift").iterdir())
    assert len(run_dirs) == 2
    assert len((root / "history" / "fixture-drift.jsonl").read_bytes().splitlines()) == 2

    competing = ContinuousMonitorService(jobs, root)
    with service, pytest.raises(FormatError, match="another monitor service"):
        competing.acquire()

    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    state["jobs"]["fixture-drift"]["status"] = "running"
    (root / "state.json").write_bytes(canonical_json_bytes(state) + b"\n")
    recovered = ContinuousMonitorService(jobs, root)
    assert recovered.status()["jobs"]["fixture-drift"]["recoveredRuns"] == 1
    stop = threading.Event()
    stop.set()
    assert recovered.serve(stop, max_cycles=1) == ()


def test_service_configuration_and_monitor_specs_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="loopback"):
        CommunityServiceConfig(
            tmp_path / "service",
            "synthetic-local-service-token",
            frozenset({"sha256:" + "0" * 64}),
            "method",
            host="0.0." + "0",
        )
    with pytest.raises(FormatError, match="internally inconsistent"):
        CommunityServiceLimits(max_body_bytes=1, max_file_bytes=2)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(FormatError, match="fields are not exact"):
        monitoring_jobs_from_document(
            {
                "artifactType": "sova.monitor-service-spec",
                "schemaVersion": "0.1.0",
                "jobs": [],
                "extra": True,
            },
            workspace=workspace,
        )


def test_leaderboard_submission_used_by_service_remains_standard(tmp_path: Path) -> None:
    artifact, trace, key_id, score, possible = _arena(tmp_path)
    submission = LeaderboardSubmission(
        "model",
        "fixture-defender",
        "1.0.0",
        STANDARD_ARENA_PROFILE.identifier,
        STANDARD_ARENA_PROFILE.digest,
        score,
        possible,
        artifact,
        trace,
        key_id,
    )
    assert submission.profile_id == STANDARD_ARENA_PROFILE.identifier


def test_monitor_and_registry_service_cli_routes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    jobs = _monitor_jobs(tmp_path)
    workspace = tmp_path / "workspace"
    specification = tmp_path / "monitor.json"
    specification.write_bytes(
        canonical_json_bytes(
            {
                "artifactType": "sova.monitor-service-spec",
                "schemaVersion": "0.1.0",
                "jobs": [
                    {
                        "id": jobs[0].identifier,
                        "baseline": "baseline.json",
                        "current": "current.json",
                        "policy": None,
                        "intervalSeconds": 1,
                        "retentionRuns": 2,
                    }
                ],
            }
        )
        + b"\n"
    )
    state = tmp_path / "monitor-state"
    assert (
        main(
            [
                "monitor",
                "serve",
                str(specification),
                str(state),
                "--workspace",
                str(workspace),
                "--once",
            ]
        )
        == 1
    )
    rows = [json.loads(row) for row in capfd.readouterr().out.splitlines()]
    assert rows[0]["artifactType"] == "sova.monitor-service-run"
    assert (
        main(
            [
                "monitor",
                "status",
                str(specification),
                str(state),
                "--workspace",
                str(workspace),
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["serviceRuns"] == 1

    token = tmp_path / "service-token"
    assert main(["registry", "init-service", str(token)]) == 0
    token_report = json.loads(capfd.readouterr().out)
    assert token_report["secretPrinted"] is False
    assert token.read_text(encoding="utf-8") not in json.dumps(token_report)
    methodology = tmp_path / "methodology.md"
    methodology.write_text("fixture methodology", encoding="utf-8")
    served: list[CommunityServiceConfig] = []

    class FakeService:
        def __init__(self, config: CommunityServiceConfig) -> None:
            served.append(config)
            self.address = (config.host, config.port)

        def serve_forever(self) -> None:
            return

    monkeypatch.setattr("sova.cli.CommunityHTTPService", FakeService)
    assert (
        main(
            [
                "registry",
                "serve",
                str(tmp_path / "registry"),
                "--token-file",
                str(token),
                "--trusted-key-id",
                "sha256:" + "1" * 64,
                "--methodology",
                str(methodology),
                "--port",
                "8799",
            ]
        )
        == 0
    )
    assert served[0].token == token.read_text(encoding="utf-8")
    assert "submitted content is verified" in capfd.readouterr().err

    monkeypatch.setattr(
        "sova.cli.check_community_service_health",
        lambda url: {
            "artifactType": "sova.community-service-health-verification",
            "schemaVersion": "0.1.0",
            "status": "ready",
            "url": url,
        },
    )
    assert main(["registry", "healthcheck"]) == 0
    assert json.loads(capfd.readouterr().out)["status"] == "ready"

    index_store = CommunityRegistryStore(
        _service_config(tmp_path / "index-service", "sha256:" + "2" * 64)
    )
    index_path = tmp_path / "live-index.json"
    index_path.write_bytes(canonical_json_bytes(index_store.signed_index()) + b"\n")
    assert (
        main(
            [
                "registry",
                "verify-live-index",
                str(index_path),
                "--trusted-service-key-id",
                index_store.key_id,
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["identityTrusted"] is True

    artifact, trace, evidence_key, score, possible = _arena(tmp_path / "upload-fixture")
    metadata = tmp_path / "leaderboard-metadata.json"
    metadata.write_bytes(
        canonical_json_bytes(
            {
                "requiredKeyId": evidence_key,
                "category": "model",
                "component": "fixture-defender",
                "version": "1.0.0",
                "profileId": STANDARD_ARENA_PROFILE.identifier,
                "profileDigest": STANDARD_ARENA_PROFILE.digest,
                "score": score,
                "possibleScore": possible,
            }
        )
        + b"\n"
    )
    upload = tmp_path / "upload.json"
    assert (
        main(
            [
                "registry",
                "prepare-upload",
                str(metadata),
                str(artifact),
                str(trace),
                str(upload),
                "--kind",
                "leaderboard",
            ]
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["uploadPerformed"] is False
    assert json.loads(upload.read_text(encoding="utf-8"))["files"]
    assert upload.read_bytes().endswith(b"}")
