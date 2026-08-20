# SPDX-License-Identifier: Apache-2.0
"""Focused launch-hardening branches for registry admission and Agent Arena."""

from __future__ import annotations

import base64
import copy
import http.client
import io
import threading
import time
import zipfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from urllib.request import Request

import pytest

import sova.community.agent_arena as agent_arena_module
import sova.community.config as community_config
import sova.registry.service as registry_module
from sova.community import (
    STANDARD_ARENA_PROFILE,
    AgentArenaBudget,
    AgentArenaCase,
    AgentArenaMatch,
    ArenaProfile,
)
from sova.formats import sha256_digest
from sova.formats.canonical import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.models import ScriptedModel
from sova.registry import (
    CommunityHTTPService,
    CommunityRegistryStore,
    CommunityServiceConfig,
    CommunityServiceLimits,
    check_community_service_health,
    prepare_community_submission,
    serialize_community_submission,
)
from sova.runtime import OciAgentRuntime

_KEY_ID = "sha256:" + "1" * 64
_OCI_IMAGE = "example.invalid/sova/coverage-agent@sha256:" + "d" * 64


def _service_config(
    root: Path,
    *,
    requests_per_minute: int = 60,
) -> CommunityServiceConfig:
    return CommunityServiceConfig(
        root,
        "x" * 24,
        frozenset({_KEY_ID}),
        "launch-hardening-methodology",
        limits=CommunityServiceLimits(requests_per_minute=requests_per_minute),
    )


def _upload_document() -> dict[str, Any]:
    files = []
    for name, data in (("case.sova", b"abc"), ("case.sova-trace", b"def")):
        files.append(
            {
                "name": name,
                "digest": sha256_digest(data),
                "size": len(data),
                "data": base64.b64encode(data).decode("ascii"),
            }
        )
    return {
        "artifactType": "sova.community-submission",
        "schemaVersion": "0.1.0",
        "kind": "registry",
        "metadata": {"requiredKeyId": _KEY_ID},
        "files": files,
    }


def _health_document() -> dict[str, Any]:
    return {
        "artifactType": "sova.community-service-health",
        "schemaVersion": "0.1.0",
        "status": "ready",
        "loopbackOnly": True,
        "serviceKeyId": _KEY_ID,
        "uploadLimits": CommunityServiceLimits().to_mapping(),
    }


def _install_health_response(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: int,
    body: bytes,
) -> None:
    response = SimpleNamespace(status=status, read=lambda _limit: body)
    opener = SimpleNamespace(
        open=lambda _request, *, timeout: nullcontext(response) if timeout == 5 else None
    )
    monkeypatch.setattr(registry_module, "build_opener", lambda *_handlers: opener)


def _http_post(host: str, port: int, path: str, body: bytes) -> int:
    connection = http.client.HTTPConnection(host, port, timeout=10)
    connection.request("POST", path, body=body)
    response = connection.getresponse()
    status = response.status
    response.read()
    connection.close()
    return status


def _provider_document() -> dict[str, Any]:
    participants = [
        {
            "id": identifier,
            "provider": "openai",
            "model": "authorized-fixture-model",
            "temperature": "0.0",
            "maxOutputTokens": 1024,
            "timeoutSeconds": "30.0",
        }
        for identifier in ("challenger", "defender", "judge")
    ]
    return {
        "profile": {
            "id": "sova.arena.custom.prevalidation",
            "version": "0.1.0",
            "standard": False,
        },
        "budget": {
            "rounds": 1,
            "maxDurationSeconds": 60,
            "maxOutputBytes": 65536,
            "maxTotalTokens": 20,
            "contentCapture": "metadata-only",
        },
        "participants": participants,
        "matches": [
            {
                "challenger": "challenger",
                "defender": "defender",
                "judge": "judge",
                "case": {
                    "id": "prevalidation-case",
                    "seed": "bounded synthetic seed",
                    "challengerObjective": "emit one bounded message",
                    "defenderObjective": "emit one bounded response",
                    "successSignal": "SAFE_SIGNAL",
                    "points": 1,
                },
            }
        ],
    }


def _arena_case() -> AgentArenaCase:
    return AgentArenaCase(
        "launch-hardening-case",
        "bounded seed",
        "send one bounded message",
        "return one bounded response",
        "SAFE_SIGNAL",
        1,
    )


def _arena_match() -> AgentArenaMatch:
    return AgentArenaMatch("challenger", "defender", "judge", _arena_case())


def _admitted_models() -> dict[str, ScriptedModel]:
    return {
        participant: ScriptedModel([], model_id=f"scripted-{participant}/0.1")
        for participant in ("challenger", "defender", "judge")
    }


def test_health_verifier_fails_closed_for_url_transport_and_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redirect = registry_module._NoRedirect()
    redirect.redirect_request(
        Request("http://127.0.0.1:8736/v1/health"),
        None,
        302,
        "redirect",
        {},
        "http://127.0.0.1:8736/elsewhere",
    )
    with pytest.raises(FormatError, match="literal-IPv4 loopback"):
        check_community_service_health("http://localhost:8736/v1/health")

    def unavailable(*_args: object, **_kwargs: object) -> object:
        raise OSError

    monkeypatch.setattr(
        registry_module,
        "build_opener",
        lambda *_handlers: SimpleNamespace(open=unavailable),
    )
    with pytest.raises(FormatError, match="unavailable"):
        check_community_service_health("http://127.0.0.1:8736/v1/health")

    _install_health_response(monkeypatch, status=503, body=b"{}")
    with pytest.raises(FormatError, match="HTTP 200"):
        check_community_service_health("http://127.0.0.1:8736/v1/health")

    _install_health_response(
        monkeypatch,
        status=200,
        body=b"x" * (registry_module._MAX_HEALTH_BYTES + 1),
    )
    with pytest.raises(FormatError, match="too large"):
        check_community_service_health("http://127.0.0.1:8736/v1/health")

    malformed = _health_document()
    malformed["status"] = "starting"
    _install_health_response(monkeypatch, status=200, body=canonical_json_bytes(malformed))
    with pytest.raises(FormatError, match="readiness contract"):
        check_community_service_health("http://127.0.0.1:8736/v1/health")

    invalid_limits = _health_document()
    invalid_limits["uploadLimits"]["maxFiles"] = True
    _install_health_response(monkeypatch, status=200, body=canonical_json_bytes(invalid_limits))
    with pytest.raises(FormatError, match="upload limits are invalid"):
        check_community_service_health("http://127.0.0.1:8736/v1/health")

    inconsistent = _health_document()
    inconsistent["uploadLimits"]["maxDecodedBytes"] += 1
    _install_health_response(monkeypatch, status=200, body=canonical_json_bytes(inconsistent))
    with pytest.raises(FormatError, match="upload limits are inconsistent"):
        check_community_service_health("http://127.0.0.1:8736/v1/health")


def test_archive_scanner_enforces_scanned_tail_member_and_entry_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as patcher:
        patcher.setattr(registry_module, "_MAX_SERVICE_UNCOMPRESSED_BYTES", 1)
        with pytest.raises(FormatError, match="scan limit"):
            registry_module._spool_archive_member(
                io.BytesIO(b"two"),
                io.BytesIO(),
                registry_module._ArchiveScanState(),
            )

    long_prefix = b"api_key" + b" " * 200 + b"="
    with pytest.raises(FormatError, match="exceeded the scan window"):
        registry_module._spool_archive_member(
            io.BytesIO(long_prefix),
            io.BytesIO(),
            registry_module._ArchiveScanState(),
        )

    secret_name = tmp_path / "secret-name.zip"
    with zipfile.ZipFile(secret_name, "w") as archive:
        archive.writestr("api_key=synthetic-credential-value", b"safe")
    with pytest.raises(FormatError, match="member name"):
        registry_module._archive_preflight(secret_name)

    short_archive = SimpleNamespace(open=lambda _info: io.BytesIO(b"x"))
    short_info = SimpleNamespace(filename="safe.bin", file_size=2)
    with pytest.raises(FormatError, match="size changed"):
        registry_module._scan_archive_member(
            cast("Any", short_archive),
            cast("Any", short_info),
            state=registry_module._ArchiveScanState(),
            depth=0,
        )

    too_many = tmp_path / "too-many.zip"
    with zipfile.ZipFile(too_many, "w") as archive:
        archive.writestr("one", b"1")
        archive.writestr("two", b"2")
    with monkeypatch.context() as patcher:
        patcher.setattr(registry_module, "_MAX_SERVICE_ARCHIVE_ENTRIES", 1)
        with pytest.raises(FormatError, match="entry count"):
            registry_module._archive_preflight(too_many)

    directory = tmp_path / "directory.zip"
    with zipfile.ZipFile(directory, "w") as archive:
        archive.writestr("folder/", b"")
        archive.writestr("folder/content.txt", b"safe")
    registry_module._archive_preflight(directory)


def test_upload_admission_covers_base64_metadata_body_and_read_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_base64 = _upload_document()
    invalid_base64["files"][0]["data"] = "%%%%"
    with pytest.raises(FormatError, match="invalid base64"):
        registry_module._parse_upload(invalid_base64, CommunityServiceLimits())

    non_object_row = _upload_document()
    non_object_row["files"][0] = []
    with pytest.raises(FormatError, match="fields are not exact"):
        registry_module._parse_upload(non_object_row, CommunityServiceLimits())

    with monkeypatch.context() as patcher:
        patcher.setattr(registry_module, "_MAX_METADATA_BYTES", 8)
        with pytest.raises(FormatError, match="metadata exceeds"):
            registry_module._parse_upload(_upload_document(), CommunityServiceLimits())

    limits = CommunityServiceLimits()
    original_canonical = canonical_json_bytes

    def oversized_document(value: Any, *args: Any, **kwargs: Any) -> bytes:
        encoded = original_canonical(value, *args, **kwargs)
        if isinstance(value, dict) and value.get("artifactType") == "sova.community-submission":
            return b"x" * (limits.max_body_bytes + 1)
        return encoded

    with monkeypatch.context() as patcher:
        patcher.setattr(registry_module, "canonical_json_bytes", oversized_document)
        with pytest.raises(FormatError, match="encoded submission exceeds"):
            serialize_community_submission(_upload_document(), limits=limits)

    capsule = tmp_path / "case.sova"
    trace = tmp_path / "case.sova-trace"
    capsule.write_bytes(b"capsule")
    trace.write_bytes(b"trace")
    original_open = Path.open

    def unreadable(source: Path, *args: Any, **kwargs: Any) -> Any:
        if source == capsule:
            raise OSError
        return original_open(source, *args, **kwargs)

    monkeypatch.setattr(Path, "open", unreadable)
    with pytest.raises(FormatError, match="could not be read safely"):
        prepare_community_submission(
            kind="registry",
            metadata={"requiredKeyId": _KEY_ID},
            capsule=capsule,
            trace=trace,
        )


def test_registry_cleanup_skip_and_post_rate_limit_branches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match="loopback-only"):
        _service_config(tmp_path / "external").__class__(
            tmp_path / "external",
            "x" * 24,
            frozenset({_KEY_ID}),
            "method",
            host="192.0.2.1",
        )

    store = CommunityRegistryStore(_service_config(tmp_path / "store"))
    with pytest.raises(FormatError, match="identity is unsafe"):
        store._discard_staging({"id": "BAD ID"})
    unsafe = store.root / "staging" / "safe-id"
    unsafe.parent.mkdir(parents=True, exist_ok=True)
    unsafe.write_bytes(b"not-a-directory")
    with pytest.raises(FormatError, match="path is unsafe"):
        store._discard_staging({"id": "safe-id"})

    queued = store.submit(_upload_document())

    def cleanup_failure(_row: object) -> None:
        raise OSError

    monkeypatch.setattr(store, "_discard_staging", cleanup_failure)
    rejected = store.process_next()
    assert rejected is not None
    assert rejected["id"] == queued["id"]
    assert rejected["error"]["stagingCleanupFailed"] is True
    assert store.signed_index()["index"]["entries"] == []
    assert store.leaderboard()["entries"] == []

    limiter = registry_module._RateLimiter(1)
    assert limiter.allow("operator", now=0)
    assert not limiter.allow("operator", now=0)
    assert limiter.allow("operator", now=60)

    service = CommunityHTTPService(_service_config(tmp_path / "http", requests_per_minute=1))
    thread = threading.Thread(target=service.serve_forever, daemon=True)
    thread.start()
    host, port = service.address
    try:
        assert _http_post(host, port, "/v1/submissions", b"{}") == 401
        assert _http_post(host, port, "/v1/submissions", b"{}") == 429
    finally:
        service.close()
        thread.join(timeout=10)

    lifecycle_service = CommunityHTTPService(_service_config(tmp_path / "lifecycle"))
    joined: list[int] = []

    def fake_start() -> None:
        worker = SimpleNamespace(join=lambda *, timeout: joined.append(timeout))
        monkeypatch.setattr(lifecycle_service, "_worker", cast("Any", worker))

    def fake_serve_forever(*, poll_interval: float) -> None:
        assert poll_interval == 0.2

    monkeypatch.setattr(lifecycle_service, "start", fake_start)
    monkeypatch.setattr(
        lifecycle_service._server,
        "serve_forever",
        fake_serve_forever,
    )
    lifecycle_service.serve_forever()
    assert joined == [5]


def test_registry_verification_and_promotion_cleanup_edges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = CommunityRegistryStore(_service_config(tmp_path / "store"))
    capsule = tmp_path / "case.sova"
    trace = tmp_path / "case.sova-trace"
    capsule.write_bytes(b"capsule")
    trace.write_bytes(b"trace")

    with monkeypatch.context() as patcher:
        patcher.setattr(
            store,
            "_staged_paths",
            lambda _row: {
                "one.sova": capsule,
                "two.sova": capsule,
                "case.sova-trace": trace,
            },
        )
        with pytest.raises(FormatError, match="exactly one capsule"):
            store._verify_row({"metadata": {}, "kind": "registry"})

    verification = store.root / "verification" / "leaderboard-row"
    verification.mkdir(parents=True)
    store._state["submissions"]["prior"] = {
        "id": "prior",
        "status": "accepted",
        "verification": {
            "capsuleDigest": sha256_digest(b"different capsule"),
            "traceDigest": sha256_digest(b"different trace"),
        },
    }

    class FakePackageReader:
        def __init__(self, _path: Path) -> None:
            pass

        def verify(self, _artifact_type: str) -> list[SimpleNamespace]:
            return [SimpleNamespace(role="trace", digest=sha256_digest(trace.read_bytes()))]

    class FakeTraceReader:
        def __init__(self, _path: Path) -> None:
            pass

        def verify(self, **_kwargs: Any) -> SimpleNamespace:
            return SimpleNamespace(completion="completed")

    def fake_leaderboard(
        _submissions: object,
        destination: Path,
        *,
        methodology_snapshot: str,
    ) -> dict[str, Any]:
        assert methodology_snapshot == "launch-hardening-methodology"
        assert not destination.exists()
        destination.mkdir(parents=True)
        return {"artifactType": "fixture"}

    metadata = {
        "requiredKeyId": _KEY_ID,
        "category": "component",
        "component": "coverage-fixture",
        "version": "0.1.0",
        "profileId": STANDARD_ARENA_PROFILE.identifier,
        "profileDigest": STANDARD_ARENA_PROFILE.digest,
        "score": 1,
        "possibleScore": 1,
    }
    with monkeypatch.context() as patcher:
        patcher.setattr(
            store,
            "_staged_paths",
            lambda _row: {"case.sova": capsule, "case.sova-trace": trace},
        )
        patcher.setattr(registry_module, "_archive_preflight", lambda _path: None)
        patcher.setattr(registry_module, "PackageReader", FakePackageReader)
        patcher.setattr(registry_module, "TraceReader", FakeTraceReader)
        patcher.setattr(registry_module, "build_static_leaderboard", fake_leaderboard)
        verified = store._verify_row(
            {"id": "leaderboard-row", "kind": "leaderboard", "metadata": metadata}
        )
        registry_verified = store._verify_row(
            {"id": "registry-row", "kind": "registry", "metadata": metadata}
        )
    assert verified["scoreEvidenceValid"] is True
    assert "scoreEvidenceValid" not in registry_verified
    assert not verification.exists()

    source = store.root / "staging-source"
    source.write_bytes(b"promoted")
    digest = sha256_digest(source.read_bytes())
    target = store.root / "objects" / "sha256" / digest[7:]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())
    row: dict[str, Any] = {
        "id": "no-staging-directory",
        "files": [{"stagingPath": "staging-source", "digest": digest}],
    }
    store._promote(row)
    assert row["files"][0]["objectPath"] == f"objects/sha256/{digest[7:]}"
    store._discard_staging({"id": "absent-staging-directory"})


def test_community_document_adapters_cover_valid_nested_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        community_config._resolved(tmp_path, "inside.bin", "$.path")
        == (tmp_path / "inside.bin").resolve()
    )
    with pytest.raises(FormatError, match="escapes"):
        community_config._resolved(tmp_path, "../outside.bin", "$.path")

    arena_document = {
        "profile": {
            "id": "sova.arena.custom.coverage",
            "version": "0.1.0",
            "standard": False,
        },
        "participants": [
            {
                "id": "attacker",
                "modelId": "scripted-attacker/0.1",
                "turns": [
                    {
                        "expectedContains": "seed",
                        "responseText": "bounded reply",
                        "failure": "synthetic failure",
                    },
                    {"expectedContains": "next", "responseText": "second bounded reply"},
                ],
            },
            {"id": "defender", "modelId": "scripted-defender/0.1", "turns": []},
        ],
        "matches": [
            {
                "attacker": "attacker",
                "defender": "defender",
                "case": {
                    "id": "coverage-case",
                    "attackerPrompt": "seed",
                    "defenderPrompt": "reply",
                    "successMarker": "SAFE_SIGNAL",
                    "points": 1,
                },
            }
        ],
    }

    def fake_local_arena(
        profile: object,
        matches: object,
        models: object,
        destination: Path,
    ) -> dict[str, Any]:
        assert destination == tmp_path / "arena.json"
        assert profile is not None and matches is not None and models is not None
        return {"artifactType": "arena-fixture"}

    monkeypatch.setattr(community_config, "run_local_arena", fake_local_arena)
    assert (
        community_config.run_arena_document(
            arena_document,
            tmp_path / "arena.json",
        )["artifactType"]
        == "arena-fixture"
    )

    artifact = tmp_path / "case.sova"
    trace = tmp_path / "case.sova-trace"
    artifact.write_bytes(b"capsule")
    trace.write_bytes(b"trace")
    captured: dict[str, object] = {}

    def fake_static_leaderboard(
        submissions: object,
        destination: Path,
        *,
        methodology_snapshot: str,
    ) -> dict[str, Any]:
        captured["submissions"] = submissions
        assert destination == tmp_path / "leaderboard.json"
        assert methodology_snapshot == "pinned-methodology"
        return {"artifactType": "leaderboard-fixture"}

    monkeypatch.setattr(community_config, "build_static_leaderboard", fake_static_leaderboard)
    leaderboard = community_config.build_leaderboard_document(
        {
            "methodologySnapshot": "pinned-methodology",
            "submissions": [
                {
                    "category": "component",
                    "component": "coverage-fixture",
                    "version": "0.1.0",
                    "profileId": STANDARD_ARENA_PROFILE.identifier,
                    "profileDigest": STANDARD_ARENA_PROFILE.digest,
                    "score": 1,
                    "possibleScore": 1,
                    "artifact": artifact.name,
                    "trace": trace.name,
                    "requiredKeyId": _KEY_ID,
                }
            ],
        },
        tmp_path / "leaderboard.json",
        base=tmp_path,
    )
    assert leaderboard["artifactType"] == "leaderboard-fixture"
    assert len(cast("Any", captured["submissions"])) == 1

    def fake_ctf(scenarios: object, destination: Path) -> dict[str, Any]:
        assert destination == tmp_path / "ctf.json"
        assert len(cast("Any", scenarios)) == 1
        return {"artifactType": "ctf-fixture"}

    monkeypatch.setattr(community_config, "build_ctf_catalog", fake_ctf)
    ctf = community_config.build_ctf_document(
        {
            "scenarios": [
                {
                    "id": "coverage-scenario",
                    "title": "Coverage scenario",
                    "difficulty": "beginner",
                    "sourceProject": "SOVA",
                    "sourceUrl": "https://example.invalid/sova",
                    "sourceLicense": "Apache-2.0",
                    "setupMode": "bundled-synthetic",
                    "artifact": artifact.name,
                    "explanation": "Bounded synthetic fixture.",
                }
            ]
        },
        tmp_path / "ctf.json",
        base=tmp_path,
    )
    assert ctf["artifactType"] == "ctf-fixture"

    rendered_specs: list[object] = []

    def fake_render(specification: object, destination: Path) -> dict[str, Any]:
        rendered_specs.append(specification)
        assert destination.suffix == ".y4m"
        return {"artifactType": "replay-fixture"}

    monkeypatch.setattr(community_config, "render_replay_clip", fake_render)
    replay_base = {
        "findingClass": "simulation",
        "artifactLink": "case.sova",
        "verificationLink": "verification.json",
        "frames": [{"eventKind": "oracle.result", "caption": "signal observed"}],
    }
    assert (
        community_config.render_replay_clip_document(
            {**replay_base, "componentName": "synthetic target", "disclosureCleared": True},
            tmp_path / "named.y4m",
        )["artifactType"]
        == "replay-fixture"
    )
    assert (
        community_config.render_replay_clip_document(
            replay_base,
            tmp_path / "unnamed.y4m",
        )["artifactType"]
        == "replay-fixture"
    )
    assert len(rendered_specs) == 2


def test_agent_arena_prevalidation_rejects_every_admission_gap_before_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_construct_provider(*_args: object, **_kwargs: object) -> object:
        raise AssertionError

    monkeypatch.setattr(
        community_config,
        "provider_model_from_route",
        must_not_construct_provider,
    )
    community_config.validate_agent_arena_document(
        _provider_document(),
        provider_calls_authorized=True,
    )

    standard = _provider_document()
    standard["profile"]["standard"] = True
    with pytest.raises(FormatError, match="custom non-comparable"):
        community_config.validate_agent_arena_document(
            standard,
            provider_calls_authorized=True,
        )

    with pytest.raises(FormatError, match="provider-call authorization"):
        community_config.validate_agent_arena_document(
            _provider_document(),
            provider_calls_authorized=False,
        )

    duplicate = _provider_document()
    duplicate["participants"].append(copy.deepcopy(duplicate["participants"][0]))
    with pytest.raises(FormatError, match="duplicated"):
        community_config.validate_agent_arena_document(
            duplicate,
            provider_calls_authorized=True,
        )

    mismatched_runtime = _provider_document()
    mismatched_runtime["ociParticipants"] = [
        {
            "id": "external",
            "runtime": OciAgentRuntime("different", _OCI_IMAGE, "/opt/sova/agent").to_mapping(),
        }
    ]
    with pytest.raises(FormatError, match="must match its runtime id"):
        community_config.validate_agent_arena_document(
            mismatched_runtime,
            provider_calls_authorized=True,
        )

    no_matches = _provider_document()
    no_matches["matches"] = []
    with pytest.raises(FormatError, match="at least one match"):
        community_config.validate_agent_arena_document(
            no_matches,
            provider_calls_authorized=True,
        )

    missing = _provider_document()
    missing["matches"][0]["judge"] = "missing"
    with pytest.raises(FormatError, match="participant is unavailable"):
        community_config.validate_agent_arena_document(
            missing,
            provider_calls_authorized=True,
        )

    with pytest.raises(FormatError, match="must be a number"):
        community_config._number([], "$.number")
    with pytest.raises(FormatError, match="must be a number"):
        community_config._number("not-a-number", "$.number")


def test_agent_arena_guards_output_accounting_deadline_and_destination(
    tmp_path: Path,
) -> None:
    with pytest.raises(FormatError, match="duration budget"):
        AgentArenaBudget(max_duration_seconds=0)
    with pytest.raises(FormatError, match="case is invalid"):
        AgentArenaCase("", "seed", "challenge", "defend", "signal")
    with pytest.raises(FormatError, match="points are invalid"):
        AgentArenaCase("case", "seed", "challenge", "defend", "signal", 0)
    with pytest.raises(FormatError, match="participant id is invalid"):
        AgentArenaMatch("", "defender", "judge", _arena_case())
    with pytest.raises(FormatError, match="must be distinct"):
        AgentArenaMatch("same", "same", "judge", _arena_case())

    with pytest.raises(FormatError, match="only message"):
        agent_arena_module._message({"message": "safe", "extra": True}, participant="challenger")
    with pytest.raises(FormatError, match="message is invalid"):
        agent_arena_module._message({"message": ""}, participant="challenger")
    with pytest.raises(FormatError, match="exactly message and signals"):
        agent_arena_module._defense({"message": "safe"})
    with pytest.raises(FormatError, match="defender message is invalid"):
        agent_arena_module._defense({"message": "", "signals": []})
    with pytest.raises(FormatError, match="signals are invalid"):
        agent_arena_module._defense({"message": "safe", "signals": {}})
    with pytest.raises(FormatError, match="credential-shaped output"):
        agent_arena_module._defense(
            {
                "message": "safe",
                "signals": ["Bearer abcdefghijklmnopqrstuvwxyz"],
            }
        )
    with pytest.raises(FormatError, match="advisory is invalid"):
        agent_arena_module._advisory({"assessment": "invalid", "limitations": []})
    with pytest.raises(FormatError, match="limitations are invalid"):
        agent_arena_module._advisory({"assessment": "observed", "limitations": [""]})

    budget = AgentArenaBudget(max_total_tokens=1)
    with pytest.raises(FormatError, match="model-reported token usage"):
        agent_arena_module._account(
            cast("Any", SimpleNamespace(token_count=None)),
            total=0,
            budget=budget,
        )
    with pytest.raises(FormatError, match="token budget exhausted"):
        agent_arena_module._account(
            cast("Any", SimpleNamespace(token_count=2)),
            total=0,
            budget=budget,
        )
    with pytest.raises(FormatError, match="duration exhausted"):
        agent_arena_module._check_deadline(
            time.monotonic() - 2,
            AgentArenaBudget(max_duration_seconds=1),
        )

    profile = ArenaProfile("sova.arena.custom.coverage", "0.1.0", standard=False)
    with pytest.raises(FormatError, match="at least one match"):
        agent_arena_module.run_agent_arena(
            profile,
            (),
            {},
            AgentArenaBudget(),
            tmp_path / "empty",
            provider_calls_authorized=True,
        )
    with pytest.raises(FormatError, match="participant is unavailable"):
        agent_arena_module.run_agent_arena(
            profile,
            (_arena_match(),),
            {},
            AgentArenaBudget(),
            tmp_path / "missing",
            provider_calls_authorized=True,
        )

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep").write_text("user-owned", encoding="utf-8")
    with pytest.raises(FormatError, match="not empty"):
        agent_arena_module.run_agent_arena(
            profile,
            (_arena_match(),),
            _admitted_models(),
            AgentArenaBudget(),
            occupied,
            provider_calls_authorized=True,
        )
