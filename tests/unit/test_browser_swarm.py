# SPDX-License-Identifier: Apache-2.0
"""Executor-backed browser swarm contracts, evidence, and hostile inputs."""

from __future__ import annotations

import json
import struct
from dataclasses import replace
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.community import (
    BrowserSwarmBudget,
    BrowserSwarmCase,
    BrowserSwarmParticipant,
    run_browser_swarm,
    run_browser_swarm_document,
    validate_browser_swarm_document,
)
from sova.community import browser_swarm as swarm_module
from sova.executors import CancellationToken
from sova.formats import PackageReader, canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import BrowserCampaignArtifacts, owned_web_campaign, owned_web_target
from sova.models import ScriptedModel, ScriptedTurn
from sova.replay import VerificationState, render_capsule_timeline, verify_artifact
from sova.runtime import (
    BrowserProfileVault,
    GVisorOciAgentAdapter,
    OciAgentResponse,
    OciAgentRuntime,
)
from sova.trace import Redactor, TraceReader, TraceWriter, generate_ed25519_keypair

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sova.live import BrowserCampaign
    from sova.runtime import BrowserProfileLease
    from sova.targets import TargetManifest


def _model(candidate: int, message: str = "safe observation") -> ScriptedModel:
    return ScriptedModel(
        [
            ScriptedTurn(
                "sova.browser-swarm-participant/0.1.0",
                "",
                {"candidateIndex": candidate, "message": message},
                token_count=2,
            )
        ],
        model_id=f"fixture-{candidate}",
    )


def _case() -> BrowserSwarmCase:
    return BrowserSwarmCase(
        "owned-swarm",
        "Owned browser swarm",
        (
            BrowserSwarmParticipant("recon", "establish a baseline", (0,)),
            BrowserSwarmParticipant("tester", "exercise the declared trigger", (3,)),
        ),
    )


def _ebml_size(value: int) -> bytes:
    if value < 0x7F:
        return bytes((0x80 | value,))
    if value < 0x3FFF:
        return bytes((0x40 | (value >> 8), value & 0xFF))
    raise AssertionError


def _ebml(identifier: bytes, payload: bytes) -> bytes:
    return identifier + _ebml_size(len(payload)) + payload


def _synthetic_webm(*, duration_seconds: float = 12.0) -> bytes:
    info = _ebml(b"\x2a\xd7\xb1", (1_000_000).to_bytes(3, "big")) + _ebml(
        b"\x44\x89", struct.pack(">d", duration_seconds * 1000)
    )
    segment = b"".join(
        (
            _ebml(b"\x15\x49\xa9\x66", info),
            _ebml(b"\x16\x54\xae\x6b", b"\xae\x80"),
            _ebml(b"\x1f\x43\xb6\x75", b"\xe7\x81\x00"),
        )
    )
    return _ebml(b"\x1a\x45\xdf\xa3", b"") + _ebml(b"\x18\x53\x80\x67", segment)


def _fake_browser_campaign(
    target: TargetManifest,
    campaign: BrowserCampaign,
    destination: Path,
    **options: Any,
) -> BrowserCampaignArtifacts:
    destination.mkdir(parents=True)
    traces = destination / "traces"
    traces.mkdir()
    target_path = destination / "target.json"
    campaign_path = destination / "campaign.json"
    report_path = destination / "report.json"
    target_path.write_text("{}\n", encoding="utf-8")
    campaign_path.write_bytes(canonical_json_bytes(campaign.to_mapping()) + b"\n")
    observed = campaign.candidates[0] == ("enable research mode", "blue owl")

    def write(path: Path, channel: str) -> tuple[str, int] | None:
        observer: Callable[[str, dict[str, Any]], None] | None = options.get("event_observer")
        writer = TraceWriter(
            path,
            capture_profile="standard",
            authorization={
                "decision": "allowed",
                "scopeDigest": target.digest,
                "decidedBy": "deterministic-test",
            },
            signing_key=generate_ed25519_keypair(),
            event_observer=(None if observer is None else lambda event: observer(channel, event)),
        )
        writer.append("run.started", {"campaign": campaign.identifier})
        oracle_event = (
            writer.append("oracle.completed", {"status": "pass", "results": []})
            if observed
            else None
        )
        writer.append("run.completed", {"status": "pass" if observed else "not-observed"})
        writer.finalize(completion="completed")
        if oracle_event is None:
            return None
        event = next(item for item in TraceReader(path).events() if item["id"] == oracle_event)
        return oracle_event, int(event["sequence"])

    attempt = traces / "attempt-001.sova-trace"
    write(attempt, "attempt-001")
    reproduction = None
    reproduction_oracle: tuple[str, int] | None = None
    if observed:
        reproduction = traces / "reproduction.sova-trace"
        reproduction_oracle = write(reproduction, "reproduction")
    report_path.write_bytes(
        canonical_json_bytes({"status": "pass" if observed else "not-confirmed"}) + b"\n"
    )
    discovery = None
    visual_replays: tuple[Path, ...] = ()
    replay_cues = None
    if options.get("record_video"):
        video = _synthetic_webm()
        video_path = destination / "visual-replay-01.webm"
        video_path.write_bytes(video)
        visual_replays = (video_path,)
        if observed:
            assert reproduction is not None
            assert reproduction_oracle is not None
            event_id, sequence = reproduction_oracle
            cue_document = {
                "artifactType": "sova.replay-cues",
                "schemaVersion": "0.1.0",
                "mediaName": video_path.name,
                "mediaDigest": sha256_digest(video),
                "synchronization": {
                    "method": "same-host-monotonic-recorder-start-rpc-bound",
                    "uncertaintyMs": "1.000",
                    "frameTimestampAttested": False,
                    "statement": "Deterministic fixture.",
                },
                "cues": [
                    {
                        "id": "decisive-reproduction",
                        "label": "Behavior reproduced",
                        "channel": "reproduction",
                        "eventId": event_id,
                        "eventKind": "oracle.completed",
                        "eventSequence": sequence,
                        "oracleStatus": "pass",
                        "offsetSeconds": "4.000000",
                        "chapterOffsetSeconds": "4.100000",
                        "preRollSeconds": "2.000000",
                        "postRollSeconds": "3.000000",
                    }
                ],
            }
            replay_cues = destination / "replay-cues.json"
            replay_cues.write_bytes(canonical_json_bytes(cue_document))
            manifest = capsule_manifest_template(
                title="Recorded participant finding",
                summary="Deterministic browser-swarm replay fixture.",
                author="Tests",
            )
            manifest["license"] = "Apache-2.0"
            manifest["safety"]["impact"] = "none"
            discovery = destination / "discovery.sova"
            build_capsule(
                discovery,
                manifest,
                attachments={
                    video_path.name: video,
                    replay_cues.name: replay_cues.read_bytes(),
                },
                traces=[attempt, reproduction],
            )
    return BrowserCampaignArtifacts(
        target_path,
        campaign_path,
        (attempt,),
        reproduction,
        discovery,
        report_path,
        "pass" if observed else "not-confirmed",
        visual_replays,
        replay_cues,
    )


def _lease(tmp_path: Path, target_digest: str) -> BrowserProfileLease:
    vault = BrowserProfileVault(tmp_path / "profiles")
    record = vault.create(identity_id="operator", target=target_digest)
    return vault.acquire(record.handle, owner_id="browser-swarm-test")


def test_browser_swarm_builds_signed_multichannel_capsule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"fixture")
    synthetic_credential = "Bearer " + "synthetic-" + "credential"
    observed: dict[str, list[dict[str, Any]]] = {}
    with _lease(tmp_path, target.digest) as lease:
        artifacts = run_browser_swarm(
            target,
            campaign,
            _case(),
            {
                "recon": _model(0, synthetic_credential),
                "tester": _model(3),
            },
            BrowserSwarmBudget(1, 1, 2, 120, 4096, 4, stop_on_success=True),
            tmp_path / "result",
            package_runner=runner,
            browser_executable=runner,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
            headless=False,
            record_video=True,
            browser_cache=tmp_path / "playwright-cache",
            event_observer=lambda channel, event: observed.setdefault(channel, []).append(event),
        )

    assert artifacts.status == "pass"
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    assert verify_artifact(artifacts.capsule).state in {
        VerificationState.VERIFIED,
        VerificationState.PARTIAL,
    }
    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["evidence"]["participantTraceCount"] == 3
    assert report["evidence"]["liveChannelStreamMatchesSignedTraces"] is True
    assert report["claims"]["unrestrictedParallelSwarm"] is False
    assert report["scheduler"]["rawCredentialsSharedWithModels"] is False
    serialized = artifacts.report.read_bytes() + artifacts.live_events.read_bytes()
    assert synthetic_credential.encode() not in serialized
    assert len(artifacts.participant_runs) == 2
    assert artifacts.decisive_replay_capsule == tmp_path / "result" / "swarm-finding.sova"
    source_finding = artifacts.participant_runs[1] / "discovery.sova"
    assert artifacts.decisive_replay_capsule.read_bytes() == source_finding.read_bytes()
    replay = render_capsule_timeline(
        artifacts.decisive_replay_capsule,
        tmp_path / "decisive-replay.html",
    )
    assert replay["opensAtDecisiveMoment"] is True
    assert replay["decisiveCueDurationBound"] is True
    decisive_objects = PackageReader(artifacts.decisive_replay_capsule).verify("sova.capsule")
    assert len([item for item in decisive_objects if item.role == "trace"]) == 2
    assert len([item for item in decisive_objects if item.role == "visual-replay"]) == 1
    assert len([item for item in decisive_objects if item.role == "replay-cues"]) == 1
    aggregate_objects = PackageReader(artifacts.capsule).verify("sova.capsule")
    assert len([item for item in aggregate_objects if item.role == "trace"]) > 2
    assert not [item for item in aggregate_objects if item.role == "visual-replay"]
    assert report["artifacts"]["aggregateCapsuleRole"] == "audit-only"
    assert report["artifacts"]["decisiveReplayCapsule"] == "swarm-finding.sova"
    assert report["decisiveReplay"]["selectionPolicy"] == "first-confirmed-in-execution-order"
    assert report["claims"]["browserSubrunsRecorded"] is True
    assert report["claims"]["participantPlanningRecordedOnVideo"] is False
    manifest = TraceReader(artifacts.trace).manifest()
    scope = {
        "targetDigest": target.digest,
        "campaignDigest": campaign.digest,
        "case": report["case"],
        "budget": report["budget"],
        "sharedBrowserProfile": report["profile"],
        "participantExecutionBindings": report["participantExecution"],
    }
    capability = {
        **scope,
        "scheduler": "sequential-turns-exclusive-profile-lease",
        "browserActions": "sova-human-approved-only",
        "participantDirectTools": False,
    }
    assert manifest["authorization"]["scopeDigest"] == sha256_digest(canonical_json_bytes(scope))
    assert manifest["executor"]["capabilityDigest"] == sha256_digest(
        canonical_json_bytes(capability)
    )
    assert observed["coordinator"] == TraceReader(artifacts.trace).events()
    assert all(
        path.name != "attempt-001.sova-trace"
        for path in artifacts.capsule.parent.glob("trace-attachments/*")
    )


@pytest.mark.parametrize(
    "defect",
    ["missing-video", "multiple-video", "missing-cues", "missing-discovery"],
)
def test_requested_recording_fails_closed_on_incomplete_decisive_evidence(
    defect: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken_campaign(*args: Any, **options: Any) -> BrowserCampaignArtifacts:
        artifacts = _fake_browser_campaign(*args, **options)
        if artifacts.status != "pass":
            return artifacts
        if defect == "missing-video":
            return replace(artifacts, visual_replays=())
        if defect == "multiple-video":
            extra = artifacts.report.parent / "visual-replay-02.webm"
            extra.write_bytes(_synthetic_webm())
            return replace(artifacts, visual_replays=(*artifacts.visual_replays, extra))
        if defect == "missing-cues":
            return replace(artifacts, replay_cues=None)
        return replace(artifacts, discovery_capsule=None)

    monkeypatch.setattr(swarm_module, "run_browser_campaign", broken_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"fixture")
    with (
        _lease(tmp_path, target.digest) as lease,
        pytest.raises(FormatError, match=r"recording|visual replay|discovery capsule"),
    ):
        run_browser_swarm(
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, 120, 4096),
            tmp_path / f"broken-{defect}",
            package_runner=runner,
            browser_executable=runner,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
            record_video=True,
        )


def _document(candidate_a: int = 0, candidate_b: int = 3) -> dict[str, Any]:
    def participant(identifier: str, candidate: int) -> dict[str, Any]:
        return {
            "id": identifier,
            "objective": "use one declared case",
            "allowedCandidateIndices": [candidate],
            "model": {
                "adapter": "scripted",
                "modelId": f"fixture-{identifier}",
                "turns": [
                    {
                        "expectedContains": "sova.browser-swarm-participant/0.1.0",
                        "responseText": "",
                        "structured": {"candidateIndex": candidate, "message": "safe"},
                        "tokenCount": 1,
                    }
                ],
            },
        }

    return {
        "artifactType": "sova.browser-swarm",
        "schemaVersion": "0.1.0",
        "case": {"id": "owned-swarm", "title": "Owned swarm"},
        "budget": {
            "rounds": 1,
            "maxTurnsPerAgent": 1,
            "maxTotalTurns": 2,
            "maxDurationSeconds": 120,
            "maxOutputBytes": 4096,
            "maxTotalTokens": 2,
            "stopOnSuccess": True,
        },
        "participants": [participant("recon", candidate_a), participant("tester", candidate_b)],
    }


def _oci_runtime(identifier: str, *, image_marker: str = "a") -> OciAgentRuntime:
    return OciAgentRuntime(
        identifier,
        f"fixture/sova-agent@sha256:{image_marker * 64}",
        "/sova-agent",
    )


def _oci_adapter(runtime: OciAgentRuntime, workspace: Path) -> GVisorOciAgentAdapter:
    adapter = object.__new__(GVisorOciAgentAdapter)
    adapter.runtime = runtime
    executor: Any = SimpleNamespace(
        attestation=SimpleNamespace(
            digest="sha256:" + "f" * 64,
            readiness="ready",
        )
    )
    adapter.executor = executor
    adapter.workspace = workspace
    return adapter


def _oci_document() -> dict[str, Any]:
    document = _document()
    document["participants"] = document["participants"][:1]
    document["ociParticipants"] = [
        {
            "id": "tester",
            "objective": "exercise one declared workflow",
            "allowedCandidateIndices": [3],
            "runtime": _oci_runtime("tester").to_mapping(),
        }
    ]
    return document


def test_document_admits_exact_attested_oci_participant_without_browser_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    monkeypatch.setattr(
        GVisorOciAgentAdapter,
        "respond",
        lambda _self, _prompt: OciAgentResponse(
            "",
            {"candidateIndex": 3, "message": "bounded isolated proposal"},
            1,
            resolved_model_id="fixture-isolated-agent",
        ),
    )
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    adapter = _oci_adapter(_oci_runtime("tester"), tmp_path)
    with _lease(tmp_path, target.digest) as lease:
        artifacts = run_browser_swarm_document(
            _oci_document(),
            target,
            campaign,
            tmp_path / "oci-swarm",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models={"tester": adapter},
        )

    report = strict_json_loads(artifacts.report.read_bytes())
    assert isinstance(report, dict)
    assert report["status"] == "pass"
    assert report["sandboxedExternalParticipants"] == ["tester"]
    assert report["nativeCodeExecuted"] is True
    assert report["participantExecution"]["tester"]["runtimeDigest"] == adapter.runtime.digest
    assert report["participantExecution"]["tester"]["attestationDigest"] == (
        adapter.executor.attestation.digest
    )
    assert report["claims"]["attestedGVisorExternalAgents"] is True
    assert report["claims"]["externalAgentsHaveDirectBrowserAuthority"] is False
    manifest = TraceReader(artifacts.trace).manifest()
    scope = {
        "targetDigest": target.digest,
        "campaignDigest": campaign.digest,
        "case": report["case"],
        "budget": report["budget"],
        "sharedBrowserProfile": report["profile"],
        "participantExecutionBindings": report["participantExecution"],
    }
    assert manifest["authorization"]["scopeDigest"] == sha256_digest(canonical_json_bytes(scope))
    assert manifest["executor"]["capabilityDigest"] == sha256_digest(
        canonical_json_bytes(
            {
                **scope,
                "scheduler": "sequential-turns-exclusive-profile-lease",
                "browserActions": "sova-human-approved-only",
                "participantDirectTools": False,
            }
        )
    )


@pytest.mark.parametrize("failure", ["missing", "wrong-type", "substitution", "undeclared"])
def test_document_refuses_unbound_or_substituted_external_participants(
    failure: str,
    tmp_path: Path,
) -> None:
    document = _oci_document()
    runtime = _oci_runtime("tester")
    external: dict[str, Any]
    if failure == "missing":
        external = {}
        expected = "no authorized external model adapter"
    elif failure == "wrong-type":
        external = {"tester": _model(3)}
        expected = "exact gVisor OCI agent adapter"
    elif failure == "substitution":
        external = {"tester": _oci_adapter(_oci_runtime("tester", image_marker="b"), tmp_path)}
        expected = "does not match the declared runtime"
    else:
        document = _document()
        external = {"undeclared": _oci_adapter(runtime, tmp_path)}
        expected = "not declared in the swarm document"
    with pytest.raises(FormatError, match=expected):
        run_browser_swarm_document(
            document,
            owned_web_target("http://127.0.0.1:9187"),
            owned_web_campaign("http://127.0.0.1:9187/"),
            tmp_path / f"external-{failure}",
            package_runner=tmp_path / "runner.exe",
            browser_executable=tmp_path / "runner.exe",
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=object(),  # type: ignore[arg-type]
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
            external_models=external,
        )


@pytest.mark.parametrize("invalid", ["candidate-grant", "aggregate-turns"])
def test_complete_prevalidation_rejects_campaign_and_turn_budget_before_external_setup(
    invalid: str,
) -> None:
    document = _oci_document()
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    if invalid == "candidate-grant":
        document["ociParticipants"][0]["allowedCandidateIndices"] = [len(campaign.candidates)]
        expected = "outside the campaign"
    else:
        document["budget"]["maxTotalTurns"] = 3
        expected = "sum of per-agent grants"
    with pytest.raises(FormatError, match=expected):
        validate_browser_swarm_document(
            document,
            campaign,
            provider_calls_authorized=False,
        )


def test_document_parser_is_strict_and_routes_models(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"fixture")
    with _lease(tmp_path, target.digest) as lease:
        artifacts = run_browser_swarm_document(
            _document(),
            target,
            campaign,
            tmp_path / "parsed",
            package_runner=runner,
            browser_executable=runner,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )
    assert artifacts.status == "pass"

    malformed = _document()
    malformed["unknown"] = True
    with pytest.raises(FormatError, match="fields are invalid"):
        run_browser_swarm_document(
            malformed,
            target,
            campaign,
            tmp_path / "rejected",
            package_runner=runner,
            browser_executable=runner,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=object(),  # type: ignore[arg-type]
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )


@pytest.mark.parametrize(
    "participant",
    [
        BrowserSwarmParticipant("agent", "objective", (0,)),
        BrowserSwarmParticipant("agent-2", "objective", (1,)),
    ],
)
def test_case_requires_multiple_unique_participants(participant: BrowserSwarmParticipant) -> None:
    with pytest.raises(FormatError):
        BrowserSwarmCase("case", "title", (participant,))


def test_hostile_identifiers_budgets_models_and_cancellation_are_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for identifier in ("../escape", "bad id", "", "a" * 65):
        with pytest.raises(FormatError):
            BrowserSwarmParticipant(identifier, "objective", (0,))
    invalid_budgets: tuple[dict[str, Any], ...] = (
        {"rounds": 0},
        {"max_total_turns": 1},
        {"max_output_bytes": 10},
        {"max_total_tokens": 0},
    )
    for values in invalid_budgets:
        with pytest.raises(FormatError):
            BrowserSwarmBudget(**values)

    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"fixture")
    token = CancellationToken()
    token.cancel()
    with (
        _lease(tmp_path, target.digest) as lease,
        pytest.raises(FormatError, match="cancelled"),
    ):
        run_browser_swarm(
            target,
            campaign,
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, 120, 4096, 4),
            tmp_path / "cancelled",
            package_runner=runner,
            browser_executable=runner,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
            cancellation=token,
        )


def test_participant_cannot_escape_candidate_grant_or_call_tools(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"fixture")
    cases = (
        _model(2),
        ScriptedModel(
            [
                ScriptedTurn(
                    "sova.browser-swarm-participant/0.1.0",
                    "",
                    {"candidateIndex": 0, "message": "unsafe"},
                    tool_calls=({"name": "browser.click", "arguments": {}},),
                )
            ]
        ),
    )
    for index, hostile in enumerate(cases):
        with _lease(tmp_path / str(index), target.digest) as lease, pytest.raises(FormatError):
            run_browser_swarm(
                target,
                campaign,
                _case(),
                {"recon": hostile, "tester": _model(3)},
                BrowserSwarmBudget(1, 1, 2, 120, 4096, None),
                tmp_path / f"hostile-{index}",
                package_runner=runner,
                browser_executable=runner,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )


def test_live_journal_is_machine_readable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    runner = tmp_path / "runner.exe"
    runner.write_bytes(b"fixture")
    with _lease(tmp_path, target.digest) as lease:
        artifacts = run_browser_swarm(
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, 120, 4096, None),
            tmp_path / "journal",
            package_runner=runner,
            browser_executable=runner,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
        )
    for line in artifacts.live_events.read_text(encoding="utf-8").splitlines():
        value = json.loads(line)
        assert set(value) == {"channel", "event"}


def test_unexpected_live_channel_fails_evidence_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def runner(*args: Any, **options: Any) -> BrowserCampaignArtifacts:
        artifacts = _fake_browser_campaign(*args, **options)
        options["event_observer"]("undeclared-channel", {"kind": "run.started"})
        return artifacts

    monkeypatch.setattr(swarm_module, "run_browser_campaign", runner)
    target = owned_web_target("http://127.0.0.1:9187")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    with (
        _lease(tmp_path, target.digest) as lease,
        pytest.raises(FormatError, match="live channels do not match"),
    ):
        run_browser_swarm(
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, 120, 4096, None),
            tmp_path / "unexpected-channel",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
        )


def test_extra_model_and_wrong_target_profile_fail_closed(tmp_path: Path) -> None:
    target = owned_web_target("http://127.0.0.1:9187")
    other = owned_web_target("http://127.0.0.1:9188")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    with _lease(tmp_path, target.digest) as lease:
        with pytest.raises(FormatError, match="undeclared participant model"):
            run_browser_swarm(
                target,
                owned_web_campaign("http://127.0.0.1:9187/"),
                _case(),
                {"recon": _model(0), "tester": _model(3), "extra": _model(1)},
                BrowserSwarmBudget(1, 1, 2),
                tmp_path / "extra-model",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )
        with pytest.raises(FormatError, match="different target"):
            run_browser_swarm(
                other,
                owned_web_campaign("http://127.0.0.1:9188/"),
                _case(),
                {"recon": _model(0), "tester": _model(3)},
                BrowserSwarmBudget(1, 1, 2),
                tmp_path / "wrong-target",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )


def test_provider_model_requires_explicit_call_permission(tmp_path: Path) -> None:
    target = owned_web_target("http://127.0.0.1:9187")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    document = _document()
    document["participants"][0]["model"] = {
        "adapter": "provider",
        "provider": "openai",
        "model": "fixture-model",
        "temperature": 0,
        "maxOutputTokens": 64,
        "timeoutSeconds": 5,
    }
    with (
        _lease(tmp_path, target.digest) as lease,
        pytest.raises(FormatError, match="explicit authorization"),
    ):
        run_browser_swarm_document(
            document,
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            tmp_path / "provider-denied",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: BrowserSwarmParticipant("agent", "", (0,)),
        lambda: BrowserSwarmParticipant("agent", "x" * 5000, (0,)),
        lambda: BrowserSwarmParticipant("agent", "objective", ()),
        lambda: BrowserSwarmParticipant("agent", "objective", (0, 0)),
        lambda: BrowserSwarmParticipant("agent", "objective", (True,)),
        lambda: BrowserSwarmParticipant("agent", "objective", (-1,)),
        lambda: BrowserSwarmCase("bad id", "title", (_case().participants)),
        lambda: BrowserSwarmCase("case", "", (_case().participants)),
        lambda: BrowserSwarmCase("case", "title", (_case().participants * 5)),
        lambda: BrowserSwarmCase(
            "case",
            "title",
            (
                BrowserSwarmParticipant("same", "one", (0,)),
                BrowserSwarmParticipant("same", "two", (1,)),
            ),
        ),
        lambda: BrowserSwarmBudget(rounds=True),
        lambda: BrowserSwarmBudget(rounds=1, max_turns_per_agent=2),
        lambda: BrowserSwarmBudget(max_total_turns=True),
        lambda: BrowserSwarmBudget(max_duration_seconds=0),
        lambda: BrowserSwarmBudget(max_output_bytes=2 * 1024 * 1024),
        lambda: BrowserSwarmBudget(max_total_tokens=True),
    ],
)
def test_constructor_hostile_boundaries(factory: Callable[[], object]) -> None:
    with pytest.raises(FormatError):
        factory()


@pytest.mark.parametrize(
    "turn",
    [
        ScriptedTurn("prompt", "", None),
        ScriptedTurn("prompt", "", {"candidateIndex": 0, "message": "ok", "extra": 1}),
        ScriptedTurn("prompt", "", {"candidateIndex": True, "message": "ok"}),
        ScriptedTurn("prompt", "", {"candidateIndex": 0, "message": 1}),
        ScriptedTurn("prompt", "x" * 2000, {"candidateIndex": 0, "message": "ok"}),
        ScriptedTurn("prompt", "", {"candidateIndex": 0, "message": "ok"}, token_count=-1),
        ScriptedTurn(
            "prompt",
            "",
            {"candidateIndex": 0, "message": "ok"},
            resolved_model_id="",
        ),
    ],
)
def test_proposal_refuses_malformed_or_over_budget_output(turn: ScriptedTurn) -> None:
    with pytest.raises(FormatError):
        swarm_module._proposal(
            ScriptedModel([turn]),
            "prompt",
            BrowserSwarmBudget(max_output_bytes=1024),
            redactor=Redactor(),
        )


def test_run_preconditions_refuse_missing_unsupported_out_of_range_and_nonempty(
    tmp_path: Path,
) -> None:
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    invalid_grant = BrowserSwarmCase(
        "invalid-grant",
        "Invalid grant",
        (
            BrowserSwarmParticipant("recon", "objective", (99,)),
            BrowserSwarmParticipant("tester", "objective", (3,)),
        ),
    )
    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "existing").write_text("fixture", encoding="utf-8")
    with _lease(tmp_path, target.digest) as lease:
        with pytest.raises(FormatError, match="outside the campaign"):
            run_browser_swarm(
                target,
                campaign,
                invalid_grant,
                {"recon": _model(0), "tester": _model(3)},
                BrowserSwarmBudget(1, 1, 2),
                tmp_path / "invalid-grant",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )
        with pytest.raises(FormatError, match="model is missing"):
            run_browser_swarm(
                target,
                campaign,
                _case(),
                {"recon": _model(0)},
                BrowserSwarmBudget(1, 1, 2),
                tmp_path / "missing",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )
        with pytest.raises(FormatError, match="only built-in"):
            run_browser_swarm(
                target,
                campaign,
                _case(),
                {"recon": _model(0), "tester": object()},  # type: ignore[dict-item]
                BrowserSwarmBudget(1, 1, 2),
                tmp_path / "unsupported",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )
        with pytest.raises(FormatError, match="sum of per-agent grants"):
            run_browser_swarm(
                target,
                campaign,
                _case(),
                {"recon": _model(0), "tester": _model(3)},
                BrowserSwarmBudget(2, 1, 3),
                tmp_path / "over-budget",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )
        with pytest.raises(FormatError, match="destination is not empty"):
            run_browser_swarm(
                target,
                campaign,
                _case(),
                {"recon": _model(0), "tester": _model(3)},
                BrowserSwarmBudget(1, 1, 2),
                nonempty,
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )


@pytest.mark.parametrize(
    ("model_finished_at", "message"),
    [(1.1, "duration budget exhausted"), (0.2, "cannot admit another browser subrun")],
)
def test_global_duration_refuses_late_or_subsecond_model_result_before_browser(
    model_finished_at: float,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 0.0}
    monkeypatch.setattr(
        swarm_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock["now"]),
    )
    original_respond = ScriptedModel.respond

    def delayed_respond(model: ScriptedModel, prompt: str) -> Any:
        response = original_respond(model, prompt)
        clock["now"] = model_finished_at
        return response

    monkeypatch.setattr(ScriptedModel, "respond", delayed_respond)
    monkeypatch.setattr(
        swarm_module,
        "run_browser_campaign",
        lambda *_args, **_kwargs: pytest.fail("browser work started after deadline gate"),
    )
    target = owned_web_target("http://127.0.0.1:9187")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    with (
        _lease(tmp_path, target.digest) as lease,
        pytest.raises(FormatError, match=message),
    ):
        run_browser_swarm(
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, max_duration_seconds=1),
            tmp_path / f"model-deadline-{model_finished_at}",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
        )


def test_global_duration_is_rechecked_immediately_after_browser_subrun(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 0.0}
    monkeypatch.setattr(
        swarm_module,
        "time",
        SimpleNamespace(monotonic=lambda: clock["now"]),
    )

    def slow_browser(*args: Any, **options: Any) -> BrowserCampaignArtifacts:
        artifacts = _fake_browser_campaign(*args, **options)
        clock["now"] = 1.1
        return artifacts

    monkeypatch.setattr(swarm_module, "run_browser_campaign", slow_browser)
    target = owned_web_target("http://127.0.0.1:9187")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    with (
        _lease(tmp_path, target.digest) as lease,
        pytest.raises(FormatError, match="duration budget exhausted"),
    ):
        run_browser_swarm(
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, max_duration_seconds=1),
            tmp_path / "browser-deadline",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=lease,
            provider_calls_authorized=False,
        )


def test_duplicate_candidate_and_missing_or_excess_token_usage_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(swarm_module, "run_browser_campaign", _fake_browser_campaign)
    target = owned_web_target("http://127.0.0.1:9187")
    campaign = owned_web_campaign("http://127.0.0.1:9187/")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    duplicate_case = BrowserSwarmCase(
        "duplicate",
        "Duplicate selection",
        (
            BrowserSwarmParticipant("first", "objective", (0,)),
            BrowserSwarmParticipant("second", "objective", (0,)),
        ),
    )
    scenarios = (
        (
            duplicate_case,
            {"first": _model(0), "second": _model(0)},
            BrowserSwarmBudget(1, 1, 2),
            "candidate reuse",
        ),
        (
            _case(),
            {
                "recon": ScriptedModel(
                    [
                        ScriptedTurn(
                            "sova.browser-swarm-participant/0.1.0",
                            "",
                            {"candidateIndex": 0, "message": "ok"},
                        )
                    ]
                ),
                "tester": _model(3),
            },
            BrowserSwarmBudget(1, 1, 2, max_total_tokens=4),
            "model-reported token counts",
        ),
        (
            _case(),
            {"recon": _model(0), "tester": _model(3)},
            BrowserSwarmBudget(1, 1, 2, max_total_tokens=3),
            "token budget exhausted",
        ),
    )
    for index, (case, models, budget, message) in enumerate(scenarios):
        with (
            _lease(tmp_path / str(index), target.digest) as lease,
            pytest.raises(FormatError, match=message),
        ):
            run_browser_swarm(
                target,
                campaign,
                case,
                models,
                budget,
                tmp_path / f"usage-{index}",
                package_runner=executable,
                browser_executable=executable,
                approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
                profile_lease=lease,
                provider_calls_authorized=False,
            )


def test_config_version_and_duplicate_ids_fail_before_execution(tmp_path: Path) -> None:
    target = owned_web_target("http://127.0.0.1:9187")
    executable = tmp_path / "runner.exe"
    executable.write_bytes(b"fixture")
    unsupported = _document()
    unsupported["schemaVersion"] = "9.9.9"
    with pytest.raises(FormatError, match="unsupported"):
        run_browser_swarm_document(
            unsupported,
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            tmp_path / "version",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=object(),  # type: ignore[arg-type]
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )
    duplicated = _document()
    duplicated["participants"][1]["id"] = "recon"
    with pytest.raises(FormatError, match="duplicated"):
        run_browser_swarm_document(
            duplicated,
            target,
            owned_web_campaign("http://127.0.0.1:9187/"),
            tmp_path / "duplicated",
            package_runner=executable,
            browser_executable=executable,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
            profile_lease=object(),  # type: ignore[arg-type]
            secret_resolver=lambda _name: None,
            provider_calls_authorized=False,
        )
