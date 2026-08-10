# SPDX-License-Identifier: Apache-2.0
"""Executor-backed browser swarm contracts, evidence, and hostile inputs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from sova.community import (
    BrowserSwarmBudget,
    BrowserSwarmCase,
    BrowserSwarmParticipant,
    run_browser_swarm,
    run_browser_swarm_document,
)
from sova.community import browser_swarm as swarm_module
from sova.executors import CancellationToken
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.live import BrowserCampaignArtifacts, owned_web_campaign, owned_web_target
from sova.models import ScriptedModel, ScriptedTurn
from sova.replay import VerificationState, verify_artifact
from sova.runtime import BrowserProfileVault
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

    def write(path: Path, channel: str) -> None:
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
        writer.append("run.completed", {"status": "pass" if observed else "not-observed"})
        writer.finalize(completion="completed")

    attempt = traces / "attempt-001.sova-trace"
    write(attempt, "attempt-001")
    reproduction = None
    if observed:
        reproduction = traces / "reproduction.sova-trace"
        write(reproduction, "reproduction")
    report_path.write_bytes(
        canonical_json_bytes({"status": "pass" if observed else "not-confirmed"}) + b"\n"
    )
    return BrowserCampaignArtifacts(
        target_path,
        campaign_path,
        (attempt,),
        reproduction,
        None,
        report_path,
        "pass" if observed else "not-confirmed",
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
    assert observed["coordinator"] == TraceReader(artifacts.trace).events()
    assert all(
        path.name != "attempt-001.sova-trace"
        for path in artifacts.capsule.parent.glob("trace-attachments/*")
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
