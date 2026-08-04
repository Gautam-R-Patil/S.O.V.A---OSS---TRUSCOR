# SPDX-License-Identifier: Apache-2.0
"""Adversarial and refusal-path coverage for Topics 21 and 23."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

import sova.community.config as community_config
import sova.local_mcp.approval as approval_module
import sova.local_mcp.tools as tool_module
from sova.community import (
    STANDARD_ARENA_PROFILE,
    ArenaCase,
    ArenaMatch,
    CTFScenario,
    LeaderboardSubmission,
    ReplayClipSpec,
    ReplayFrame,
    build_ctf_catalog,
    build_static_leaderboard,
    issue_probe_response,
    run_local_arena,
    verify_probe_response,
)
from sova.formats import canonical_json_bytes, strict_json_loads
from sova.formats.errors import FormatError
from sova.local_mcp import (
    LocalApprovalStore,
    LocalSOVAMCPServer,
    LocalToolContext,
    create_control_key,
    dispatch_local_tool,
    load_control_key,
    serve_stdio,
)
from sova.local_mcp.model import InvocationDescriptor, LocalToolDefinition
from sova.models import ScriptedModel, ScriptedTurn
from sova.rehearsal import prepare_rehearsal_environment
from sova.runtime import standard_profile
from sova.trace import (
    generate_ed25519_keypair,
    sign_dsse_payload,
    verify_dsse_payload,
)
from sova.workflows import run_complete_demo

if TYPE_CHECKING:
    from collections.abc import Callable

    from pytest import MonkeyPatch

_PROBE_TYPE = "application/vnd.sova.probe-response+json;version=0.1"


def _invocation(target: str = "sleeper") -> InvocationDescriptor:
    return InvocationDescriptor(
        "sova.detonate",
        {"target": target, "output": "out"},
        target,
        ("exact",),
        ("sova.detonate",),
        {"maxInvocations": 1},
        60,
        ("fixture risk",),
    )


def _store(tmp_path: Path) -> LocalApprovalStore:
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return LocalApprovalStore(tmp_path / "control", b"k" * 32, workspace=workspace)


def _response(value: dict[str, Any] | None) -> dict[str, Any]:
    assert value is not None
    return value


def _approve_call(
    context: LocalToolContext, tool: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    first = dispatch_local_tool(context, tool, arguments)
    challenge = first["challenge"]
    context.approval_store.approve(
        challenge["challengeId"],
        exact_phrase=challenge["exactPhrase"],
        reviewed_effects=True,
        human_confirmed=True,
    )
    return dispatch_local_tool(
        context,
        tool,
        {**arguments, "approvalChallengeId": challenge["challengeId"]},
    )


def test_control_key_and_approval_record_refusals(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    key_path = tmp_path / "key"
    create_control_key(key_path)
    assert len(load_control_key(key_path)) == 32
    with pytest.raises(FormatError, match="already exists"):
        create_control_key(key_path)
    short = tmp_path / "short"
    short.write_bytes(b"short")
    with pytest.raises(FormatError, match="at least 32"):
        load_control_key(short)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with pytest.raises(FormatError, match="outside"):
        LocalApprovalStore(workspace / "control", b"k" * 32, workspace=workspace)
    with pytest.raises(FormatError, match="at least 32"):
        LocalApprovalStore(tmp_path / "control-short", b"short", workspace=workspace)

    store = LocalApprovalStore(tmp_path / "control", b"k" * 32, workspace=workspace)
    with pytest.raises(FormatError, match="identifier"):
        store.challenge_record("../bad")
    with pytest.raises(FormatError, match="TTL"):
        store.challenge(_invocation(), ttl=timedelta(milliseconds=1))
    now = datetime(2026, 8, 4, 12, tzinfo=UTC)
    challenge = store.challenge(_invocation(), now=now)
    with pytest.raises(FormatError, match="phrase"):
        store.approve(
            challenge["challengeId"],
            exact_phrase="wrong",
            reviewed_effects=True,
            human_confirmed=True,
            now=now,
        )
    with pytest.raises(FormatError, match="human"):
        store.approve(
            challenge["challengeId"],
            exact_phrase=challenge["exactPhrase"],
            reviewed_effects=False,
            human_confirmed=True,
            now=now,
        )
    with pytest.raises(FormatError, match="expired"):
        store.approve(
            challenge["challengeId"],
            exact_phrase=challenge["exactPhrase"],
            reviewed_effects=True,
            human_confirmed=True,
            now=now + timedelta(minutes=6),
        )

    malformed = store.challenge(_invocation(), now=now)
    record = tmp_path / "control" / "challenges" / f"{malformed['challengeId']}.json"
    record.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="malformed"):
        store.challenge_record(malformed["challengeId"])

    write_failure = store.challenge(_invocation(), now=now)
    original_write = Path.write_bytes

    def fail_token_write(path: Path, data: bytes) -> int:
        if path.parent.name == "tokens":
            raise OSError("fixture")
        return original_write(path, data)

    monkeypatch.setattr(Path, "write_bytes", fail_token_write)
    with pytest.raises(FormatError, match="write failed"):
        store.approve(
            write_failure["challengeId"],
            exact_phrase=write_failure["exactPhrase"],
            reviewed_effects=True,
            human_confirmed=True,
            now=now,
        )


def test_approval_token_tampering_scope_expiry_and_policy(tmp_path: Path) -> None:
    now = datetime(2026, 8, 4, 12, tzinfo=UTC)
    store = _store(tmp_path)

    def token_for(invocation: InvocationDescriptor) -> tuple[str, Path]:
        challenge = store.challenge(invocation, ttl=timedelta(seconds=2), now=now)
        store.approve(
            challenge["challengeId"],
            exact_phrase=challenge["exactPhrase"],
            reviewed_effects=True,
            human_confirmed=True,
            now=now,
        )
        return (
            challenge["challengeId"],
            tmp_path / "control" / "tokens" / f"{challenge['challengeId']}.json",
        )

    identifier, path = token_for(_invocation())
    token = json.loads(path.read_text(encoding="utf-8"))
    token["signature"] = "bad"
    path.write_text(json.dumps(token), encoding="utf-8")
    with pytest.raises(FormatError, match="invalid"):
        store.consume(identifier, _invocation(), now=now)

    identifier, _path = token_for(_invocation())
    with pytest.raises(FormatError, match="does not match"):
        store.consume(identifier, _invocation("different"), now=now)

    identifier, _path = token_for(_invocation())
    with pytest.raises(FormatError, match="expired"):
        store.consume(identifier, _invocation(), now=now + timedelta(seconds=3))

    identifier, path = token_for(_invocation())
    token = json.loads(path.read_text(encoding="utf-8"))
    unsigned = {**token, "reviewedEffects": False}
    unsigned.pop("signature")
    token = {**unsigned, "signature": store._sign(unsigned)}
    path.write_text(json.dumps(token), encoding="utf-8")
    with pytest.raises(FormatError, match="policy"):
        store.consume(identifier, _invocation(), now=now)


def test_local_mcp_server_protocol_refusal_and_success(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = LocalToolContext(
        workspace,
        workspace / "evidence",
        LocalApprovalStore(tmp_path / "control", b"k" * 32, workspace=workspace),
        sensitive_mapping_allowed=True,
    )
    server = LocalSOVAMCPServer(context)
    assert _response(server.handle({"jsonrpc": "1.0", "id": 1}))["error"]["code"] == -32600
    assert (
        _response(server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": []}))[
            "error"
        ]["code"]
        == -32602
    )
    assert (
        _response(server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))["error"][
            "code"
        ]
        == -32002
    )
    initialized = _response(server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
    assert initialized["result"]["protocolVersion"] == "2025-11-25"
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    listed = _response(server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    assert listed["result"]["tools"]
    assert (
        _response(server.handle({"jsonrpc": "2.0", "id": 3, "method": "unknown"}))["error"]["code"]
        == -32601
    )
    assert (
        _response(
            server.handle(
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": 1}}
            )
        )["error"]["code"]
        == -32602
    )
    tool_error = _response(
        server.handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "unknown", "arguments": {}},
            }
        )
    )
    assert tool_error["error"]["data"]["sovaCode"] == "SOVA-LOCAL-MCP-TOOL"
    success = _response(
        server.handle(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "sova.map", "arguments": {"root": "."}},
            }
        )
    )
    assert success["result"]["structuredContent"]["artifactType"] == "sova.mcp-tool-result"

    stream = io.BytesIO(
        b"[]\nnot-json\n"
        b'{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    )
    output = io.BytesIO()
    serve_stdio(context, input_stream=stream, output_stream=output)
    rows = [json.loads(item) for item in output.getvalue().splitlines()]
    assert rows[0]["error"]["data"]["sovaCode"] == "SOVA-MCP-REQUEST"
    assert rows[1]["error"]["code"] == -32700
    assert rows[2]["result"]["serverInfo"]["name"] == "sova-oss-local"


def test_local_mcp_safe_and_gated_dispatch_paths(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    store = LocalApprovalStore(tmp_path / "control", b"k" * 32, workspace=workspace)
    context = LocalToolContext(workspace, workspace / "evidence", store)
    with pytest.raises(FormatError, match="mapping consent"):
        dispatch_local_tool(context, "sova.map", {})
    with pytest.raises(FormatError, match="pinned manifest"):
        dispatch_local_tool(context, "sova.verify", {"path": "x", "unknown": True})
    with pytest.raises(FormatError, match="escapes"):
        dispatch_local_tool(context, "sova.verify", {"path": "../outside"})
    with pytest.raises(FormatError, match="unknown safe"):
        tool_module._safe_dispatch(context, "sova.unknown", {})

    context = LocalToolContext(
        workspace, workspace / "evidence", store, sensitive_mapping_allowed=True
    )
    assert dispatch_local_tool(context, "sova.map", {})["artifactType"] == "sova.mcp-tool-result"
    demo = run_complete_demo(workspace / "demo", profile=standard_profile())
    trace_relative = demo.trace.relative_to(workspace).as_posix()
    capsule_relative = demo.capsule.relative_to(workspace).as_posix()
    assert dispatch_local_tool(context, "sova.verify", {"path": capsule_relative})["result"]
    assert dispatch_local_tool(context, "sova.forensics", {"trace": trace_relative})["result"]
    assert dispatch_local_tool(
        context, "sova.check", {"target": "synthetic-sleeper", "output": "check"}
    )["result"]

    registry = workspace / "registry"
    registry.mkdir()
    (registry / "index.json").write_text(
        '{"index":{"entries":[{"id":"alpha"},{"id":"beta"}]}}', encoding="utf-8"
    )
    monkeypatch.setattr(tool_module, "verify_registry", lambda _root: {"accepted": True})
    search = dispatch_local_tool(
        context,
        "sova.registry.search",
        {"registry": "registry", "query": "alpha", "limit": 1},
    )
    assert len(search["result"]["matches"]) == 1
    with pytest.raises(FormatError, match="limit"):
        tool_module._registry_search(context, {"registry": "registry", "query": "", "limit": True})

    detonation = _approve_call(
        context, "sova.detonate", {"target": "sleeper", "output": "detonation"}
    )
    assert detonation["executed"] is True
    rehearsal_source = workspace / "rehearsal-source"
    rehearsal_source.mkdir()
    rehearsal_workspace = workspace / "rehearsal"
    prepare_rehearsal_environment(rehearsal_source, rehearsal_workspace)
    rehearsal = _approve_call(
        context,
        "sova.rehearse",
        {
            "workspace": "rehearsal",
            "trace": "rehearsal.sova-trace",
            "specification": {
                "task": "write fixture",
                "agentId": "fixture",
                "authorizationConfirmed": True,
                "actions": [
                    {
                        "id": "write",
                        "actorId": "fixture",
                        "kind": "file.write",
                        "target": "result.txt",
                        "operation": "write",
                        "parameters": {"content": "safe"},
                        "materialStep": False,
                    }
                ],
            },
        },
    )
    assert rehearsal["executed"] is True


def _resigned_probe(
    mutator: Callable[[dict[str, Any]], None],
) -> tuple[dict[str, Any], datetime, str]:
    now = datetime(2026, 8, 4, 12, tzinfo=UTC)
    key = generate_ed25519_keypair()
    document = issue_probe_response(
        key,
        subject="fixture",
        nonce="nonce",
        scope=("scope",),
        assertions=({},),
        observations=({},),
        conformance_status="passed",
        now=now,
    )
    payload = verify_dsse_payload(
        document["envelope"], key.public_key, expected_payload_type=_PROBE_TYPE
    )
    body = strict_json_loads(payload)
    assert isinstance(body, dict)
    mutator(body)
    document["envelope"] = sign_dsse_payload(_PROBE_TYPE, canonical_json_bytes(body), key)
    return document, now, key.key_id


def test_probe_issue_and_verification_refusal_matrix() -> None:
    key = generate_ed25519_keypair()
    now = datetime(2026, 8, 4, 12, tzinfo=UTC)
    for subject, ttl, status, when in (
        ("", timedelta(minutes=1), "passed", now),
        ("x", timedelta(0), "passed", now),
        ("x", timedelta(minutes=1), "bad", now),
        ("x", timedelta(minutes=1), "passed", now.replace(tzinfo=None)),
    ):
        with pytest.raises(FormatError):
            issue_probe_response(
                key,
                subject=subject,
                nonce="nonce",
                scope=("scope",),
                assertions=(),
                observations=(),
                conformance_status=status,
                now=when,
                ttl=ttl,
            )

    with pytest.raises(FormatError, match="malformed"):
        verify_probe_response({}, expected_nonce="n", expected_scope=("s",), now=now)
    good, _now, key_id = _resigned_probe(lambda _body: None)
    bad_key = json.loads(json.dumps(good))
    bad_key["publicKey"]["keyid"] = "sha256:" + "0" * 64
    with pytest.raises(FormatError, match="inconsistent"):
        verify_probe_response(bad_key, expected_nonce="nonce", expected_scope=("scope",), now=now)
    with pytest.raises(FormatError, match="pinned"):
        verify_probe_response(
            good,
            expected_nonce="nonce",
            expected_scope=("scope",),
            now=now,
            required_key_id="sha256:" + "1" * 64,
        )
    with pytest.raises(FormatError, match="timezone"):
        verify_probe_response(
            good,
            expected_nonce="nonce",
            expected_scope=("scope",),
            now=now.replace(tzinfo=None),
        )
    assert key_id == good["publicKey"]["keyid"]

    mutations: tuple[tuple[Callable[[dict[str, Any]], None], str], ...] = (
        (lambda body: body.update({"issuedAt": "bad"}), "time"),
        (lambda body: body.update({"expiresAt": body["issuedAt"]}), "freshness"),
        (lambda body: body.update({"nonce": "other"}), "nonce"),
        (lambda body: body.update({"scope": ["other"]}), "scope"),
        (lambda body: body.update({"conformanceStatus": "bad"}), "status"),
        (lambda body: body.update({"sovaObservations": "bad"}), "evidence"),
    )
    for mutation, _expected in mutations:
        document, current, _key = _resigned_probe(mutation)
        with pytest.raises(FormatError):
            verify_probe_response(
                document,
                expected_nonce="nonce",
                expected_scope=("scope",),
                now=current,
            )


def test_arena_ctf_leaderboard_and_media_rejections(tmp_path: Path) -> None:
    with pytest.raises(FormatError, match="at least one"):
        run_local_arena(STANDARD_ARENA_PROFILE, (), {}, tmp_path / "empty")
    case = ArenaCase("case", "seed", "defend", "marker")
    with pytest.raises(FormatError, match="must differ"):
        run_local_arena(
            STANDARD_ARENA_PROFILE,
            (ArenaMatch("same", "same", case),),
            {"same": ScriptedModel([ScriptedTurn("seed", "x")])},
            tmp_path / "same",
        )
    with pytest.raises(FormatError, match="unavailable"):
        run_local_arena(
            STANDARD_ARENA_PROFILE,
            (ArenaMatch("a", "b", case),),
            {},
            tmp_path / "missing",
        )

    for values in (
        ("id", "title", "impossible", "bundled-synthetic"),
        ("id", "title", "beginner", "unsafe-auto"),
        ("", "title", "beginner", "bundled-synthetic"),
    ):
        with pytest.raises(FormatError):
            CTFScenario(
                values[0],
                values[1],
                values[2],
                "source",
                "url",
                "licence",
                values[3],
                tmp_path / "none.sova",
                "explain",
            )
    with pytest.raises(FormatError, match="requires scenarios"):
        build_ctf_catalog((), tmp_path / "ctf.json")

    with pytest.raises(FormatError, match="ranks technical"):
        LeaderboardSubmission(
            "person", "x", "1", "p", "d", 0, 1, tmp_path / "a", tmp_path / "t", "k"
        )
    with pytest.raises(FormatError, match="identity"):
        LeaderboardSubmission("model", "", "1", "p", "d", 0, 1, tmp_path / "a", tmp_path / "t", "k")
    with pytest.raises(FormatError, match="score"):
        LeaderboardSubmission(
            "model", "x", "1", "p", "d", 2, 1, tmp_path / "a", tmp_path / "t", "k"
        )
    with pytest.raises(FormatError, match="submissions"):
        build_static_leaderboard((), tmp_path / "leaderboard", methodology_snapshot="")

    with pytest.raises(FormatError, match="links and frames"):
        ReplayClipSpec("simulation", "a", "v", ())
    with pytest.raises(FormatError, match="too many"):
        ReplayClipSpec("simulation", "a", "v", tuple(ReplayFrame("event", "x") for _ in range(13)))
    with pytest.raises(FormatError, match="finding class"):
        ReplayClipSpec("unknown", "a", "v", (ReplayFrame("event", "x"),))
    with pytest.raises(FormatError, match="clearance"):
        ReplayClipSpec(
            "real-disclosed-finding",
            "a",
            "v",
            (ReplayFrame("event", "x"),),
            component_name="name",
            disclosure_cleared=False,
        )


def test_approval_timestamp_parser_edges() -> None:
    for value in (None, "not-time", "2026-08-04T12:00:00"):
        with pytest.raises(FormatError, match="timestamp"):
            approval_module._parse_timestamp(value)


def test_mcp_contract_and_path_validation_edges(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    with pytest.raises(FormatError, match="identity"):
        LocalToolDefinition(
            "bad",
            "",
            {},
            {},
            read_only=True,
            destructive=False,
            open_world=False,
            gated=False,
            side_effects=(),
        )
    with pytest.raises(FormatError, match="cannot claim"):
        LocalToolDefinition(
            "sova.bad",
            "bad",
            {},
            {},
            read_only=True,
            destructive=False,
            open_world=False,
            gated=True,
            side_effects=(),
        )
    invalid_invocations: tuple[Callable[[], object], ...] = (
        lambda: InvocationDescriptor(
            "sova.x", {}, "target", ("s",), ("a",), {}, 1, ("r",), ownership="third-party"
        ),
        lambda: InvocationDescriptor("bad", {}, "", ("s",), ("a",), {}, 1, ("r",)),
        lambda: InvocationDescriptor("sova.x", {}, "t", ("s",), ("a",), {}, 0, ("r",)),
        lambda: InvocationDescriptor("sova.x", {}, "t", (), ("a",), {}, 1, ("r",)),
    )
    for invocation in invalid_invocations:
        with pytest.raises(FormatError):
            invocation()

    workspace = tmp_path / "workspace"
    with pytest.raises(FormatError, match="workspace must exist"):
        LocalToolContext(
            workspace,
            tmp_path / "evidence",
            LocalApprovalStore(tmp_path / "control", b"k" * 32, workspace=workspace),
        )
    workspace.mkdir()
    context = LocalToolContext(
        workspace,
        workspace / "evidence",
        LocalApprovalStore(tmp_path / "control-2", b"k" * 32, workspace=workspace),
    )
    for value in ("", "bad\\path", "bad\x00path", "/absolute"):
        with pytest.raises(FormatError, match="path"):
            tool_module._relative_path(workspace, value)
    with pytest.raises(FormatError, match="does not exist"):
        tool_module._relative_path(workspace, "missing", must_exist=True)
    with pytest.raises(FormatError, match="non-empty"):
        tool_module._string({}, "target")

    registry = workspace / "registry"
    registry.mkdir()
    monkeypatch.setattr(tool_module, "verify_registry", lambda _root: {"accepted": True})
    (registry / "index.json").write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="index is malformed"):
        tool_module._registry_search(context, {"registry": "registry"})
    (registry / "index.json").write_text('{"index":{"entries":{}}}', encoding="utf-8")
    with pytest.raises(FormatError, match="entries are malformed"):
        tool_module._registry_search(context, {"registry": "registry"})


def test_strict_community_document_helpers_and_duplicate_participant(tmp_path: Path) -> None:
    invalid_integer: object = True
    invalid_calls: tuple[Callable[[], object], ...] = (
        lambda: community_config._object([], "$"),
        lambda: community_config._object({1: "bad"}, "$"),
        lambda: community_config._sequence({}, "$"),
        lambda: community_config._text("", "$"),
        lambda: community_config._integer(invalid_integer, "$"),
        lambda: community_config._boolean(1, "$"),
        lambda: community_config._fields({}, "$", required=("needed",)),
        lambda: community_config._fields({"extra": 1}, "$", required=()),
    )
    for call in invalid_calls:
        with pytest.raises(FormatError):
            call()

    document = {
        "profile": {
            "id": STANDARD_ARENA_PROFILE.identifier,
            "version": STANDARD_ARENA_PROFILE.version,
            "standard": True,
        },
        "participants": [
            {"id": "same", "modelId": "m", "turns": []},
            {"id": "same", "modelId": "m", "turns": []},
        ],
        "matches": [],
    }
    with pytest.raises(FormatError, match="duplicated"):
        community_config.run_arena_document(document, tmp_path / "out")
