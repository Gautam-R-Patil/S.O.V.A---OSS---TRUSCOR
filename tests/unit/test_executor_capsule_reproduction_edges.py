# SPDX-License-Identifier: Apache-2.0
"""Fail-closed contracts for executable chamber capsules."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest

import sova.community.executor_capsule_reproduction as reproduction
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError


def _source() -> dict[str, Any]:
    return {
        "case": {"id": "case:fixture"},
        "grants": [
            {
                "id": "grant:fixture",
                "codecId": "codec:fixture",
                "bindingId": "binding:fixture",
                "argumentSchema": {"type": "object"},
            }
        ],
    }


def _action() -> dict[str, Any]:
    grant = _source()["grants"][0]
    return {
        "order": 0,
        "grantId": grant["id"],
        "codecId": grant["codecId"],
        "bindingId": grant["bindingId"],
        "argumentSchemaDigest": sha256_digest(canonical_json_bytes(grant["argumentSchema"])),
        "plannerArguments": {},
    }


def _plan() -> dict[str, Any]:
    return {
        "schemaVersion": "0.1.0",
        "freshTargetAndSessionRequired": True,
        "freshAuthorizationRequired": True,
        "credentialMaterialIncluded": False,
        "sourceTraceDigest": "sha256:" + "a" * 64,
        "caseId": "case:fixture",
        "actions": [_action()],
    }


def test_json_artifact_scan_ignores_nonattachments_and_malformed_json_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptors = (
        SimpleNamespace(role="trace", mediaType="application/json", payload=b"{}"),
        SimpleNamespace(role="attachment", mediaType="text/plain", payload=b"{}"),
        SimpleNamespace(role="attachment", mediaType="application/json", payload=b"[]"),
        SimpleNamespace(role="attachment", mediaType="application/json", payload=b"{}"),
        SimpleNamespace(
            role="attachment",
            mediaType="application/json",
            payload=b'{"artifactType":"fixture","value":1}',
        ),
    )
    reader = SimpleNamespace(
        verify=lambda _kind: descriptors,
        read_object=lambda descriptor: descriptor.payload,
    )
    monkeypatch.setattr(reproduction, "PackageReader", lambda _path: reader)
    assert reproduction._json_artifacts(cast("Any", SimpleNamespace())) == {
        "fixture": [{"artifactType": "fixture", "value": 1}]
    }


def test_exact_artifact_and_source_contract_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(FormatError, match="exactly one"):
        reproduction._exact_artifact({}, "fixture")
    with pytest.raises(FormatError, match="exactly one"):
        reproduction._exact_artifact({"fixture": [{}, {}]}, "fixture")
    assert reproduction._exact_artifact({"fixture": [{"ok": True}]}, "fixture") == {"ok": True}

    document = {"authorization": {"providerCalls": False, "offensive": False}}
    contract = {
        "schemaVersion": "0.1.0",
        "document": document,
        "sourceDocumentDigest": sha256_digest(canonical_json_bytes(document)),
    }
    monkeypatch.setattr(reproduction, "validate_executor_chamber_document", lambda *_a, **_k: None)
    assert reproduction._source_document(contract) == document
    for changed, message in (
        ({**contract, "schemaVersion": "9"}, "version"),
        ({**contract, "document": []}, "no chamber document"),
        ({**contract, "sourceDocumentDigest": "sha256:" + "0" * 64}, "digest"),
        (
            {
                **contract,
                "document": {},
                "sourceDocumentDigest": sha256_digest(canonical_json_bytes({})),
            },
            "authorization",
        ),
    ):
        with pytest.raises(FormatError, match=message):
            reproduction._source_document(changed)


def test_reproduction_plan_rejects_unbound_case_grant_order_and_arguments() -> None:
    source = _source()
    trace_digests = frozenset({"sha256:" + "a" * 64})
    plan = _plan()
    assert reproduction._validated_actions(plan, source, trace_digests) == [_action()]

    prerequisites = (
        {**plan, "schemaVersion": "9"},
        {**plan, "freshTargetAndSessionRequired": False},
        {**plan, "freshAuthorizationRequired": False},
        {**plan, "credentialMaterialIncluded": True},
        {**plan, "sourceTraceDigest": "sha256:" + "b" * 64},
    )
    for invalid in prerequisites:
        with pytest.raises(FormatError, match="fresh authorized"):
            reproduction._validated_actions(invalid, source, trace_digests)

    with pytest.raises(FormatError, match="case"):
        reproduction._validated_actions({**plan, "caseId": "other"}, source, trace_digests)
    with pytest.raises(FormatError, match="case"):
        reproduction._validated_actions(plan, {**source, "case": []}, trace_digests)
    with pytest.raises(FormatError, match="grants"):
        reproduction._validated_actions(plan, {**source, "grants": {}}, trace_digests)
    actions_values: tuple[object, ...] = ([], {}, [_action() for _ in range(513)])
    for actions in actions_values:
        with pytest.raises(FormatError, match=r"1\.\.512"):
            reproduction._validated_actions({**plan, "actions": actions}, source, trace_digests)

    with pytest.raises(FormatError, match="order"):
        reproduction._validated_actions(
            {**plan, "actions": [{**_action(), "order": 1}]}, source, trace_digests
        )
    for changed in (
        {**_action(), "grantId": "grant:missing"},
        {**_action(), "plannerArguments": []},
        {**_action(), "codecId": "codec:other"},
        {**_action(), "bindingId": "binding:other"},
        {**_action(), "argumentSchemaDigest": "sha256:" + "0" * 64},
        {**_action(), "plannerArguments": {"action": "x"}, "action": "y"},
    ):
        with pytest.raises(FormatError, match="exact admitted grant"):
            reproduction._validated_actions({**plan, "actions": [changed]}, source, trace_digests)


def test_recorded_actions_rebind_only_exact_browser_and_computer_shapes() -> None:
    with pytest.raises(FormatError, match="planner arguments"):
        reproduction._fresh_planner_arguments({"codecId": "codec:fixture", "plannerArguments": []})
    with pytest.raises(FormatError, match="browser action"):
        reproduction._fresh_planner_arguments(
            {"codecId": reproduction._BROWSER_CODEC, "plannerArguments": {}}
        )
    browser = reproduction._fresh_planner_arguments(
        {
            "codecId": reproduction._BROWSER_CODEC,
            "plannerArguments": {
                "action": "browser.click",
                "arguments": {"ref": "e1"},
                "observationDigest": "sha256:" + "a" * 64,
            },
        }
    )
    assert browser["observationDigest"] == reproduction._OBSERVATION_DIGEST_PLACEHOLDER

    with pytest.raises(FormatError, match="computer action"):
        reproduction._fresh_planner_arguments(
            {"codecId": reproduction._COMPUTER_CODEC, "plannerArguments": {}}
        )
    computer = reproduction._fresh_planner_arguments(
        {
            "codecId": reproduction._COMPUTER_CODEC,
            "plannerArguments": {
                "action": "computer.click",
                "arguments": {"x": 1, "y": 2},
                "binding": {"window": "old"},
                "observationDigest": "sha256:" + "a" * 64,
            },
        }
    )
    assert computer["binding"] == reproduction._COMPUTER_BINDING_PLACEHOLDER
    assert computer["observationDigest"] == reproduction._OBSERVATION_DIGEST_PLACEHOLDER
    assert reproduction._fresh_planner_arguments(
        {"codecId": "codec:fixture", "plannerArguments": {"value": 1}}
    ) == {"value": 1}
