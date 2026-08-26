# SPDX-License-Identifier: Apache-2.0
"""Defensive validation and parser edges for the P3 security adapter boundary."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

import sova.adapters.security_parsers as parser_module
from sova.adapters.security_catalog import (
    assert_catalog_ids,
    get_security_adapter,
)
from sova.adapters.security_contracts import (
    AdapterAdmission,
    AdapterInvocation,
    AdapterRunReport,
    AdapterTransport,
    ExternalToolEnvelope,
    ExternalTransferDecision,
    ExternalTransferGate,
    ExternalTransferRequest,
    ExternalTrust,
    NormalizedObservation,
    OutputSource,
    PrivacyDefaults,
    RawArtifact,
    ResourceBounds,
)
from sova.adapters.security_parsers import (
    compare_reproduction,
    normalize_external_envelope,
    normalize_security_output,
)
from sova.formats import sha256_digest
from sova.formats.errors import FormatError

_DIGEST = "sha256:" + "a" * 64
_OTHER_DIGEST = "sha256:" + "b" * 64
_EXECUTABLE_DIGEST = "sha256:" + "e" * 64


def _invocation(adapter_id: str) -> AdapterInvocation:
    descriptor = get_security_adapter(adapter_id)
    evidence = f"{descriptor.tool_name} {descriptor.tool_version}".encode()
    return AdapterInvocation(
        identifier="defensive-edge-run",
        descriptor_id=adapter_id,
        target_id="sova:sandbox:defensive-edge",
        target="owned-target",
        target_predicate=descriptor.target_predicates[0],
        target_profile_digest=_DIGEST,
        target_generation=_OTHER_DIGEST,
        executable_path="C:/fixture/tool.exe",
        observed_tool_version=descriptor.tool_version,
        version_evidence_digest=sha256_digest(evidence),
        output_path="output.json",
        config_path="config.json",
        config_digest="sha256:" + "c" * 64,
        ruleset_path="rules.json",
        ruleset_digest="sha256:" + "d" * 64,
        disclosure_gate_id="sova:disclosure:defensive-edge",
        disclosure_gate_digest="sha256:" + "f" * 64,
    )


def _observation() -> NormalizedObservation:
    descriptor = get_security_adapter("adapter.syft")
    return normalize_security_output(
        descriptor,
        _invocation(descriptor.identifier),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=b'{"artifacts":[{"id":"pkg-1","name":"owned"}]}',
        media_type="application/json",
    )[0]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"identifier": "bad"}, "identifier"),
        ({"tool_name": ""}, "tool name"),
        ({"tool_version": "bad version"}, "exact version"),
        ({"executable_names": ()}, "bare names"),
        ({"executable_names": ("bad/name",)}, "bare names"),
        ({"executable_digest_policy": "optional"}, "SHA-256"),
        ({"license_expression": ""}, "licence"),
        ({"source_url": "http://invalid"}, "HTTPS source"),
        ({"release_url": "http://invalid"}, "HTTPS release"),
        ({"platforms": ()}, "platforms"),
        ({"platforms": ("plan9",)}, "platforms"),
        ({"target_predicates": ()}, "lists are empty"),
        ({"output_media_types": ("invalid",)}, "media type"),
        ({"required_effect": "unknown"}, "effect"),
        ({"network_requirement": "unknown"}, "network"),
        ({"parser_id": ""}, "parser identity"),
        ({"parser_version": "bad version"}, "parser identity"),
        ({"argv_template": ("--no-executable",)}, "start with the executable"),
        ({"argv_template": ("{executable}", "{unknown}")}, "unknown token"),
        ({"ruleset_pin": ""}, "ruleset pin"),
        ({"config_pin": ""}, "configuration pin"),
        ({"environment": (("A", "1"), ("A", "2"))}, "unique"),
        ({"accepted_result_exit_codes": ()}, "include zero"),
        ({"accepted_result_exit_codes": (1,)}, "include zero"),
        ({"accepted_result_exit_codes": (0, True)}, "byte-sized"),
        ({"accepted_result_exit_codes": (0, 256)}, "byte-sized"),
    ],
)
def test_descriptor_rejects_unsafe_contract_variants(changes: dict[str, Any], message: str) -> None:
    with pytest.raises(FormatError, match=message):
        replace(get_security_adapter("adapter.syft"), **changes)


def test_legal_hold_descriptor_requires_an_explicit_reason() -> None:
    descriptor = get_security_adapter("adapter.nmap")
    assert descriptor.admission == AdapterAdmission.LEGAL_HOLD
    with pytest.raises(FormatError, match="requires a reason"):
        replace(descriptor, legal_note=None)


@pytest.mark.parametrize(
    "changes",
    [
        {"timeout_seconds": 0},
        {"timeout_seconds": 3601},
        {"max_output_bytes": 1},
        {"max_output_bytes": 64 * 1024 * 1024 + 1},
        {"max_findings": 0},
        {"max_findings": 100_001},
        {"max_processes": 0},
        {"max_processes": 1025},
        {"max_network_requests": -1},
    ],
)
def test_resource_bounds_reject_values_outside_portable_limits(changes: dict[str, int]) -> None:
    bounds = ResourceBounds(timeout_seconds=1, max_output_bytes=1024, max_findings=1)
    with pytest.raises(FormatError):
        replace(bounds, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"telemetry": True},
        {"remote_generation": True},
        {"uploads": True},
        {"implicit_pulls": True},
        {"auto_update": True},
        {"unreviewed_templates": True},
        {"external_transfer_requires_disclosure_gate": False},
    ],
)
def test_privacy_defaults_fail_closed(changes: dict[str, bool]) -> None:
    with pytest.raises(FormatError, match="disable external disclosure"):
        PrivacyDefaults(**changes)


def test_disclosure_request_and_decision_validate_every_binding() -> None:
    request = ExternalTransferRequest(
        target_id="sova:sandbox:defensive-edge",
        destination="https://owned.invalid",
        purpose="owned fixture",
        data_classes=("synthetic",),
        authorization_reference="sova:authorization:defensive-edge",
        human_reviewed=True,
        retention_reviewed=True,
    )
    allowed = ExternalTransferGate().assess(request)
    denied = ExternalTransferGate().assess(replace(request, human_reviewed=False))
    with pytest.raises(FormatError, match="incomplete"):
        replace(request, purpose="")
    with pytest.raises(FormatError, match="data classes"):
        replace(request, data_classes=())
    with pytest.raises(FormatError, match="decision ID"):
        replace(allowed, identifier="invalid")
    with pytest.raises(FormatError, match="request digest"):
        replace(allowed, request_digest="invalid")
    with pytest.raises(FormatError, match="allowed decisions"):
        replace(allowed, reasons=("contradiction",))
    with pytest.raises(FormatError, match="allowed decisions"):
        replace(denied, reasons=())
    assert allowed.to_mapping()["method"] == "sova.adapter-disclosure-gate/0.1"


@pytest.mark.parametrize(
    "changes",
    [
        {"identifier": "Invalid ID"},
        {"target": ""},
        {"target_profile_digest": "invalid"},
        {"output_path": ""},
        {"config_path": "config.json", "config_digest": None},
        {"config_path": None, "config_digest": _DIGEST},
        {"ruleset_path": "rules.json", "ruleset_digest": None},
        {"ruleset_path": None, "ruleset_digest": _DIGEST},
        {"disclosure_gate_id": ""},
        {"disclosure_gate_id": "sova:disclosure:test", "disclosure_gate_digest": None},
        {"disclosure_gate_id": None, "disclosure_gate_digest": _DIGEST},
    ],
)
def test_invocation_rejects_incomplete_or_unbound_inputs(changes: dict[str, Any]) -> None:
    with pytest.raises(FormatError):
        replace(_invocation("adapter.syft"), **changes)


def test_raw_observation_and_report_reject_trust_or_binding_inflation() -> None:
    raw = RawArtifact(
        digest=_DIGEST,
        media_type="application/json",
        size=2,
        complete=True,
        source=OutputSource.STDOUT,
    )
    with pytest.raises(FormatError, match="identity"):
        replace(raw, digest="invalid")
    with pytest.raises(FormatError, match="identity"):
        replace(raw, size=-1)
    with pytest.raises(FormatError, match="media type"):
        replace(raw, media_type="invalid")

    observation = _observation()
    with pytest.raises(FormatError, match="digest"):
        replace(observation, stable_fingerprint="invalid")
    with pytest.raises(FormatError, match="cannot confirm"):
        replace(observation, finding_confirmed=True)
    with pytest.raises(FormatError, match="cannot confirm"):
        replace(observation, independently_reproduced=True)
    with pytest.raises(FormatError, match="severity"):
        replace(observation, severity="urgent")
    with pytest.raises(FormatError, match="confidence"):
        replace(observation, confidence="certain")

    report = AdapterRunReport(
        invocation_id="defensive-edge-run",
        descriptor_id=observation.adapter_id,
        descriptor_digest=observation.adapter_digest,
        executable_digest=observation.executable_digest,
        outcome_status="completed",
        infrastructure_failure=False,
        cleanup_verified=True,
        trace_path="trace.sova-trace",
        trace_digest=_OTHER_DIGEST,
        raw_artifact=observation.raw,
        observations=(observation,),
    )
    assert report.to_mapping()["rawArtifact"]["digest"] == observation.raw.digest
    with pytest.raises(FormatError, match="digest"):
        replace(report, trace_digest="invalid")
    with pytest.raises(FormatError, match="outcome"):
        replace(report, outcome_status="unknown")
    with pytest.raises(FormatError, match="completed run"):
        replace(report, infrastructure_failure=True)
    with pytest.raises(FormatError, match="cleanup failure"):
        replace(report, cleanup_verified=False)
    with pytest.raises(FormatError, match="unique"):
        replace(report, limitations=("same", "same"))
    with pytest.raises(FormatError, match="bindings"):
        replace(report, observations=(replace(observation, adapter_id="adapter.other"),))


def test_generic_envelope_rejects_process_identity_and_trust_inflation() -> None:
    valid = ExternalToolEnvelope(
        transport=AdapterTransport.HTTP,
        producer="owned-provider",
        raw_digest=_DIGEST,
        schema=None,
        summary=None,
        evidence_references=(),
    )
    normalized = normalize_external_envelope(valid)
    assert normalized["schemaDigest"] is None
    assert normalized["summaryPresent"] is False
    with pytest.raises(FormatError, match="stdio or HTTP"):
        replace(valid, transport=AdapterTransport.PROCESS)
    with pytest.raises(FormatError, match="identity"):
        replace(valid, producer="")
    with pytest.raises(FormatError, match="identity"):
        replace(valid, raw_digest="invalid")
    inflated_fields: tuple[dict[str, Any], ...] = (
        {"schema_trust": ExternalTrust.SOVA_VALIDATED},
        {"summary_trust": ExternalTrust.SOVA_VALIDATED},
        {"evidence_trust": ExternalTrust.SOVA_VALIDATED},
    )
    for changes in inflated_fields:
        with pytest.raises(FormatError, match="begin untrusted"):
            replace(valid, **changes)


def test_catalog_lookup_and_parity_fail_with_structured_errors() -> None:
    with pytest.raises(FormatError, match="not present"):
        get_security_adapter("adapter.missing")
    assert_catalog_ids(("adapter.syft",))
    with pytest.raises(FormatError, match="required adapters"):
        assert_catalog_ids(("adapter.missing",))


@pytest.mark.parametrize(
    ("adapter_id", "raw", "message"),
    [
        ("adapter.zap", b"[]", "ZAP JSON root"),
        ("adapter.nuclei", b"[]\n", "JSONL record"),
        ("adapter.pyrit", b'{"exportSchema":"wrong"}', "pinned SOVA export"),
        ("adapter.promptfoo", b"[]", "promptfoo JSON root"),
        ("adapter.trivy", b"[]", "Trivy JSON root"),
        ("adapter.syft", b"[]", "Syft JSON root"),
        ("adapter.grype", b"[]", "Grype JSON root"),
        ("adapter.osv-scanner", b"[]", "OSV-Scanner JSON root"),
        ("adapter.gitleaks", b"{}", "Gitleaks JSON root"),
        ("adapter.semgrep", b"[]", "Semgrep JSON root"),
    ],
)
def test_promoted_parsers_reject_wrong_root_shapes(
    adapter_id: str, raw: bytes, message: str
) -> None:
    descriptor = get_security_adapter(adapter_id)
    with pytest.raises(FormatError, match=message):
        normalize_security_output(
            descriptor,
            _invocation(adapter_id),
            executable_digest=_EXECUTABLE_DIGEST,
            raw=raw,
            media_type=descriptor.output_media_types[0],
        )


def test_xml_parser_rejects_entities_size_nodes_and_malformed_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = get_security_adapter("adapter.schemathesis")
    invocation = _invocation(descriptor.identifier)

    def normalize(raw: bytes) -> tuple[NormalizedObservation, ...]:
        return normalize_security_output(
            descriptor,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=raw,
            media_type=descriptor.output_media_types[0],
        )

    with pytest.raises(FormatError, match="entity declarations"):
        normalize(b'<!DOCTYPE x [<!ENTITY y "z">]><testsuite/>')
    with pytest.raises(FormatError, match="invalid XML"):
        normalize(b"<testsuite>")
    monkeypatch.setattr(parser_module, "_MAX_XML_BYTES", 4)
    with pytest.raises(FormatError, match="byte limit"):
        normalize(b"<testsuite/>")
    monkeypatch.setattr(parser_module, "_MAX_XML_BYTES", 1024)
    monkeypatch.setattr(parser_module, "_MAX_XML_NODES", 1)
    with pytest.raises(FormatError, match="node limit"):
        normalize(b"<testsuite><testcase/></testsuite>")


def test_parser_state_alternatives_and_empty_reproduction_are_explicit() -> None:
    schemathesis = get_security_adapter("adapter.schemathesis")
    passed = normalize_security_output(
        schemathesis,
        _invocation(schemathesis.identifier),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=b'<testsuite><testcase name="owned"/></testsuite>',
        media_type=schemathesis.output_media_types[0],
    )
    assert passed[0].state.value == "tool-asserted-pass"
    errored = normalize_security_output(
        schemathesis,
        _invocation(schemathesis.identifier),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=b'<testsuite><testcase name="owned"><error message="boom"/></testcase></testsuite>',
        media_type=schemathesis.output_media_types[0],
    )
    assert errored[0].severity == "high"

    garak = get_security_adapter("adapter.garak")
    garak_output = normalize_security_output(
        garak,
        _invocation(garak.identifier),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=(
            b'{"entry_type":"ignored"}\n'
            b'{"entry_type":"eval","passed":true}\n'
            b'{"entry_type":"eval","score":1}\n'
            b'{"entry_type":"eval","score":0}\n'
            b'{"entry_type":"eval"}\n'
        ),
        media_type=garak.output_media_types[0],
    )
    assert [item.state.value for item in garak_output] == [
        "tool-asserted-pass",
        "tool-asserted-failure",
        "tool-asserted-pass",
        "inconclusive",
    ]
    assert compare_reproduction((), ())["independentlyReproduced"] is False


def test_jsonl_limits_and_normalization_bounds_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nuclei = get_security_adapter("adapter.nuclei")
    invocation = _invocation(nuclei.identifier)
    monkeypatch.setattr(parser_module, "_MAX_JSONL_LINES", 1)
    with pytest.raises(FormatError, match="record limit"):
        normalize_security_output(
            nuclei,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b"{}\n{}\n",
            media_type=nuclei.output_media_types[0],
        )
    with pytest.raises(FormatError, match="descriptor do not match"):
        normalize_security_output(
            nuclei,
            replace(invocation, descriptor_id="adapter.syft"),
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b"{}\n",
            media_type=nuclei.output_media_types[0],
        )
    with pytest.raises(FormatError, match="not admitted"):
        normalize_security_output(
            nuclei,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b"{}\n",
            media_type="application/xml",
        )
    small_output = replace(
        nuclei,
        bounds=replace(nuclei.bounds, max_output_bytes=1024),
    )
    with pytest.raises(FormatError, match="output exceeds"):
        normalize_security_output(
            small_output,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b" " * 1025,
            media_type=nuclei.output_media_types[0],
        )
    unsupported = replace(nuclei, parser_id="sova.parser.not-implemented")
    with pytest.raises(FormatError, match="not implemented"):
        normalize_security_output(
            unsupported,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b"{}\n",
            media_type=nuclei.output_media_types[0],
        )


def test_finding_limit_and_less_common_collection_shapes_are_bounded() -> None:
    semgrep = get_security_adapter("adapter.semgrep")
    limited = replace(semgrep, bounds=replace(semgrep.bounds, max_findings=1))
    raw = b'{"results":[{"check_id":"a"},{"check_id":"b"}]}'
    with pytest.raises(FormatError, match="assertion limit"):
        normalize_security_output(
            limited,
            _invocation(semgrep.identifier),
            executable_digest=_EXECUTABLE_DIGEST,
            raw=raw,
            media_type=semgrep.output_media_types[0],
        )

    promptfoo = get_security_adapter("adapter.promptfoo")
    prompt_observations = normalize_security_output(
        promptfoo,
        _invocation(promptfoo.identifier),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=b'{"results":[{"success":true},{"gradingResult":{"reason":"unknown"}}]}',
        media_type=promptfoo.output_media_types[0],
    )
    assert [item.state.value for item in prompt_observations] == [
        "tool-asserted-pass",
        "inconclusive",
    ]

    osv = get_security_adapter("adapter.osv-scanner")
    osv_observations = normalize_security_output(
        osv,
        _invocation(osv.identifier),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=(
            b'{"results":[{"packages":[{"package":{"name":"owned"},'
            b'"groups":[{"ids":["OSV-ONLY-ID"]}]}]}]}'
        ),
        media_type=osv.output_media_types[0],
    )
    assert osv_observations[0].rule_id == "OSV-ONLY-ID"

    gitleaks = get_security_adapter("adapter.gitleaks")
    assert (
        normalize_security_output(
            gitleaks,
            _invocation(gitleaks.identifier),
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b"[1]",
            media_type=gitleaks.output_media_types[0],
        )
        == ()
    )


def test_external_transfer_decision_constructor_cannot_claim_allow_without_review() -> None:
    with pytest.raises(FormatError, match="allowed decisions"):
        ExternalTransferDecision(
            identifier="sova:disclosure:defensive-edge",
            allowed=True,
            request_digest=_DIGEST,
            target_id="sova:sandbox:defensive-edge",
            destination="https://owned.invalid",
            reasons=("review-missing",),
        )
