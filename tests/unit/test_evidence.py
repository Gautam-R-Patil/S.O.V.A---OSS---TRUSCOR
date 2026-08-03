# SPDX-License-Identifier: Apache-2.0
"""Evidence, adjudication, disclosure, and reporting contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from sova.evidence import (
    ExecutionObservation,
    ObservationState,
    ScannerFinding,
    adjudicate_findings,
    build_evidence_bundle,
    construct_safe_test_plan,
    default_disclosure_clock,
    discover_maintainer_contacts,
    evidence_to_sarif,
    import_sarif,
    prepare_disclosure_package,
    render_evidence_report,
)
from sova.formats import validate_document
from sova.formats.errors import FormatError
from sova.safety import DisclosureRequest, VulnerabilityState

if TYPE_CHECKING:
    from pathlib import Path


def evidence_specification() -> dict[str, Any]:
    digest = "sha256:" + "a" * 64
    return {
        "finding": {
            "id": "SOVA-FIXTURE-001",
            "title": "Synthetic unexpected tool effect",
            "summary": "A fixture agent emitted a deterministic sink-only effect.",
            "affected": {
                "component": "fixture-agent",
                "version": "1.0.0",
                "identifiers": ["pkg:pypi/fixture-agent@1.0.0"],
            },
            "technicalSeverity": "medium",
            "harmCategory": "unexpected-tool-use",
        },
        "evidence": [
            {
                "role": "capsule",
                "uri": "fixture.sova",
                "digest": digest,
                "mediaType": "application/vnd.sova.capsule+zip",
                "verified": True,
            },
            {
                "role": "trace",
                "uri": "fixture.sova-trace",
                "digest": digest,
                "mediaType": "application/vnd.sova.trace+zip",
                "verified": True,
            },
        ],
        "conditionsTested": ["synthetic fixture version 1"],
        "coverage": {
            "testedCount": 4,
            "denominator": 4,
            "detectionFloor": "one deterministic planted condition",
        },
        "reproduction": {
            "successful": 4,
            "eligible": 4,
            "rate": "1",
            "interval": {"method": "wilson-95", "low": "0.510109", "high": "1"},
        },
        "taxonomyMappings": [{"taxonomy": "OWASP Agentic", "version": "2025", "id": "ASI02"}],
        "methodology": {"profile": "standard/0.1.0", "oracle": "fixture-effect/1"},
        "suggestedMitigations": ["Remove the fixture permission."],
        "regressionEvidence": [],
        "attachments": [],
        "limitations": ["Synthetic fixture only."],
        "lifecycle": {"state": "draft", "supersedes": None, "disputes": []},
    }


def _finding(scanner: str, *, mechanism: str = "scanner-a") -> ScannerFinding:
    return ScannerFinding(
        scanner,
        "1",
        f"RULE-{scanner}",
        "fixture-agent",
        "agent.py:1",
        "possible fixture issue",
        f"evidence:{scanner}",
        mechanism,
    )


def test_evidence_bundle_machine_human_and_sarif_exports() -> None:
    bundle = build_evidence_bundle(evidence_specification())
    mapping = bundle.to_mapping()
    validate_document(mapping, "sova.evidence")
    assert mapping["coverage"]["absenceMeansSafe"] is False
    assert "NOT INDEPENDENT ATTESTATION" in mapping["assuranceBoundary"]["watermark"]
    sarif = evidence_to_sarif(bundle)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["properties"]["sovaIndependentAttestation"] is False
    for audience in ("technical", "executive", "reproduction", "methodology"):
        report = render_evidence_report(bundle, audience=audience)
        assert "NOT INDEPENDENT ATTESTATION" in report
        assert "Limitations" in report
    with pytest.raises(FormatError, match="audience"):
        render_evidence_report(bundle, audience="marketing")


def test_evidence_builder_rejects_missing_trace_bad_digest_and_invalid_coverage() -> None:
    specification = evidence_specification()
    specification["evidence"] = [specification["evidence"][0]]
    with pytest.raises(FormatError, match="trace"):
        build_evidence_bundle(specification)
    specification = evidence_specification()
    specification["evidence"][0]["digest"] = "sha256:bad"
    with pytest.raises(FormatError, match="SHA-256"):
        build_evidence_bundle(specification)
    specification = evidence_specification()
    specification["coverage"]["denominator"] = 2
    with pytest.raises(FormatError, match="denominator"):
        build_evidence_bundle(specification)


def test_sarif_import_preserves_scanner_identity_and_location() -> None:
    document = {
        "runs": [
            {
                "tool": {"driver": {"name": "Scanner X", "version": "2"}},
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "possible issue"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "agent.py"}}}
                        ],
                        "fingerprints": {"sovaTarget": "fixture"},
                    }
                ],
            }
        ]
    }
    findings = import_sarif(document)
    assert findings[0].scanner == "Scanner X"
    assert findings[0].target_id == "fixture"
    assert findings[0].location == "agent.py"
    with pytest.raises(FormatError, match="runs"):
        import_sarif({"runs": "invalid"})


def test_execution_bounded_adjudication_has_four_terminal_states() -> None:
    findings = tuple(_finding(f"scanner-{index}", mechanism="same") for index in range(4))
    keys = [finding.claim_key for finding in findings]
    observations = (
        ExecutionObservation(
            claim_key=keys[0],
            state=ObservationState.CONFIRMED,
            trace_reference="trace:1",
            oracle_method="oracle",
            evidence_complete=True,
            safe_and_authorized=True,
        ),
        ExecutionObservation(
            claim_key=keys[1],
            state=ObservationState.CONTRADICTED,
            trace_reference="trace:2",
            oracle_method="oracle",
            evidence_complete=True,
            safe_and_authorized=True,
        ),
        ExecutionObservation(
            claim_key=keys[2],
            state=ObservationState.NOT_OBSERVED,
            trace_reference="trace:3",
            oracle_method="oracle",
            evidence_complete=True,
            safe_and_authorized=True,
        ),
        ExecutionObservation(
            claim_key=keys[3],
            state=ObservationState.INCONCLUSIVE,
            trace_reference=None,
            oracle_method="oracle",
            evidence_complete=False,
            safe_and_authorized=True,
        ),
    )
    report = adjudicate_findings(findings, observations)
    states = {claim.state.value for claim in report.claims}
    assert states == {
        "confirmed-positive",
        "false-positive-under-declared-test",
        "not-observed-under-declared-test",
        "inconclusive",
    }
    assert report.to_mapping()["claims"][1]["universalGroundTruth"] is False
    plan = construct_safe_test_plan(
        findings,
        target_owned_or_authorized=True,
        allowed_action_families=("fixture.read",),
    )
    assert plan["executionMode"] == "inert-plan-only"
    with pytest.raises(FormatError, match="authorized"):
        construct_safe_test_plan(
            findings,
            target_owned_or_authorized=False,
            allowed_action_families=("fixture.read",),
        )


def test_disclosure_is_local_redacted_and_gate_bounded() -> None:
    bundle = build_evidence_bundle(evidence_specification())
    request = DisclosureRequest(
        target_kind="synthetic",
        vulnerability_state=VulnerabilityState.PATCHED,
        contains_working_payload=False,
        authorization_redacted=True,
        secrets_scan_clean=True,
        human_reviewed=True,
        limitations_present=True,
    )
    package = prepare_disclosure_package(
        bundle,
        request,
        contacts=({"address": "security@example.invalid", "source": "fixture"},),
        clock={"reportedAt": "2026-01-01T00:00:00Z", "embargoState": "reviewed"},
    )
    output = package.to_mapping()
    assert package.release_allowed
    assert output["externalMessageSent"] is False
    assert output["published"] is False
    assert all("uri" not in item for item in output["redactedPreview"]["evidenceReferences"])


def test_local_contact_discovery_and_default_policy_clock(tmp_path: Path) -> None:
    (tmp_path / "SECURITY.md").write_text(
        "Security: Security@Example.invalid and security@example.invalid",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text('{"author":"maintainer@example.org"}', encoding="utf-8")
    contacts = discover_maintainer_contacts(tmp_path)
    assert [item["address"] for item in contacts] == [
        "maintainer@example.org",
        "security@example.invalid",
    ]
    assert all(item["discoveredBy"] == "local-static-metadata" for item in contacts)
    clock = default_disclosure_clock("2026-08-03T00:00:00+00:00")
    assert clock["defaultPeriodDays"] == 90
    assert clock["embargoEndsAt"] == "2026-11-01T00:00:00+00:00"
    assert clock["automaticReminderSent"] is False
    with pytest.raises(FormatError, match="timezone"):
        default_disclosure_clock("2026-08-03T00:00:00")
    with pytest.raises(FormatError, match="ISO 8601"):
        default_disclosure_clock("not-a-time")
    with pytest.raises(FormatError, match="directory"):
        discover_maintainer_contacts(tmp_path / "missing")
