# SPDX-License-Identifier: Apache-2.0
"""Catalog, parser, trust, and reproduction contracts for P3 adapters."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from sova.adapters.security_catalog import (
    get_security_adapter,
    promoted_security_adapters,
    security_adapter_catalog,
)
from sova.adapters.security_contracts import (
    AdapterAdmission,
    AdapterInvocation,
    AdapterTransport,
    ExternalToolEnvelope,
    ExternalTransferGate,
    ExternalTransferRequest,
    ObservationState,
)
from sova.adapters.security_parsers import (
    compare_reproduction,
    normalize_external_envelope,
    normalize_security_output,
)
from sova.cli import main
from sova.formats import sha256_digest, validate_document
from sova.formats.errors import FormatError
from sova.methodology import load_builtin_library

if TYPE_CHECKING:
    from pathlib import Path

_DIGEST = "sha256:" + "a" * 64
_EXECUTABLE_DIGEST = "sha256:" + "e" * 64

PROMOTED_FIXTURES = {
    "adapter.zap": (
        b'{"site":[{"@name":"http://owned","alerts":[{"pluginid":"100",'
        b'"alert":"owned alert","riskdesc":"High","confidence":"High",'
        b'"instances":[{"uri":"http://owned/a"}]}]}]}'
    ),
    "adapter.nuclei": (
        b'{"template-id":"owned-template","info":{"name":"owned match",'
        b'"severity":"medium"},"matched-at":"http://owned/a","type":"http"}\n'
    ),
    "adapter.schemathesis": (
        b'<testsuite tests="1"><testcase name="GET /owned" classname="api">'
        b'<failure message="status mismatch"/></testcase></testsuite>'
    ),
    "adapter.pyrit": (
        b'{"exportSchema":"sova-pyrit/0.1.0","results":[{"id":"owned-attack",'
        b'"title":"owned result","outcome":"unsafe","severity":"high",'
        b'"confidence":"medium","target":"owned"}]}'
    ),
    "adapter.garak": b'{"entry_type":"detector","detector":"owned.Detector","passed":false}\n',
    "adapter.promptfoo": (
        b'{"results":{"results":[{"testIdx":1,"success":false,'
        b'"description":"owned assertion","provider":"owned"}]}}'
    ),
    "adapter.trivy": (
        b'{"Results":[{"Target":"owned.lock","Vulnerabilities":['
        b'{"VulnerabilityID":"CVE-TEST-1","Title":"owned package issue",'
        b'"Severity":"HIGH"}]}]}'
    ),
    "adapter.syft": (
        b'{"artifacts":[{"id":"pkg-1","name":"owned-package","version":"1.0",'
        b'"type":"python","purl":"pkg:pypi/owned-package@1.0"}]}'
    ),
    "adapter.grype": (
        b'{"matches":[{"vulnerability":{"id":"CVE-TEST-2",'
        b'"description":"owned issue","severity":"High"},"artifact":'
        b'{"name":"owned-package","version":"1.0",'
        b'"purl":"pkg:pypi/owned-package@1.0"}}]}'
    ),
    "adapter.osv-scanner": (
        b'{"results":[{"packages":[{"package":{"name":"owned-package"},'
        b'"groups":[{"ids":["OSV-TEST-1"],"vulnerabilities":['
        b'{"id":"OSV-TEST-1","summary":"owned issue"}]}]}]}]}'
    ),
    "adapter.gitleaks": (
        b'[{"RuleID":"owned-secret-rule","Description":"owned secret marker",'
        b'"File":"fixture.txt","StartLine":2,"Secret":"must-not-survive",'
        b'"Match":"must-not-survive"}]'
    ),
    "adapter.semgrep": (
        b'{"results":[{"check_id":"owned.rule","path":"owned.py",'
        b'"start":{"line":4},"extra":{"message":"owned issue",'
        b'"severity":"ERROR","metavars":{"$X":'
        b'{"abstract_content":"secret"}}}}]}'
    ),
}


def _invocation(adapter_id: str) -> AdapterInvocation:
    descriptor = get_security_adapter(adapter_id)
    evidence = f"{descriptor.tool_name} {descriptor.tool_version}".encode()
    return AdapterInvocation(
        identifier="adapter-fixture-run",
        descriptor_id=adapter_id,
        target_id="sova:sandbox:owned-target",
        target="owned-target",
        target_predicate=descriptor.target_predicates[0],
        target_profile_digest=_DIGEST,
        target_generation="sha256:" + "b" * 64,
        executable_path="C:/fixture/tool.exe",
        observed_tool_version=descriptor.tool_version,
        version_evidence_digest=sha256_digest(evidence),
        output_path="output.json",
        config_path="config.json",
        config_digest="sha256:" + "c" * 64,
        ruleset_path="rules.json",
        ruleset_digest="sha256:" + "d" * 64,
        disclosure_gate_id="sova:disclosure:owned-fixture",
        disclosure_gate_digest="sha256:" + "f" * 64,
    )


def test_catalog_has_exact_admission_tiers_and_schema_valid_descriptors() -> None:
    catalog = security_adapter_catalog()
    assert len(catalog) == 21
    assert len(promoted_security_adapters()) == 12
    assert sum(item.admission == AdapterAdmission.CONSTRAINED for item in catalog) == 8
    assert sum(item.admission == AdapterAdmission.LEGAL_HOLD for item in catalog) == 1
    assert {item.identifier for item in promoted_security_adapters()} == set(PROMOTED_FIXTURES)
    for descriptor in catalog:
        validate_document(descriptor.to_mapping())
        assert descriptor.executable_digest_policy == "runtime-sha256-required"
        assert descriptor.privacy.telemetry is False
        assert descriptor.privacy.remote_generation is False
        assert descriptor.privacy.uploads is False
        assert descriptor.privacy.implicit_pulls is False
        assert descriptor.privacy.auto_update is False
        assert descriptor.privacy.unreviewed_templates is False
        assert descriptor.privacy.external_transfer_requires_disclosure_gate is True


def test_nmap_is_user_supplied_legal_hold_and_cannot_be_silently_promoted() -> None:
    descriptor = get_security_adapter("adapter.nmap")
    assert descriptor.admission == AdapterAdmission.LEGAL_HOLD
    assert "neither redistributes nor auto-installs" in (descriptor.legal_note or "")
    assert "NPSL" in descriptor.license_expression


def test_native_methodology_routes_only_to_cataloged_security_adapters() -> None:
    catalog_ids = {item.identifier for item in security_adapter_catalog()}
    candidate_ids = {
        adapter
        for playbook in load_builtin_library().playbooks
        for requirement in playbook.tool_requirements
        for adapter in requirement.candidate_adapters
    }
    assert candidate_ids
    assert candidate_ids <= catalog_ids


@pytest.mark.parametrize("adapter_id", sorted(PROMOTED_FIXTURES))
def test_every_promoted_parser_emits_unconfirmed_schema_valid_observations(
    adapter_id: str,
) -> None:
    descriptor = get_security_adapter(adapter_id)
    observations = normalize_security_output(
        descriptor,
        _invocation(adapter_id),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=PROMOTED_FIXTURES[adapter_id],
        media_type=descriptor.output_media_types[0],
    )
    assert observations
    for observation in observations:
        assert observation.finding_confirmed is False
        assert observation.independently_reproduced is False
        assert observation.state != ObservationState.INFRASTRUCTURE_FAILURE
        validate_document(observation.to_mapping())
        serialized = str(observation.to_mapping())
        assert "must-not-survive" not in serialized
        assert "abstract_content" not in serialized
    reproduced = normalize_security_output(
        descriptor,
        replace(_invocation(adapter_id), identifier="second-fixture-run"),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=PROMOTED_FIXTURES[adapter_id] + b"\n",
        media_type=descriptor.output_media_types[0],
    )
    assert compare_reproduction(observations, reproduced)["independentlyReproduced"] is True


@pytest.mark.parametrize("adapter_id", sorted(PROMOTED_FIXTURES))
def test_every_promoted_parser_rejects_corruption_and_partial_output(adapter_id: str) -> None:
    descriptor = get_security_adapter(adapter_id)
    invocation = _invocation(adapter_id)
    with pytest.raises(FormatError):
        normalize_security_output(
            descriptor,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=b"\xff{not-valid",
            media_type=descriptor.output_media_types[0],
        )
    with pytest.raises(FormatError, match="partial output"):
        normalize_security_output(
            descriptor,
            invocation,
            executable_digest=_EXECUTABLE_DIGEST,
            raw=PROMOTED_FIXTURES[adapter_id],
            media_type=descriptor.output_media_types[0],
            complete=False,
        )


def test_semantic_reproduction_ignores_raw_encoding_but_detects_nondeterminism() -> None:
    descriptor = get_security_adapter("adapter.nuclei")
    invocation = _invocation(descriptor.identifier)
    first = normalize_security_output(
        descriptor,
        invocation,
        executable_digest=_EXECUTABLE_DIGEST,
        raw=PROMOTED_FIXTURES[descriptor.identifier],
        media_type=descriptor.output_media_types[0],
    )
    second = normalize_security_output(
        descriptor,
        replace(invocation, identifier="second-fixture-run"),
        executable_digest=_EXECUTABLE_DIGEST,
        raw=PROMOTED_FIXTURES[descriptor.identifier] + b"\n",
        media_type=descriptor.output_media_types[0],
    )
    assert first[0].raw.digest != second[0].raw.digest
    assessment = compare_reproduction(first, second)
    assert assessment["matched"] is True
    assert assessment["independentlyReproduced"] is True
    changed = normalize_security_output(
        descriptor,
        invocation,
        executable_digest=_EXECUTABLE_DIGEST,
        raw=PROMOTED_FIXTURES[descriptor.identifier].replace(b"/a", b"/different"),
        media_type=descriptor.output_media_types[0],
    )
    assert compare_reproduction(first, changed)["matched"] is False


def test_generic_mcp_and_http_envelopes_trust_no_provider_claims() -> None:
    for transport in (AdapterTransport.MCP_STDIO, AdapterTransport.HTTP):
        envelope = ExternalToolEnvelope(
            transport=transport,
            producer="untrusted-fixture",
            raw_digest=_DIGEST,
            schema={"type": "object"},
            summary="provider says safe",
            evidence_references=("provider://claim",),
        )
        normalized = normalize_external_envelope(envelope)
        assert normalized["trust"] == {
            "schema": "untrusted",
            "summary": "untrusted",
            "evidence": "untrusted",
        }
        assert normalized["findingConfirmed"] is False


def test_external_envelope_cannot_self_upgrade_trust() -> None:
    with pytest.raises(FormatError, match="begin untrusted"):
        ExternalToolEnvelope(
            transport=AdapterTransport.HTTP,
            producer="untrusted-fixture",
            raw_digest=_DIGEST,
            schema=None,
            summary=None,
            evidence_references=(),
            schema_trust="sova-validated",  # type: ignore[arg-type]
        )


def test_external_transfer_gate_requires_human_and_retention_review() -> None:
    request = ExternalTransferRequest(
        target_id="sova:sandbox:owned-target",
        destination="https://owned.invalid",
        purpose="owned fixture",
        data_classes=("synthetic-prompt",),
        authorization_reference="sova:authorization:owned-fixture",
        human_reviewed=False,
        retention_reviewed=False,
        contains_unredacted_secrets=True,
    )
    denied = ExternalTransferGate().assess(request)
    assert denied.allowed is False
    assert set(denied.reasons) == {
        "human-transfer-review-required",
        "destination-retention-review-required",
        "unredacted-secrets-prohibited",
    }
    allowed = ExternalTransferGate().assess(
        replace(
            request,
            human_reviewed=True,
            retention_reviewed=True,
            contains_unredacted_secrets=False,
        )
    )
    assert allowed.allowed is True
    assert allowed.reasons == ()
    assert allowed.digest.startswith("sha256:")


def test_adapter_cli_is_inert_and_emits_offline_artifacts(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    catalog_path = tmp_path / "catalog.json"
    assert main(["adapter", "catalog", str(catalog_path)]) == 0
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    assert catalog["descriptorCount"] == 21
    assert catalog["installationPerformed"] is False
    assert catalog["executionAuthorized"] is False
    capfd.readouterr()

    descriptor_path = tmp_path / "syft.json"
    assert main(["adapter", "describe", "adapter.syft", str(descriptor_path)]) == 0
    assert json.loads(descriptor_path.read_text(encoding="utf-8"))["id"] == "adapter.syft"
    capfd.readouterr()

    plan_path = tmp_path / "plan.json"
    assert main(["adapter", "plan", "adapter.syft", str(plan_path)]) == 0
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert plan["commandMaterialized"] is False
    assert plan["executionPerformed"] is False
    assert plan["findingConfirmed"] is False
    capfd.readouterr()

    invocation_path = tmp_path / "invocation.json"
    invocation = _invocation("adapter.syft")
    invocation_path.write_text(
        json.dumps(
            {
                "id": invocation.identifier,
                "descriptorId": invocation.descriptor_id,
                "targetId": invocation.target_id,
                "target": invocation.target,
                "targetPredicate": invocation.target_predicate,
                "targetProfileDigest": invocation.target_profile_digest,
                "targetGeneration": invocation.target_generation,
                "executablePath": invocation.executable_path,
                "observedToolVersion": invocation.observed_tool_version,
                "versionEvidenceDigest": invocation.version_evidence_digest,
                "outputPath": invocation.output_path,
                "configPath": invocation.config_path,
                "configDigest": invocation.config_digest,
                "rulesetPath": invocation.ruleset_path,
                "rulesetDigest": invocation.ruleset_digest,
                "disclosureGateId": invocation.disclosure_gate_id,
                "disclosureGateDigest": invocation.disclosure_gate_digest,
            }
        ),
        encoding="utf-8",
    )
    raw_path = tmp_path / "syft-output.json"
    raw_path.write_bytes(PROMOTED_FIXTURES["adapter.syft"])
    normalized_path = tmp_path / "normalized.json"
    assert (
        main(
            [
                "adapter",
                "normalize",
                "adapter.syft",
                str(invocation_path),
                str(raw_path),
                str(normalized_path),
                "--executable-digest",
                _EXECUTABLE_DIGEST,
            ]
        )
        == 0
    )
    normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
    assert normalized["executionPerformed"] is False
    assert normalized["findingConfirmed"] is False
    assert normalized["observationCount"] == 1
