# SPDX-License-Identifier: Apache-2.0
"""Signed exact-candidate P6 launch dossier tests."""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from sova.cli import main
from sova.formats import FormatError, canonical_json_bytes, sha256_digest, validate_document
from sova.trace import generate_ed25519_keypair
from sova.validation import (
    LaunchGate,
    LaunchGateReceipt,
    LaunchRole,
    OperationalReceipt,
    RegistryControl,
    ReleaseCandidate,
    ReviewGate,
    ReviewReceipt,
    evaluate_blinded_protocol,
    evaluate_launch_bundle,
    evaluate_registry_beta,
    launch_bundle_from_mapping,
    operational_receipt_from_mapping,
    protocol_from_mapping,
    read_launch_bundle,
    registry_policy_from_mapping,
    release_candidate_from_mapping,
    sign_launch_evidence,
    trust_policy_from_mapping,
)
from tests.support.p6 import digest, observations, protocol, registry_policy

if TYPE_CHECKING:
    from pathlib import Path

    from sova.trace.integrity import Ed25519Keypair

_CHECKS = {
    LaunchGate.P5_PRODUCTION_ISOLATION: (
        "cleanup-and-evidence-extraction",
        "dedicated-patched-linux-kvm-host",
        "independent-isolation-review-bound",
        "live-firecracker-microvm",
        "malicious-guest-exact-host-matrix",
    ),
    LaunchGate.BLINDED_FIELD_VALIDATION: (
        "all-eight-target-classes",
        "complete-run-ledger",
        "independent-answer-key-custody",
        "matched-baseline-execution",
        "multiple-provider-families",
        "negative-results-retained",
        "owned-or-licensed-targets",
        "preregistered-before-results",
    ),
    LaunchGate.DETERMINISTIC_RELEASE_CHECKS: (
        "checksums",
        "ci-provenance",
        "dependency-audit",
        "deterministic-build",
        "full-test-suite",
        "isolated-wheel-smoke",
        "license-audit",
        "package-resource-check",
        "public-boundary",
        "sbom",
        "secret-audit",
        "staged-path-review",
        "static-analysis",
    ),
}
_ENVIRONMENTS = {
    LaunchGate.P5_PRODUCTION_ISOLATION: "dedicated-linux-kvm-worker",
    LaunchGate.BLINDED_FIELD_VALIDATION: "blinded-owned-or-licensed-field-study",
    LaunchGate.DETERMINISTIC_RELEASE_CHECKS: "exact-final-commit-ci",
}


def _with_digest(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result["contentDigest"] = sha256_digest(canonical_json_bytes(result))
    return result


def _public_claims_snapshot(commit: str, *, ready: bool = True) -> bytes:
    kinds = ("readme", "documentation", "demo", "website", "paper", "registry", "release-notes")
    surfaces = [
        {
            "id": f"surface:{kind}",
            "kind": kind,
            "locator": f"fixture://{kind}",
            "contentDigest": digest(f"public-claim:{kind}"),
            "status": "reconciled" if ready or kind != "website" else "hold",
            "reviewed": ready or kind != "website",
            "limitations": ["fixture-only"],
        }
        for kind in kinds
    ]
    document = _with_digest(
        {
            "artifactType": "sova.public-claims-snapshot",
            "schemaVersion": "0.1.0",
            "releaseCommit": commit,
            "capturedAt": "2026-08-31T13:30:00Z",
            "surfaces": surfaces,
            "publicClaimsReady": ready,
        }
    )
    return canonical_json_bytes(document) + b"\n"


def _principals() -> tuple[dict[LaunchRole, Ed25519Keypair], list[dict[str, Any]]]:
    keys: dict[LaunchRole, Ed25519Keypair] = {}
    rows: list[dict[str, Any]] = []
    names = {
        LaunchRole.EVALUATION_CUSTODIAN: ("evaluation-custodian", "Independent Eval Lab"),
        LaunchRole.REGISTRY_OPERATOR: ("fixture-operator", "Registry Operator"),
        LaunchRole.P5_OPERATOR: ("isolation-operator", "Isolation Operations"),
        LaunchRole.RELEASE_OPERATOR: ("release-operator", "Release Operations"),
        LaunchRole.FOUNDER: ("founder-reviewer", "SOVA"),
        LaunchRole.INDEPENDENT_TECHNICAL: ("technical-reviewer", "Independent Tech Lab"),
        LaunchRole.INDEPENDENT_ISOLATION: (
            "isolation-reviewer",
            "Independent Isolation Lab",
        ),
        LaunchRole.LEGAL: ("legal-reviewer", "Independent Legal Counsel"),
        LaunchRole.SECURITY: ("security-reviewer", "Independent Security Lab"),
    }
    for role in LaunchRole:
        key = generate_ed25519_keypair()
        keys[role] = key
        name, organization = names[role]
        rows.append(
            {
                "keyId": key.key_id,
                "publicKey": base64.b64encode(key.public_key).decode("ascii"),
                "name": name,
                "organization": organization,
                "roles": [role.value],
            }
        )
    return keys, rows


def _sign(document: dict[str, Any], key: Ed25519Keypair) -> dict[str, Any]:
    return sign_launch_evidence(document, key.private_key, key.public_key)


def _ready_bundle() -> tuple[dict[str, Any], bytes, bytes, str, dict[LaunchRole, Ed25519Keypair]]:
    plan = protocol()
    commit = plan.release_commit
    manifest = b"sha256 fixture-release.whl\n"
    claims = b"# exact release claims\n"
    public_claims = _public_claims_snapshot(commit)
    manifest_digest = sha256_digest(manifest)
    claims_digest = sha256_digest(claims)
    keys, principals = _principals()
    observation_ledger = _with_digest(
        {
            "artifactType": "sova.evaluation-observation-ledger",
            "schemaVersion": "0.1.0",
            "protocolDigest": plan.digest,
            "observations": [item.to_mapping() for item in observations(plan)],
        }
    )
    evaluation = evaluate_blinded_protocol(plan, observations(plan))

    policy = registry_policy()
    operations = tuple(
        OperationalReceipt(
            control=control,
            policy_digest=policy.digest,
            release_artifact_digest=policy.release_artifact_digest,
            environment="production",
            issuer="fixture-operator",
            issued_at="2026-08-27T13:00:00Z",
            result="pass",
            evidence_digest=digest(f"operation:{control.value}"),
            synthetic=False,
        )
        for control in RegistryControl
    )
    registry = evaluate_registry_beta(policy, operations)
    operation_by_control = {item.control: item for item in operations}
    candidate = ReleaseCandidate(
        release_commit=commit,
        artifact_manifest_digest=manifest_digest,
        evaluation_report_digest=str(evaluation["contentDigest"]),
        registry_readiness_digest=str(registry["contentDigest"]),
        claims_register_digest=claims_digest,
        public_claims_snapshot_digest=sha256_digest(public_claims),
        rollback_test_digest=operation_by_control[RegistryControl.ROLLBACK].evidence_digest,
        incident_test_digest=operation_by_control[
            RegistryControl.INCIDENT_RESPONSE
        ].evidence_digest,
        blinded_results_public=True,
        limitations_public=True,
    )
    trust = _with_digest(
        {
            "artifactType": "sova.launch-trust-policy",
            "schemaVersion": "0.1.0",
            "releaseCommit": commit,
            "artifactManifestDigest": manifest_digest,
            "releaseCandidateDigest": candidate.digest,
            "principals": principals,
        }
    )

    review_role = {
        ReviewGate.FOUNDER: LaunchRole.FOUNDER,
        ReviewGate.INDEPENDENT_TECHNICAL: LaunchRole.INDEPENDENT_TECHNICAL,
        ReviewGate.INDEPENDENT_ISOLATION: LaunchRole.INDEPENDENT_ISOLATION,
        ReviewGate.LEGAL: LaunchRole.LEGAL,
        ReviewGate.SECURITY: LaunchRole.SECURITY,
    }
    principal_by_role = {LaunchRole(row["roles"][0]): row for row in principals}
    reviews: list[dict[str, Any]] = []
    for review_gate in ReviewGate:
        role = review_role[review_gate]
        identity = principal_by_role[role]
        review_receipt = ReviewReceipt(
            gate=review_gate,
            release_commit=commit,
            artifact_manifest_digest=manifest_digest,
            reviewer=str(identity["name"]),
            organization=str(identity["organization"]),
            issued_at="2026-08-27T14:00:00Z",
            result="pass",
            independent=review_gate
            in {ReviewGate.INDEPENDENT_TECHNICAL, ReviewGate.INDEPENDENT_ISOLATION},
            evidence_digest=digest(f"review:{review_gate.value}"),
            synthetic=False,
        )
        reviews.append(_sign(review_receipt.to_mapping(), keys[role]))

    gates: list[dict[str, Any]] = []
    for launch_gate in LaunchGate:
        role = {
            LaunchGate.P5_PRODUCTION_ISOLATION: LaunchRole.P5_OPERATOR,
            LaunchGate.BLINDED_FIELD_VALIDATION: LaunchRole.EVALUATION_CUSTODIAN,
            LaunchGate.DETERMINISTIC_RELEASE_CHECKS: LaunchRole.RELEASE_OPERATOR,
        }[launch_gate]
        identity = principal_by_role[role]
        subject = (
            str(evaluation["contentDigest"])
            if launch_gate is LaunchGate.BLINDED_FIELD_VALIDATION
            else manifest_digest
        )
        gate_receipt = LaunchGateReceipt(
            gate=launch_gate,
            release_commit=commit,
            artifact_manifest_digest=manifest_digest,
            subject_digest=subject,
            environment=_ENVIRONMENTS[launch_gate],
            issuer=str(identity["name"]),
            organization=str(identity["organization"]),
            issued_at="2026-08-27T15:00:00Z",
            result="pass",
            checks=_CHECKS[launch_gate],
            evidence_digest=digest(f"gate:{launch_gate.value}"),
            synthetic=False,
        )
        gates.append(_sign(gate_receipt.to_mapping(), keys[role]))

    bundle = _with_digest(
        {
            "artifactType": "sova.launch-evidence-bundle",
            "schemaVersion": "0.1.0",
            "trustPolicy": trust,
            "protocol": plan.to_mapping(),
            "observationLedger": _sign(observation_ledger, keys[LaunchRole.EVALUATION_CUSTODIAN]),
            "registryPolicy": policy.to_mapping(),
            "operationalReceipts": [
                _sign(item.to_mapping(), keys[LaunchRole.REGISTRY_OPERATOR]) for item in operations
            ],
            "candidate": candidate.to_mapping(),
            "reviewReceipts": reviews,
            "gateReceipts": gates,
        }
    )
    return bundle, manifest, claims, commit, keys


def _trust_digest(document: dict[str, Any]) -> str:
    return str(document["trustPolicy"]["contentDigest"])


def _signed_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return dict(json.loads(base64.b64decode(str(envelope["payload"]), validate=True)))


def _refresh_bundle(document: dict[str, Any]) -> dict[str, Any]:
    return _with_digest({key: value for key, value in document.items() if key != "contentDigest"})


def _refresh_trust(document: dict[str, Any]) -> dict[str, Any]:
    trust = dict(document["trustPolicy"])
    document["trustPolicy"] = _with_digest(
        {key: value for key, value in trust.items() if key != "contentDigest"}
    )
    return _refresh_bundle(document)


def _rebind_registry_candidate(document: dict[str, Any]) -> dict[str, Any]:
    policy = registry_policy_from_mapping(document["registryPolicy"])
    receipts = tuple(
        operational_receipt_from_mapping(_signed_payload(envelope))
        for envelope in document["operationalReceipts"]
    )
    registry = evaluate_registry_beta(policy, receipts)
    document["candidate"]["registryReadinessDigest"] = registry["contentDigest"]
    candidate = release_candidate_from_mapping(document["candidate"])
    document["trustPolicy"]["releaseCandidateDigest"] = candidate.digest
    return _refresh_trust(document)


def test_signed_launch_dossier_can_be_ready_but_never_publishes() -> None:
    document, manifest, claims, commit, _keys = _ready_bundle()
    dossier = evaluate_launch_bundle(
        launch_bundle_from_mapping(document),
        artifact_manifest=manifest,
        claims_register=claims,
        public_claims_snapshot=_public_claims_snapshot(commit),
        expected_commit=commit,
        expected_trust_policy_digest=_trust_digest(document),
    )
    validate_document(dossier, "sova.launch-dossier")
    assert dossier["status"] == "ready"
    assert dossier["tagOrPublishAllowed"] is True
    assert dossier["automaticPublishPerformed"] is False
    assert dossier["receiptCounts"] == {"operational": 10, "reviews": 5, "launchGates": 3}
    assert len(dossier["trustedSignerKeyIds"]) == 9
    assert dossier["holdReasons"] == []
    assert dossier["evaluationSummary"] == {
        "status": "conclusive",
        "expectedRuns": 32,
        "observedRuns": 32,
        "missingRunCount": 0,
        "budgetExceedanceCount": 0,
    }
    assert dossier["registrySummary"]["liveBetaReady"] is True
    assert dossier["reviewSummary"] == {
        "missingReviews": [],
        "failedReviews": [],
        "syntheticReviews": [],
        "independenceFailures": [],
    }
    assert all(dossier["externalGates"].values())
    assert dossier["claims"]["reviewerIdentityLegallyVerifiedBySova"] is False
    assert dossier["claims"]["allVulnerabilitiesFound"] is False
    inconsistent = copy.deepcopy(dossier)
    inconsistent["status"] = "hold"
    inconsistent["tagOrPublishAllowed"] = False
    with pytest.raises(FormatError):
        validate_document(inconsistent, "sova.launch-dossier")


def test_unreconciled_or_tampered_public_claims_keep_release_closed() -> None:
    document, manifest, claims, commit, _keys = _ready_bundle()
    held_snapshot = _public_claims_snapshot(commit, ready=False)
    document["candidate"]["publicClaimsSnapshotDigest"] = sha256_digest(held_snapshot)
    document["trustPolicy"]["releaseCandidateDigest"] = sha256_digest(
        canonical_json_bytes(document["candidate"])
    )
    document = _refresh_trust(document)
    dossier = evaluate_launch_bundle(
        launch_bundle_from_mapping(document),
        artifact_manifest=manifest,
        claims_register=claims,
        public_claims_snapshot=held_snapshot,
        expected_commit=commit,
        expected_trust_policy_digest=_trust_digest(document),
    )
    assert dossier["externalGates"]["publicClaimsReconciled"] is False
    assert dossier["status"] == "hold"
    assert dossier["holdReasons"] == ["external-gate-not-passed:publicClaimsReconciled"]

    ready_document, manifest, claims, commit, _keys = _ready_bundle()
    with pytest.raises(FormatError, match="snapshot bytes"):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(ready_document),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=held_snapshot,
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(ready_document),
        )
    with pytest.raises(FormatError, match="canonical JSON"):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(ready_document),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit) + b" ",
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(ready_document),
        )
    with pytest.raises(FormatError, match="another release commit"):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(ready_document),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot("different-commit"),
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(ready_document),
        )


def test_public_claims_snapshot_rejects_false_readiness_and_duplicate_surfaces() -> None:
    document, manifest, claims, commit, _keys = _ready_bundle()
    parsed = json.loads(_public_claims_snapshot(commit))
    parsed["publicClaimsReady"] = False
    parsed = _with_digest({key: value for key, value in parsed.items() if key != "contentDigest"})
    with pytest.raises(FormatError, match="readiness"):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(document),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=canonical_json_bytes(parsed) + b"\n",
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(document),
        )

    parsed = json.loads(_public_claims_snapshot(commit))
    parsed["surfaces"][-1]["kind"] = parsed["surfaces"][0]["kind"]
    parsed = _with_digest({key: value for key, value in parsed.items() if key != "contentDigest"})
    with pytest.raises(FormatError, match="unique"):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(document),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=canonical_json_bytes(parsed) + b"\n",
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(document),
        )


def test_missing_or_synthetic_gate_keeps_dossier_on_hold() -> None:
    document, manifest, claims, commit, _keys = _ready_bundle()
    document["gateReceipts"] = document["gateReceipts"][:-1]
    document = _with_digest(
        {key: value for key, value in document.items() if key != "contentDigest"}
    )
    dossier = evaluate_launch_bundle(
        launch_bundle_from_mapping(document),
        artifact_manifest=manifest,
        claims_register=claims,
        public_claims_snapshot=_public_claims_snapshot(commit),
        expected_commit=commit,
        expected_trust_policy_digest=_trust_digest(document),
    )
    assert dossier["status"] == "hold"
    assert dossier["tagOrPublishAllowed"] is False
    assert dossier["gateReceipts"]["deterministic-release-checks"]["present"] is False
    assert dossier["holdReasons"] == ["external-gate-not-passed:deterministicReleaseChecks"]

    missing_review, manifest, claims, commit, _keys = _ready_bundle()
    missing_review["reviewReceipts"] = missing_review["reviewReceipts"][:-1]
    missing_review = _refresh_bundle(missing_review)
    review_dossier = _evaluate_ready_document(missing_review, manifest, claims, commit)
    assert review_dossier["reviewSummary"]["missingReviews"] == ["security-signoff"]
    assert review_dossier["holdReasons"] == ["review-missing:security-signoff"]

    missing_operation, manifest, claims, commit, _keys = _ready_bundle()
    missing_operation["operationalReceipts"] = missing_operation["operationalReceipts"][1:]
    missing_operation = _rebind_registry_candidate(missing_operation)
    operation_dossier = _evaluate_ready_document(missing_operation, manifest, claims, commit)
    assert operation_dossier["registrySummary"]["missingControls"] == [
        "authentication-authorization"
    ]
    assert operation_dossier["holdReasons"] == [
        "external-gate-not-passed:registryLiveBeta",
        "registry-missing-control:authentication-authorization",
    ]


def test_launch_bundle_rejects_tampering_drift_and_untrusted_signers() -> None:
    document, manifest, claims, commit, _keys = _ready_bundle()
    with pytest.raises(FormatError, match="content digest"):
        launch_bundle_from_mapping({**document, "contentDigest": digest("wrong")})
    bundle = launch_bundle_from_mapping(document)
    with pytest.raises(FormatError, match="release commit"):
        evaluate_launch_bundle(
            bundle,
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit),
            expected_commit="other",
            expected_trust_policy_digest=_trust_digest(document),
        )
    with pytest.raises(FormatError, match="artifact manifest bytes"):
        evaluate_launch_bundle(
            bundle,
            artifact_manifest=b"tampered",
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit),
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(document),
        )
    tampered = dict(document)
    envelope = dict(tampered["observationLedger"])
    envelope["payload"] = envelope["payload"][:-2] + "AA"
    tampered["observationLedger"] = envelope
    tampered = _with_digest(
        {key: value for key, value in tampered.items() if key != "contentDigest"}
    )
    with pytest.raises(FormatError):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(tampered),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit),
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(tampered),
        )

    unknown = generate_ed25519_keypair()
    unauthorized = dict(document)
    observation_payload = read_launch_bundle(canonical_json_bytes(document)).observation_envelope
    payload = base64.b64decode(str(observation_payload["payload"]), validate=True)
    parsed = __import__("json").loads(payload)
    unauthorized["observationLedger"] = _sign(parsed, unknown)
    unauthorized = _with_digest(
        {key: value for key, value in unauthorized.items() if key != "contentDigest"}
    )
    with pytest.raises(FormatError, match="not trusted"):
        evaluate_launch_bundle(
            launch_bundle_from_mapping(unauthorized),
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit),
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(unauthorized),
        )


def test_launch_signing_and_cli_operator_path(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    private_key = tmp_path / "private.key"
    public_key = tmp_path / "public.key"
    assert main(["release", "keygen", str(private_key), str(public_key)]) == 0
    capfd.readouterr()

    plan = protocol()
    ledger = _with_digest(
        {
            "artifactType": "sova.evaluation-observation-ledger",
            "schemaVersion": "0.1.0",
            "protocolDigest": plan.digest,
            "observations": [],
        }
    )
    document_path = tmp_path / "ledger.json"
    document_path.write_bytes(canonical_json_bytes(ledger))
    envelope_path = tmp_path / "ledger.dsse.json"
    assert (
        main(
            [
                "release",
                "sign-evidence",
                str(document_path),
                str(private_key),
                str(public_key),
                str(envelope_path),
            ]
        )
        == 0
    )
    capfd.readouterr()
    assert envelope_path.is_file()

    bundle, manifest, claims, commit, _keys = _ready_bundle()
    trust_path = tmp_path / "trust-policy.json"
    protocol_path = tmp_path / "protocol.json"
    observation_path = tmp_path / "observations.dsse.json"
    registry_path = tmp_path / "registry-policy.json"
    candidate_path = tmp_path / "candidate.json"
    operational_paths = [tmp_path / f"operation-{index}.dsse.json" for index in range(10)]
    review_paths = [tmp_path / f"review-{index}.dsse.json" for index in range(5)]
    gate_paths = [tmp_path / f"gate-{index}.dsse.json" for index in range(3)]
    for path, value in (
        (trust_path, bundle["trustPolicy"]),
        (protocol_path, bundle["protocol"]),
        (observation_path, bundle["observationLedger"]),
        (registry_path, bundle["registryPolicy"]),
        (candidate_path, bundle["candidate"]),
        *zip(operational_paths, bundle["operationalReceipts"], strict=True),
        *zip(review_paths, bundle["reviewReceipts"], strict=True),
        *zip(gate_paths, bundle["gateReceipts"], strict=True),
    ):
        path.write_bytes(canonical_json_bytes(value))
    bundle_path = tmp_path / "bundle.json"
    assemble_args = [
        "release",
        "assemble-evidence",
        str(trust_path),
        str(protocol_path),
        str(observation_path),
        str(registry_path),
        str(candidate_path),
        str(bundle_path),
    ]
    for path in operational_paths:
        assemble_args.extend(("--operational-receipt", str(path)))
    for path in review_paths:
        assemble_args.extend(("--review-receipt", str(path)))
    for path in gate_paths:
        assemble_args.extend(("--gate-receipt", str(path)))
    assert main(assemble_args) == 0
    assembled_report = json.loads(capfd.readouterr().out)
    assert assembled_report["signaturesVerified"] is False
    assert assembled_report["publicationPerformed"] is False
    assert json.loads(bundle_path.read_bytes()) == bundle

    manifest_path = tmp_path / "SHA256SUMS"
    claims_path = tmp_path / "claims.md"
    public_claims_path = tmp_path / "public-claims.json"
    dossier_path = tmp_path / "dossier.json"
    manifest_path.write_bytes(manifest)
    claims_path.write_bytes(claims)
    public_claims_path.write_bytes(_public_claims_snapshot(commit))
    assert (
        main(
            [
                "release",
                "dossier",
                str(bundle_path),
                str(manifest_path),
                str(claims_path),
                str(public_claims_path),
                str(dossier_path),
                "--expected-commit",
                commit,
                "--expected-trust-policy-digest",
                _trust_digest(bundle),
            ]
        )
        == 0
    )
    capfd.readouterr()
    assert dossier_path.is_file()

    with pytest.raises(FormatError, match="cannot be signed"):
        sign_launch_evidence(
            {"artifactType": "unsupported"}, private_key.read_bytes(), public_key.read_bytes()
        )


def test_gate_receipt_contract_rejects_missing_checks_and_synthetic_pass() -> None:
    document, _manifest, _claims, _commit, _keys = _ready_bundle()
    bundle = launch_bundle_from_mapping(document)
    evaluation = evaluate_blinded_protocol(bundle.protocol, observations(bundle.protocol))
    receipt = LaunchGateReceipt(
        gate=LaunchGate.BLINDED_FIELD_VALIDATION,
        release_commit=bundle.candidate.release_commit,
        artifact_manifest_digest=bundle.candidate.artifact_manifest_digest,
        subject_digest=str(evaluation["contentDigest"]),
        environment=_ENVIRONMENTS[LaunchGate.BLINDED_FIELD_VALIDATION],
        issuer="evaluation-custodian",
        organization="Independent Eval Lab",
        issued_at="2026-08-27T15:00:00Z",
        result="pass",
        checks=_CHECKS[LaunchGate.BLINDED_FIELD_VALIDATION],
        evidence_digest=digest("field"),
        synthetic=True,
    )
    assert receipt.passed is False
    with pytest.raises(FormatError, match="checks"):
        replace(receipt, checks=receipt.checks[:-1])

    with pytest.raises(FormatError, match="digest"):
        replace(receipt, subject_digest="bad")
    with pytest.raises(FormatError, match="identity"):
        replace(receipt, issuer="")
    with pytest.raises(FormatError, match="result"):
        replace(receipt, result="unknown")
    with pytest.raises(FormatError, match="RFC 3339"):
        replace(receipt, issued_at="not-a-time")
    with pytest.raises(FormatError, match="environment"):
        replace(receipt, environment="developer-laptop")


def test_launch_trust_and_registry_input_types_fail_closed() -> None:  # noqa: PLR0915
    document, _manifest, _claims, _commit, _keys = _ready_bundle()
    policy = trust_policy_from_mapping(document["trustPolicy"])
    principal = policy.principals[0]
    assert policy.principal(principal.key_id) is principal
    with pytest.raises(FormatError, match="does not match"):
        replace(principal, key_id=digest("wrong-key"))
    with pytest.raises(FormatError, match="identity"):
        replace(principal, name="")
    with pytest.raises(FormatError, match="unique"):
        replace(principal, roles=(LaunchRole.FOUNDER, LaunchRole.FOUNDER))
    with pytest.raises(FormatError, match="release binding"):
        replace(policy, release_candidate_digest="bad")
    with pytest.raises(FormatError, match="unique"):
        replace(policy, principals=(principal, principal))
    with pytest.raises(FormatError, match="every launch trust role"):
        replace(policy, principals=(replace(principal, roles=(LaunchRole.FOUNDER,)),))
    coalesced = (
        replace(
            policy.principals[0],
            roles=(policy.principals[0].roles[0], policy.principals[1].roles[0]),
        ),
        *policy.principals[2:],
    )
    with pytest.raises(FormatError, match="distinct trusted principal"):
        replace(policy, principals=coalesced)
    by_role = {item.roles[0]: item for item in policy.principals}
    internal_identity = tuple(
        replace(
            item,
            name=by_role[LaunchRole.FOUNDER].name,
            organization=by_role[LaunchRole.FOUNDER].organization,
        )
        if item.roles == (LaunchRole.INDEPENDENT_TECHNICAL,)
        else item
        for item in policy.principals
    )
    with pytest.raises(FormatError, match="separate from internal"):
        replace(policy, principals=internal_identity)
    shared_independent_organization = tuple(
        replace(item, organization=by_role[LaunchRole.INDEPENDENT_TECHNICAL].organization)
        if item.roles == (LaunchRole.INDEPENDENT_ISOLATION,)
        else item
        for item in policy.principals
    )
    with pytest.raises(FormatError, match="must be separate"):
        replace(policy, principals=shared_independent_organization)
    with pytest.raises(FormatError, match="not trusted"):
        policy.principal(digest("unknown"))

    trust = copy.deepcopy(document["trustPolicy"])
    trust["principals"][0]["publicKey"] = "%%%%"
    trust = _with_digest({key: value for key, value in trust.items() if key != "contentDigest"})
    with pytest.raises(FormatError, match="base64"):
        trust_policy_from_mapping(trust)
    trust = copy.deepcopy(document["trustPolicy"])
    trust["principals"][0]["publicKey"] = base64.b64encode(b"short").decode("ascii")
    trust = _with_digest({key: value for key, value in trust.items() if key != "contentDigest"})
    with pytest.raises(FormatError, match="raw Ed25519"):
        trust_policy_from_mapping(trust)

    registry = registry_policy().to_mapping()
    malformed: list[dict[str, Any]] = []
    extra = copy.deepcopy(registry)
    extra["unknown"] = True
    malformed.append(extra)
    bad_object = copy.deepcopy(registry)
    bad_object["images"] = []
    malformed.append(bad_object)
    bad_array = copy.deepcopy(registry)
    bad_array["moderatorRoles"] = "triage"
    malformed.append(bad_array)
    bad_string = copy.deepcopy(registry)
    bad_string["images"]["sova"] = 7
    malformed.append(bad_string)
    bad_integer = copy.deepcopy(registry)
    bad_integer["requestsPerMinute"] = True
    malformed.append(bad_integer)
    bad_boolean = copy.deepcopy(registry)
    bad_boolean["backup"]["encrypted"] = "true"
    malformed.append(bad_boolean)
    for value in malformed:
        with pytest.raises(FormatError):
            registry_policy_from_mapping(value)


def _evaluate_ready_document(
    document: dict[str, Any], manifest: bytes, claims: bytes, commit: str
) -> dict[str, Any]:
    return evaluate_launch_bundle(
        launch_bundle_from_mapping(document),
        artifact_manifest=manifest,
        claims_register=claims,
        public_claims_snapshot=_public_claims_snapshot(commit),
        expected_commit=commit,
        expected_trust_policy_digest=_trust_digest(document),
    )


def test_signed_receipt_roles_identities_and_bindings_fail_closed() -> None:
    document, manifest, claims, commit, keys = _ready_bundle()

    wrong_role = copy.deepcopy(document)
    operational_payload = _signed_payload(wrong_role["operationalReceipts"][0])
    wrong_role["operationalReceipts"][0] = _sign(
        operational_payload, keys[LaunchRole.RELEASE_OPERATOR]
    )
    with pytest.raises(FormatError, match="registry-operator"):
        _evaluate_ready_document(_refresh_bundle(wrong_role), manifest, claims, commit)

    wrong_issuer = copy.deepcopy(document)
    operational_payload = _signed_payload(wrong_issuer["operationalReceipts"][0])
    operational_payload["issuer"] = "different-operator"
    wrong_issuer["operationalReceipts"][0] = _sign(
        operational_payload, keys[LaunchRole.REGISTRY_OPERATOR]
    )
    with pytest.raises(FormatError, match="issuer does not match"):
        _evaluate_ready_document(_refresh_bundle(wrong_issuer), manifest, claims, commit)

    wrong_reviewer = copy.deepcopy(document)
    review_payload = _signed_payload(wrong_reviewer["reviewReceipts"][0])
    review_payload["reviewer"] = "someone-else"
    wrong_reviewer["reviewReceipts"][0] = _sign(review_payload, keys[LaunchRole.FOUNDER])
    with pytest.raises(FormatError, match="review identity"):
        _evaluate_ready_document(_refresh_bundle(wrong_reviewer), manifest, claims, commit)

    wrong_gate_identity = copy.deepcopy(document)
    gate_payload = _signed_payload(wrong_gate_identity["gateReceipts"][0])
    gate_payload["organization"] = "different-organization"
    wrong_gate_identity["gateReceipts"][0] = _sign(gate_payload, keys[LaunchRole.P5_OPERATOR])
    with pytest.raises(FormatError, match="gate identity"):
        _evaluate_ready_document(_refresh_bundle(wrong_gate_identity), manifest, claims, commit)

    duplicate_gate = copy.deepcopy(document)
    duplicate_gate["gateReceipts"][1] = duplicate_gate["gateReceipts"][0]
    with pytest.raises(FormatError, match="duplicated"):
        _evaluate_ready_document(_refresh_bundle(duplicate_gate), manifest, claims, commit)

    for field, value, message in (
        ("releaseCommit", "different-commit", "another release"),
        ("subjectDigest", digest("different-subject"), "another subject"),
    ):
        drifted = copy.deepcopy(document)
        gate_payload = _signed_payload(drifted["gateReceipts"][0])
        gate_payload[field] = value
        drifted["gateReceipts"][0] = _sign(gate_payload, keys[LaunchRole.P5_OPERATOR])
        with pytest.raises(FormatError, match=message):
            _evaluate_ready_document(_refresh_bundle(drifted), manifest, claims, commit)

    wrong_protocol = copy.deepcopy(document)
    ledger = _signed_payload(wrong_protocol["observationLedger"])
    ledger["protocolDigest"] = digest("different-protocol")
    ledger = _with_digest({key: value for key, value in ledger.items() if key != "contentDigest"})
    wrong_protocol["observationLedger"] = _sign(ledger, keys[LaunchRole.EVALUATION_CUSTODIAN])
    with pytest.raises(FormatError, match="another protocol"):
        _evaluate_ready_document(_refresh_bundle(wrong_protocol), manifest, claims, commit)


def test_candidate_and_external_trust_pins_fail_closed() -> None:
    document, manifest, claims, commit, _keys = _ready_bundle()
    bundle = launch_bundle_from_mapping(document)
    with pytest.raises(FormatError, match="externally pinned"):
        evaluate_launch_bundle(
            bundle,
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit),
            expected_commit=commit,
            expected_trust_policy_digest=digest("different-policy"),
        )
    with pytest.raises(FormatError, match="claims register bytes"):
        evaluate_launch_bundle(
            bundle,
            artifact_manifest=manifest,
            claims_register=b"different claims",
            public_claims_snapshot=_public_claims_snapshot(commit),
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(document),
        )
    with pytest.raises(FormatError, match="snapshot bytes"):
        evaluate_launch_bundle(
            bundle,
            artifact_manifest=manifest,
            claims_register=claims,
            public_claims_snapshot=_public_claims_snapshot(commit, ready=False),
            expected_commit=commit,
            expected_trust_policy_digest=_trust_digest(document),
        )

    wrong_candidate_pin = copy.deepcopy(document)
    wrong_candidate_pin["trustPolicy"]["releaseCandidateDigest"] = digest("other-candidate")
    wrong_candidate_pin = _refresh_trust(wrong_candidate_pin)
    with pytest.raises(FormatError, match="another release candidate"):
        _evaluate_ready_document(wrong_candidate_pin, manifest, claims, commit)

    for field, message in (
        ("evaluationReportDigest", "evaluation report digest drifted"),
        ("registryReadinessDigest", "Registry readiness digest drifted"),
        ("publicClaimsSnapshotDigest", "public claims snapshot bytes do not match release"),
        ("rollbackTestDigest", "rollback receipt digest drifted"),
        ("incidentTestDigest", "incident receipt digest drifted"),
    ):
        drifted = copy.deepcopy(document)
        drifted["candidate"][field] = digest(f"different:{field}")
        drifted["trustPolicy"]["releaseCandidateDigest"] = sha256_digest(
            canonical_json_bytes(drifted["candidate"])
        )
        drifted = _refresh_trust(drifted)
        with pytest.raises(FormatError, match=message):
            _evaluate_ready_document(drifted, manifest, claims, commit)


def test_protocol_derived_fields_and_signing_key_size_are_verified() -> None:
    plan = protocol().to_mapping()
    plan["runCount"] += 1
    with pytest.raises(FormatError, match="derived fields"):
        protocol_from_mapping(plan)

    ledger = _with_digest(
        {
            "artifactType": "sova.evaluation-observation-ledger",
            "schemaVersion": "0.1.0",
            "protocolDigest": protocol().digest,
            "observations": [],
        }
    )
    with pytest.raises(FormatError, match="raw Ed25519"):
        sign_launch_evidence(ledger, b"short", b"short")
