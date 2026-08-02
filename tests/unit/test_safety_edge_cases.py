# SPDX-License-Identifier: Apache-2.0
"""Malformed and adversarial edge coverage for Topic 07 controls."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from sova.formats.errors import FormatError
from sova.safety import (
    ActionIntent,
    ApprovalLevel,
    AuthorityEnvelope,
    AuthorizationKernel,
    AuthorizationSession,
    BudgetCost,
    ControlProof,
    ControlProofMethod,
    EffectBudget,
    EffectClass,
    OutOfBandApprovalAuthority,
    Principal,
    PrincipalKind,
    Scope,
    validate_control_proof,
)
from sova.safety.authorization import BudgetLedger

if TYPE_CHECKING:
    from collections.abc import Callable

NOW = datetime(2030, 1, 1, tzinfo=UTC)
TARGET = "sova:sandbox:edge"
DIGEST = "sha256:" + "e" * 64


def _scope() -> Scope:
    return Scope(frozenset({TARGET}), frozenset({"tool.invoke"}))


def _authority(**changes: object) -> AuthorityEnvelope:
    values: dict[str, object] = {
        "id": "authority",
        "issued_by": Principal("human", PrincipalKind.HUMAN, "owner"),
        "subject": Principal("agent", PrincipalKind.AGENT, "agent"),
        "scope": _scope(),
        "max_effect": EffectClass.DESTRUCTIVE,
        "budget": EffectBudget(max_steps=2, max_duration_ms=100),
        "valid_from": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(minutes=1),
        "single_use": True,
        "ownership": "self",
        "required_containment_digest": DIGEST,
    }
    values.update(changes)
    return AuthorityEnvelope(**values)  # type: ignore[arg-type]


def _proof(method: ControlProofMethod, evidence: dict[str, object]) -> ControlProof:
    return ControlProof(
        method,
        TARGET,
        "challenge",
        evidence,
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=1),
        "edge-test",
    )


def _intent(**changes: object) -> ActionIntent:
    values: dict[str, object] = {
        "id": "intent",
        "target": TARGET,
        "action": "tool.invoke",
        "effect": EffectClass.OBSERVE,
        "required_evidence": frozenset({"tool.result"}),
    }
    values.update(changes)
    return ActionIntent(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: Principal("", PrincipalKind.HUMAN, "owner"),
        lambda: Scope(frozenset(), frozenset({"read"})),
        lambda: Scope(frozenset({TARGET}), frozenset({""})),
        lambda: Scope(frozenset({TARGET}), frozenset({"read"}), domains=frozenset({"*."})),
        lambda: EffectBudget(max_steps=0, max_duration_ms=1),
        lambda: EffectBudget(max_steps=1, max_duration_ms=1, max_files=-1),
        lambda: BudgetCost(tokens=-1),
        lambda: ActionIntent("", TARGET, "read", EffectClass.READ, frozenset({"event"})),
        lambda: ActionIntent("id", TARGET, "read", EffectClass.READ, frozenset()),
    ],
)
def test_invalid_authorization_primitives_fail_closed(factory: Callable[[], object]) -> None:
    with pytest.raises(FormatError):
        factory()


def test_naive_time_and_invalid_authority_windows_are_refused() -> None:
    naive = datetime(2030, 1, 1, tzinfo=UTC).replace(tzinfo=None)
    with pytest.raises(FormatError, match="timezone"):
        ControlProof(
            ControlProofMethod.SANDBOX,
            TARGET,
            "challenge",
            {"challenge": "challenge"},
            naive,
            NOW,
            "test",
        ).to_mapping()
    with pytest.raises(FormatError, match="timezones"):
        _authority(valid_from=naive)
    with pytest.raises(FormatError, match="follow issuance"):
        _authority(valid_from=NOW, expires_at=NOW)
    with pytest.raises(FormatError, match="ownership"):
        _authority(ownership="assumed")
    with pytest.raises(FormatError, match="identity"):
        _authority(id="")
    with pytest.raises(FormatError, match="containment digest"):
        _authority(required_containment_digest="unbound")
    assert _authority().digest.startswith("sha256:")


def test_control_proof_requires_complete_identity_and_ordered_window() -> None:
    with pytest.raises(FormatError, match="non-empty"):
        replace(_proof(ControlProofMethod.SANDBOX, {"challenge": "challenge"}), verifier="")
    with pytest.raises(FormatError, match="follow observation"):
        replace(
            _proof(ControlProofMethod.SANDBOX, {"challenge": "challenge"}),
            observed_at=NOW,
            expires_at=NOW,
        )


def test_every_control_proof_family_has_positive_and_negative_cases() -> None:
    loopback = replace(_proof(ControlProofMethod.LOOPBACK, {}), subject="localhost")
    assert validate_control_proof(loopback, target="localhost", now=NOW)[0]
    assert not validate_control_proof(
        replace(loopback, subject="public.example"), target="public.example", now=NOW
    )[0]

    well_known = replace(
        _proof(
            ControlProofMethod.WELL_KNOWN,
            {
                "https": True,
                "statusCode": 200,
                "finalHost": "example.invalid",
                "redirected": False,
                "body": "challenge",
            },
        ),
        subject="example.invalid",
    )
    assert validate_control_proof(well_known, target="example.invalid", now=NOW)[0]

    dns = replace(
        _proof(ControlProofMethod.DNS, {"txtValues": ["challenge"]}),
        subject="example.invalid",
    )
    assert validate_control_proof(dns, target="example.invalid", now=NOW)[0]
    assert not validate_control_proof(
        replace(dns, evidence={"txtValues": "challenge"}),
        target="example.invalid",
        now=NOW,
    )[0]

    signed = _proof(
        ControlProofMethod.SIGNED_MANIFEST,
        {"keyId": "key-1", "signatureValid": True, "challenge": "challenge"},
    )
    assert validate_control_proof(
        signed, target=TARGET, now=NOW, trusted_key_ids=frozenset({"key-1"})
    )[0]
    invalid_signed = replace(
        signed,
        evidence={"keyId": 7, "signatureValid": False, "challenge": "wrong"},
    )
    allowed, reasons = validate_control_proof(invalid_signed, target=TARGET, now=NOW)
    assert not allowed
    assert {
        "untrusted-control-key",
        "control-signature-invalid",
        "signed-challenge-mismatch",
    }.issubset(reasons)

    scoped = replace(signed, method=ControlProofMethod.SCOPED_DOCUMENT)
    assert validate_control_proof(
        scoped, target=TARGET, now=NOW, trusted_key_ids=frozenset({"key-1"})
    )[0]
    legal = _proof(
        ControlProofMethod.LEGAL_ACQUISITION,
        {"offlineOnly": True, "source": "archive", "licenseOrAuthority": "Apache-2.0"},
    )
    assert validate_control_proof(legal, target=TARGET, now=NOW)[0]
    assert not validate_control_proof(
        replace(legal, evidence={"offlineOnly": False}), target=TARGET, now=NOW
    )[0]


def test_budget_ledger_refuses_direct_overconsumption() -> None:
    ledger = BudgetLedger(EffectBudget(max_steps=1, max_duration_ms=1))
    with pytest.raises(FormatError, match="exceeded"):
        ledger.consume(BudgetCost(steps=2))


def test_approval_channel_rejects_configuration_phrase_and_tampering() -> None:
    with pytest.raises(FormatError, match="32 bytes"):
        OutOfBandApprovalAuthority(b"short")
    with pytest.raises(FormatError, match="out-of-band"):
        OutOfBandApprovalAuthority(b"k" * 32, channel="in-band")

    channel = OutOfBandApprovalAuthority(b"k" * 32)
    intent = _intent(effect=EffectClass.MUTATE)
    challenge = channel.challenge(_authority(), intent, level=ApprovalLevel.NORMAL, now=NOW)
    reviewer = Principal("reviewer", PrincipalKind.HUMAN, "reviewer")
    with pytest.raises(FormatError, match="phrase"):
        channel.approve(
            challenge,
            approver=reviewer,
            exact_phrase="wrong",
            reviewed_effects=True,
        )
    token = channel.approve(
        challenge,
        approver=reviewer,
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    mutations = (
        replace(token, signature="bad"),
        replace(token, authority_id="other"),
        replace(token, approver=Principal("service", PrincipalKind.SERVICE, "service")),
        replace(token, channel="other"),
        replace(token, expires_at=NOW),
    )
    expected = (
        "approval-signature-invalid",
        "approval-scope-mismatch",
        "approval-not-human-out-of-band",
        "approval-not-human-out-of-band",
        "approval-expired",
    )
    for candidate, reason in zip(mutations, expected, strict=True):
        allowed, reasons = channel.consume(
            candidate,
            authority_id="authority",
            intent_digest=intent.digest,
            minimum_level=ApprovalLevel.NORMAL,
            now=NOW,
        )
        assert not allowed
        assert reason in reasons


def test_authority_currentness_and_legal_offline_rules_are_enforced() -> None:
    proof = _proof(ControlProofMethod.SANDBOX, {"challenge": "challenge"})
    expired = AuthorizationSession(
        authority=_authority(expires_at=NOW),
        proof=proof,
        containment_allowed=True,
        containment_digest=DIGEST,
        kernel=AuthorizationKernel(),
    ).authorize(_intent(), now=NOW)
    assert "authority-not-current" in expired.reasons

    legal_authority = _authority(ownership="legal-offline")
    wrong_proof = AuthorizationSession(
        authority=legal_authority,
        proof=proof,
        containment_allowed=True,
        containment_digest=DIGEST,
        kernel=AuthorizationKernel(),
    ).authorize(_intent(), now=NOW)
    assert "legal-offline-proof-required" in wrong_proof.reasons

    legal_proof = _proof(
        ControlProofMethod.LEGAL_ACQUISITION,
        {"offlineOnly": True, "source": "archive", "licenseOrAuthority": "licence"},
    )
    external = AuthorizationSession(
        authority=replace(legal_authority, max_effect=EffectClass.EXTERNAL),
        proof=legal_proof,
        containment_allowed=True,
        containment_digest=DIGEST,
        kernel=AuthorizationKernel(),
    ).authorize(_intent(effect=EffectClass.EXTERNAL), now=NOW)
    assert "legal-acquisition-is-offline-only" in external.reasons


def test_empty_invocation_claim_is_refused() -> None:
    session = AuthorizationSession(
        authority=_authority(),
        proof=_proof(ControlProofMethod.SANDBOX, {"challenge": "challenge"}),
        containment_allowed=True,
        containment_digest=DIGEST,
        kernel=AuthorizationKernel(),
    )
    with pytest.raises(FormatError, match="cannot be empty"):
        session.claim_invocation("")
