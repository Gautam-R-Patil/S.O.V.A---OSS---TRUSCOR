# SPDX-License-Identifier: Apache-2.0
"""`full_capability_authority` profile: convenience wiring, not new trust logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sova.formats.errors import FormatError
from sova.safety import (
    ApprovalLevel,
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
    full_capability_authority,
)
from sova.safety.authorization import ActionIntent

NOW = datetime(2030, 1, 1, tzinfo=UTC)
TARGET = "authorized.example.invalid"
CONTAINMENT = "sha256:" + "f" * 64


def _principal(kind: PrincipalKind, suffix: str) -> Principal:
    return Principal(f"sova:principal:{suffix}", kind, suffix)


def _budget() -> EffectBudget:
    return EffectBudget(
        max_steps=16, max_duration_ms=60_000, max_mutations=8, max_network_requests=8
    )


def _valid_proof(*, target: str = TARGET) -> ControlProof:
    challenge = "sova-control:full-capability"
    return ControlProof(
        method=ControlProofMethod.WELL_KNOWN,
        subject=target,
        challenge=challenge,
        evidence={
            "https": True,
            "statusCode": 200,
            "finalHost": target,
            "redirected": False,
            "body": challenge,
        },
        observed_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=30),
        verifier="sova.well-known/0.1",
    )


def _legal_proof() -> ControlProof:
    return ControlProof(
        method=ControlProofMethod.LEGAL_ACQUISITION,
        subject="sova:local-software:fixture",
        challenge="sova-legal:full-capability",
        evidence={
            "offlineOnly": True,
            "source": "purchased-fixture",
            "licenseOrAuthority": "test-license",
        },
        observed_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=30),
        verifier="sova.legal-acquisition/0.1",
    )


def test_rejects_an_invalid_or_expired_proof() -> None:
    expired = ControlProof(
        method=ControlProofMethod.WELL_KNOWN,
        subject=TARGET,
        challenge="c",
        evidence={
            "https": True,
            "statusCode": 200,
            "finalHost": TARGET,
            "redirected": False,
            "body": "c",
        },
        observed_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=5),
        verifier="sova.well-known/0.1",
    )
    with pytest.raises(FormatError, match="already-valid control proof"):
        full_capability_authority(
            target=TARGET,
            subject=_principal(PrincipalKind.AGENT, "agent"),
            issued_by=_principal(PrincipalKind.HUMAN, "owner"),
            proof=expired,
            containment_digest=CONTAINMENT,
            budget=_budget(),
            now=NOW,
        )


def test_agent_cannot_be_the_issuer() -> None:
    with pytest.raises(FormatError, match="cannot be issued by an agent"):
        full_capability_authority(
            target=TARGET,
            subject=_principal(PrincipalKind.AGENT, "agent"),
            issued_by=_principal(PrincipalKind.AGENT, "not-human"),
            proof=_valid_proof(),
            containment_digest=CONTAINMENT,
            budget=_budget(),
            now=NOW,
        )


def test_ownership_must_match_proof_method() -> None:
    with pytest.raises(FormatError, match="must match the control proof method"):
        full_capability_authority(
            target=TARGET,
            subject=_principal(PrincipalKind.AGENT, "agent"),
            issued_by=_principal(PrincipalKind.HUMAN, "owner"),
            proof=_valid_proof(),
            containment_digest=CONTAINMENT,
            budget=_budget(),
            ownership="legal-offline",
            now=NOW,
        )
    with pytest.raises(FormatError, match="must match the control proof method"):
        full_capability_authority(
            target="sova:local-software:fixture",
            subject=_principal(PrincipalKind.AGENT, "agent"),
            issued_by=_principal(PrincipalKind.HUMAN, "owner"),
            proof=_legal_proof(),
            containment_digest=CONTAINMENT,
            budget=_budget(),
            ownership="self",
            now=NOW,
        )


def test_offensive_and_irreversible_require_owned_not_legal_offline() -> None:
    with pytest.raises(FormatError, match="proven self/explicit ownership"):
        full_capability_authority(
            target="sova:local-software:fixture",
            subject=_principal(PrincipalKind.AGENT, "agent"),
            issued_by=_principal(PrincipalKind.HUMAN, "owner"),
            proof=_legal_proof(),
            containment_digest=CONTAINMENT,
            budget=_budget(),
            ownership="legal-offline",
            allow_irreversible=True,
            now=NOW,
        )


def test_empty_action_classes_rejected() -> None:
    with pytest.raises(FormatError, match="at least one action class"):
        full_capability_authority(
            target=TARGET,
            subject=_principal(PrincipalKind.AGENT, "agent"),
            issued_by=_principal(PrincipalKind.HUMAN, "owner"),
            proof=_valid_proof(),
            containment_digest=CONTAINMENT,
            budget=_budget(),
            action_classes=(),
            now=NOW,
        )


def test_external_effect_permitted_on_authorized_domain_denied_on_other() -> None:
    authority = full_capability_authority(
        target=TARGET,
        subject=_principal(PrincipalKind.AGENT, "agent"),
        issued_by=_principal(PrincipalKind.HUMAN, "owner"),
        proof=_valid_proof(),
        containment_digest=CONTAINMENT,
        budget=_budget(),
        domains=frozenset({TARGET}),
        now=NOW,
    )
    approval_authority = OutOfBandApprovalAuthority(b"k" * 32)
    kernel = AuthorizationKernel(approval_authority)

    def _intent(*, domain: str) -> ActionIntent:
        return ActionIntent(
            id=f"sova:intent:submit:{domain}",
            target=TARGET,
            action="browser.submit",
            effect=EffectClass.EXTERNAL,
            required_evidence=frozenset({"post-observation-digest"}),
            cost=BudgetCost(steps=1, network_requests=1),
            domain=domain,
        )

    authorized_intent = _intent(domain=TARGET)
    challenge = approval_authority.challenge(
        authority, authorized_intent, level=ApprovalLevel.EXTERNAL, now=NOW
    )
    token = approval_authority.approve(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    session = AuthorizationSession(
        authority=authority,
        proof=_valid_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=kernel,
    )
    allowed_decision = session.authorize(authorized_intent, approval=token, now=NOW)
    assert allowed_decision.allowed

    off_target_intent = _intent(domain="unrelated.example.invalid")
    denied_decision = session.authorize(off_target_intent, now=NOW)
    assert not denied_decision.allowed
    assert "domain-out-of-scope" in denied_decision.reasons


def test_settings_change_and_form_submit_are_not_categorically_blocked() -> None:
    """Regression guard: guardrails gate MUTATE/EXTERNAL effects, they never cap them."""
    authority = full_capability_authority(
        target=TARGET,
        subject=_principal(PrincipalKind.AGENT, "agent"),
        issued_by=_principal(PrincipalKind.HUMAN, "owner"),
        proof=_valid_proof(),
        containment_digest=CONTAINMENT,
        budget=_budget(),
        domains=frozenset({TARGET}),
        now=NOW,
    )
    approval_authority = OutOfBandApprovalAuthority(b"k" * 32)
    kernel = AuthorizationKernel(approval_authority)
    intent = ActionIntent(
        id="sova:intent:change-setting",
        target=TARGET,
        action="browser.click",
        effect=EffectClass.MUTATE,
        required_evidence=frozenset({"post-observation-digest"}),
        cost=BudgetCost(steps=1, mutations=1),
        domain=TARGET,
    )
    challenge = approval_authority.challenge(authority, intent, level=ApprovalLevel.NORMAL, now=NOW)
    token = approval_authority.approve(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    session = AuthorizationSession(
        authority=authority,
        proof=_valid_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=kernel,
    )
    decision = session.authorize(intent, approval=token, now=NOW)
    assert decision.allowed
