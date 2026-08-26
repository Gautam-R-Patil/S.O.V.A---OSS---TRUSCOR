# SPDX-License-Identifier: Apache-2.0
"""Guarded irreversible-effect opt-in on `AuthorityEnvelope`."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from sova.formats.errors import FormatError
from sova.safety import (
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
)
from sova.safety.authorization import ActionIntent

NOW = datetime(2030, 1, 1, tzinfo=UTC)
TARGET = "sova:sandbox:owned-target"
CONTAINMENT = "sha256:" + "c" * 64


def _principal(kind: PrincipalKind, suffix: str) -> Principal:
    return Principal(f"sova:principal:{suffix}", kind, suffix)


def _scope() -> Scope:
    return Scope(
        targets=frozenset({TARGET}),
        actions=frozenset({"filesystem.delete"}),
        paths=frozenset({"/fixture/work"}),
    )


def _authority(
    *,
    ownership: str = "self",
    allow_irreversible: bool = False,
    max_effect: EffectClass = EffectClass.DESTRUCTIVE,
) -> AuthorityEnvelope:
    return AuthorityEnvelope(
        id="sova:authorization:irreversible-test",
        issued_by=_principal(PrincipalKind.HUMAN, "owner"),
        subject=_principal(PrincipalKind.AGENT, "agent"),
        scope=_scope(),
        max_effect=max_effect,
        budget=EffectBudget(max_steps=4, max_duration_ms=1000, max_mutations=2, max_files=2),
        valid_from=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        single_use=True,
        ownership=ownership,
        required_containment_digest=CONTAINMENT,
        allow_irreversible=allow_irreversible,
    )


def _proof() -> ControlProof:
    challenge = "sova-control:test"
    return ControlProof(
        method=ControlProofMethod.SANDBOX,
        subject=TARGET,
        challenge=challenge,
        evidence={"challenge": challenge, "synthetic": True},
        observed_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
        verifier="sova.synthetic-world/0.1",
    )


def _legal_proof() -> ControlProof:
    return ControlProof(
        method=ControlProofMethod.LEGAL_ACQUISITION,
        subject=TARGET,
        challenge="sova-legal:test",
        evidence={
            "offlineOnly": True,
            "source": "purchased-fixture",
            "licenseOrAuthority": "test-license",
        },
        observed_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
        verifier="sova.legal-acquisition/0.1",
    )


def _intent(*, irreversible: bool) -> ActionIntent:
    return ActionIntent(
        id="sova:intent:delete",
        target=TARGET,
        action="filesystem.delete",
        effect=EffectClass.DESTRUCTIVE,
        required_evidence=frozenset({"deleted-content-digest"}),
        cost=BudgetCost(steps=1, mutations=1, files=1),
        path="/fixture/work/item.txt",
        irreversible=irreversible,
    )


def test_default_authority_still_blocks_irreversible() -> None:
    session = AuthorizationSession(
        authority=_authority(allow_irreversible=False),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=AuthorizationKernel(),
    )
    decision = session.authorize(_intent(irreversible=True), now=NOW)
    assert not decision.allowed
    assert "irreversible-effect-prohibited" in decision.reasons


def test_opted_in_authority_allows_irreversible_with_destructive_approval() -> None:
    approval_authority = OutOfBandApprovalAuthority(b"k" * 32)
    kernel = AuthorizationKernel(approval_authority)
    authority = _authority(allow_irreversible=True)
    intent = _intent(irreversible=True)
    challenge = approval_authority.challenge(
        authority, intent, level=ApprovalLevel.DESTRUCTIVE, now=NOW
    )
    token = approval_authority.approve(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    session = AuthorizationSession(
        authority=authority,
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=kernel,
    )
    decision = session.authorize(intent, approval=token, now=NOW)
    assert decision.allowed
    assert "irreversible-effect-prohibited" not in decision.reasons


def test_opted_in_authority_still_requires_destructive_not_normal_approval() -> None:
    approval_authority = OutOfBandApprovalAuthority(b"k" * 32)
    kernel = AuthorizationKernel(approval_authority)
    authority = _authority(allow_irreversible=True)
    intent = _intent(irreversible=True)
    # Only a NORMAL-level approval is presented for an irreversible action.
    challenge = approval_authority.challenge(authority, intent, level=ApprovalLevel.NORMAL, now=NOW)
    token = approval_authority.approve(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    session = AuthorizationSession(
        authority=authority,
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=kernel,
    )
    decision = session.authorize(intent, approval=token, now=NOW)
    assert not decision.allowed
    assert "approval-level-insufficient" in decision.reasons


def test_legal_offline_authority_cannot_construct_with_irreversible_opt_in() -> None:
    with pytest.raises(FormatError, match="offline legal-acquisition authority"):
        _authority(ownership="legal-offline", allow_irreversible=True)


def test_reversible_intent_is_unaffected_by_opt_in_flag() -> None:
    for allow_irreversible in (False, True):
        session = AuthorizationSession(
            authority=_authority(allow_irreversible=allow_irreversible),
            proof=_proof(),
            containment_allowed=True,
            containment_digest=CONTAINMENT,
            kernel=AuthorizationKernel(),
        )
        decision = session.authorize(
            replace(_intent(irreversible=False), id="sova:intent:reversible"), now=NOW
        )
        # No approval token supplied; a DESTRUCTIVE-effect intent still needs one,
        # but "irreversible-effect-prohibited" itself must never appear here.
        assert "irreversible-effect-prohibited" not in decision.reasons
