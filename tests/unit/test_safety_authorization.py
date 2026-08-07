# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the authority-containment-evidence kernel."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

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
    InteractiveTerminalApprovalAuthority,
    OutOfBandApprovalAuthority,
    Principal,
    PrincipalKind,
    Scope,
    validate_control_proof,
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)
TARGET = "sova:sandbox:owned-target"
CONTAINMENT = "sha256:" + "c" * 64


def _principal(kind: PrincipalKind, suffix: str) -> Principal:
    return Principal(f"sova:principal:{suffix}", kind, suffix)


def _scope() -> Scope:
    return Scope(
        targets=frozenset({TARGET}),
        actions=frozenset({"tool.invoke", "filesystem.delete"}),
        paths=frozenset({"/fixture/work"}),
        tools=frozenset({"safe-tool"}),
        identities=frozenset({"synthetic-user"}),
        domains=frozenset({"api.example.invalid", "*.sandbox.example.invalid"}),
    )


def _authority(*, max_effect: EffectClass = EffectClass.DESTRUCTIVE) -> AuthorityEnvelope:
    return AuthorityEnvelope(
        id="sova:authorization:test",
        issued_by=_principal(PrincipalKind.HUMAN, "owner"),
        subject=_principal(PrincipalKind.AGENT, "agent"),
        scope=_scope(),
        max_effect=max_effect,
        budget=EffectBudget(
            max_steps=4,
            max_duration_ms=1000,
            max_mutations=2,
            max_files=2,
            max_network_requests=1,
        ),
        valid_from=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=5),
        single_use=True,
        ownership="self",
        required_containment_digest=CONTAINMENT,
    )


def _proof(*, target: str = TARGET) -> ControlProof:
    challenge = "sova-control:test"
    return ControlProof(
        method=ControlProofMethod.SANDBOX,
        subject=target,
        challenge=challenge,
        evidence={"challenge": challenge, "synthetic": True},
        observed_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
        verifier="sova.synthetic-world/0.1",
    )


def _intent(
    *,
    effect: EffectClass = EffectClass.OBSERVE,
    offensive: bool = False,
) -> ActionIntent:
    return ActionIntent(
        id="sova:intent:test",
        target=TARGET,
        action="tool.invoke",
        effect=effect,
        required_evidence=frozenset({"tool.result", "oracle.completed"}),
        cost=BudgetCost(
            steps=1,
            duration_ms=10,
            mutations=int(effect >= EffectClass.MUTATE),
            network_requests=int(effect >= EffectClass.EXTERNAL),
        ),
        path="/fixture/work/item.txt",
        tool="safe-tool",
        identity="synthetic-user",
        domain="child.sandbox.example.invalid",
        offensive=offensive,
    )


def test_agents_cannot_issue_authority_or_self_approve() -> None:
    with pytest.raises(FormatError, match="agent cannot issue authority"):
        replace(_authority(), issued_by=_principal(PrincipalKind.AGENT, "issuer"))

    approval_authority = OutOfBandApprovalAuthority(b"k" * 32)
    challenge = approval_authority.challenge(
        _authority(),
        _intent(effect=EffectClass.MUTATE),
        level=ApprovalLevel.NORMAL,
        now=NOW,
    )
    with pytest.raises(FormatError, match="cannot approve"):
        approval_authority.approve(
            challenge,
            approver=_principal(PrincipalKind.AGENT, "self"),
            exact_phrase=challenge.exact_phrase,
            reviewed_effects=False,
        )


def test_exact_scope_checks_every_declared_dimension() -> None:
    intent = _intent()
    allowed, reasons = _scope().allows(intent)
    assert allowed
    assert reasons == ()
    mutations = (
        (replace(intent, target="sova:sandbox:other"), "target-out-of-scope"),
        (replace(intent, action="other.action"), "action-out-of-scope"),
        (replace(intent, path="/fixture/work-evil/item"), "path-out-of-scope"),
        (replace(intent, tool="other-tool"), "tool-out-of-scope"),
        (replace(intent, identity="real-user"), "identity-out-of-scope"),
        (replace(intent, domain="sandbox.example.invalid"), "domain-out-of-scope"),
    )
    for candidate, reason in mutations:
        candidate_allowed, candidate_reasons = _scope().allows(candidate)
        assert not candidate_allowed
        assert reason in candidate_reasons


@given(st.sampled_from(["/fixture/work/../escape", "/fixture/work\x00secret"]))
def test_non_normal_paths_are_refused(path: str) -> None:
    with pytest.raises(FormatError):
        replace(_intent(), path=path)


def test_url_alone_is_not_control_proof_and_proofs_expire() -> None:
    url_only = ControlProof(
        ControlProofMethod.WELL_KNOWN,
        "example.invalid",
        "challenge",
        {"url": "https://example.invalid/.well-known/sova-control"},
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=1),
        "fixture",
    )
    allowed, reasons = validate_control_proof(url_only, target="example.invalid", now=NOW)
    assert not allowed
    assert "well-known-proof-invalid" in reasons

    expired = replace(_proof(), expires_at=NOW)
    assert validate_control_proof(expired, target=TARGET, now=NOW)[0] is False


def test_kernel_fails_closed_on_containment_scope_effect_and_budget() -> None:
    session = AuthorizationSession(
        _authority(max_effect=EffectClass.READ),
        _proof(),
        containment_allowed=False,
        containment_digest="sha256:" + "d" * 64,
        kernel=AuthorizationKernel(),
    )
    decision = session.authorize(_intent(effect=EffectClass.EXTERNAL), now=NOW)
    assert not decision.allowed
    assert {
        "containment-binding-mismatch",
        "containment-not-admissible",
        "effect-exceeds-authority",
        "fresh-out-of-band-approval-required",
    }.issubset(decision.reasons)
    assert session.ledger.used.steps == 0


def test_observe_decision_binds_distinct_scope_intent_proof_and_containment() -> None:
    session = AuthorizationSession(
        _authority(),
        _proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=AuthorizationKernel(),
    )
    decision = session.authorize(_intent(), now=NOW)
    mapping = decision.to_mapping()
    assert decision.allowed
    assert mapping["scopeDigest"] != mapping["intentDigest"]
    assert mapping["proofDigest"].startswith("sha256:")
    assert mapping["containmentDigest"] == CONTAINMENT
    assert mapping["authorizationDigest"].startswith("sha256:")
    assert mapping["issuedBy"] == {"id": "sova:principal:owner", "kind": "human"}
    assert mapping["subject"] == {"id": "sova:principal:agent", "kind": "agent"}
    assert mapping["ownership"] == "self"
    assert mapping["requiredEvidence"] == ["oracle.completed", "tool.result"]
    assert mapping["budgetAfter"]["steps"] == 1


def test_mutation_requires_fresh_single_use_human_approval() -> None:
    approval_authority = OutOfBandApprovalAuthority(b"a" * 32)
    kernel = AuthorizationKernel(approval_authority)
    intent = _intent(effect=EffectClass.MUTATE)
    challenge = approval_authority.challenge(
        _authority(), intent, level=ApprovalLevel.NORMAL, now=NOW
    )
    token = approval_authority.approve(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    first = AuthorizationSession(
        authority=_authority(),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=kernel,
    ).authorize(intent, approval=token, now=NOW)
    second = AuthorizationSession(
        authority=_authority(),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=kernel,
    ).authorize(intent, approval=token, now=NOW)
    assert first.allowed
    assert not second.allowed
    assert "approval-already-used" in second.reasons


def test_interactive_batch_approval_binds_every_exact_intent_once() -> None:
    approval_authority = InteractiveTerminalApprovalAuthority(b"i" * 32)
    authority = _authority()
    first_intent = _intent(effect=EffectClass.MUTATE)
    second_intent = replace(
        first_intent,
        id="sova:intent:second",
        path="/fixture/work/second.txt",
    )
    challenge = approval_authority.batch_challenge(
        authority,
        (
            (first_intent, ApprovalLevel.NORMAL),
            (second_intent, ApprovalLevel.DESTRUCTIVE),
        ),
        now=NOW,
    )
    tokens = approval_authority.approve_batch(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )

    assert len(tokens) == 2
    assert tokens[0].channel == "interactive-terminal"
    assert tokens[0].intent_digest == first_intent.digest
    assert tokens[1].intent_digest == second_intent.digest
    allowed, reasons = approval_authority.consume(
        tokens[0],
        authority_id=authority.id,
        intent_digest=first_intent.digest,
        minimum_level=ApprovalLevel.NORMAL,
        now=NOW,
    )
    assert allowed
    assert reasons == ()
    replayed, replay_reasons = approval_authority.consume(
        tokens[0],
        authority_id=authority.id,
        intent_digest=first_intent.digest,
        minimum_level=ApprovalLevel.NORMAL,
        now=NOW,
    )
    assert not replayed
    assert "approval-already-used" in replay_reasons


def test_batch_approval_rejects_replay_substitution_and_nonhuman_approval() -> None:
    approval_authority = InteractiveTerminalApprovalAuthority(b"j" * 32)
    authority = _authority()
    intent = _intent(effect=EffectClass.MUTATE)
    challenge = approval_authority.batch_challenge(
        authority,
        ((intent, ApprovalLevel.DESTRUCTIVE),),
        now=NOW,
    )
    with pytest.raises(FormatError, match="cannot approve"):
        approval_authority.approve_batch(
            challenge,
            approver=_principal(PrincipalKind.AGENT, "self"),
            exact_phrase=challenge.exact_phrase,
            reviewed_effects=True,
        )
    with pytest.raises(FormatError, match="effect review"):
        approval_authority.approve_batch(
            challenge,
            approver=_principal(PrincipalKind.HUMAN, "reviewer"),
            exact_phrase=challenge.exact_phrase,
            reviewed_effects=False,
        )
    tokens = approval_authority.approve_batch(
        challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=challenge.exact_phrase,
        reviewed_effects=True,
    )
    with pytest.raises(FormatError, match="already issued"):
        approval_authority.approve_batch(
            challenge,
            approver=_principal(PrincipalKind.HUMAN, "reviewer"),
            exact_phrase=challenge.exact_phrase,
            reviewed_effects=True,
        )
    substituted = replace(intent, id="sova:intent:substituted")
    allowed, reasons = approval_authority.consume(
        tokens[0],
        authority_id=authority.id,
        intent_digest=substituted.digest,
        minimum_level=ApprovalLevel.DESTRUCTIVE,
        now=NOW,
    )
    assert not allowed
    assert "approval-scope-mismatch" in reasons


def test_offensive_intent_requires_destructive_approval_every_invocation() -> None:
    approval_authority = OutOfBandApprovalAuthority(b"b" * 32)
    intent = _intent(effect=EffectClass.OBSERVE, offensive=True)
    normal_challenge = approval_authority.challenge(
        _authority(), intent, level=ApprovalLevel.NORMAL, now=NOW
    )
    normal_token = approval_authority.approve(
        normal_challenge,
        approver=_principal(PrincipalKind.HUMAN, "reviewer"),
        exact_phrase=normal_challenge.exact_phrase,
        reviewed_effects=True,
    )
    session = AuthorizationSession(
        authority=_authority(),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=AuthorizationKernel(approval_authority),
    )
    denied = session.authorize(intent, approval=normal_token, now=NOW)
    assert not denied.allowed
    assert "approval-level-insufficient" in denied.reasons

    destructive = approval_authority.challenge(
        _authority(), intent, level=ApprovalLevel.DESTRUCTIVE, now=NOW
    )
    with pytest.raises(FormatError, match="effect review"):
        approval_authority.approve(
            destructive,
            approver=_principal(PrincipalKind.HUMAN, "reviewer"),
            exact_phrase=destructive.exact_phrase,
            reviewed_effects=False,
        )


def test_budget_consumption_is_monotone_and_never_partially_applied() -> None:
    session = AuthorizationSession(
        authority=_authority(),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=AuthorizationKernel(),
    )
    first = session.authorize(_intent(), now=NOW)
    assert first.allowed
    oversized = replace(_intent(), cost=BudgetCost(steps=4, duration_ms=1))
    denied = session.authorize(oversized, now=NOW)
    assert not denied.allowed
    assert "budget-exceeded:steps" in denied.reasons
    assert session.ledger.used.steps == 1


def test_irreversible_effects_are_hard_stopped_even_with_effect_ceiling() -> None:
    session = AuthorizationSession(
        authority=_authority(),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=AuthorizationKernel(),
    )
    decision = session.authorize(replace(_intent(), irreversible=True), now=NOW)
    assert not decision.allowed
    assert "irreversible-effect-prohibited" in decision.reasons


def test_single_use_authority_can_bind_only_one_runner_invocation() -> None:
    session = AuthorizationSession(
        authority=_authority(),
        proof=_proof(),
        containment_allowed=True,
        containment_digest=CONTAINMENT,
        kernel=AuthorizationKernel(),
    )
    session.claim_invocation("run-one")
    with pytest.raises(FormatError, match="already claimed"):
        session.claim_invocation("run-two")
