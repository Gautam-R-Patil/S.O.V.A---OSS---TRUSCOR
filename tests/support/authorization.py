# SPDX-License-Identifier: Apache-2.0
"""Test-only fresh authorization sessions for owned synthetic fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sova.executors import Capability, action_intent_for_step
from sova.safety import (
    ApprovalLevel,
    ApprovalToken,
    AuthorityEnvelope,
    AuthorizationKernel,
    AuthorizationSession,
    ControlProof,
    ControlProofMethod,
    EffectBudget,
    EffectClass,
    OutOfBandApprovalAuthority,
    Principal,
    PrincipalKind,
    Scope,
)

_TARGET = "sova:sandbox:test-owned-fixture"
_CONTAINMENT = "sha256:" + "7" * 64


@dataclass(frozen=True, slots=True)
class TestAuthorization:
    session: AuthorizationSession
    approvals: dict[str, ApprovalToken]


def authorize_synthetic_steps(
    scenario: dict[str, Any],
    capabilities: tuple[Capability, ...],
) -> TestAuthorization:
    """Authorize exact synthetic test steps with fresh per-effect approvals."""
    now = datetime.now(UTC)
    by_action = {capability.name: capability for capability in capabilities}
    steps = scenario["procedure"]["steps"]
    intents = [
        action_intent_for_step(
            scenario,
            step,
            side_effect=by_action[step["action"]].side_effect,
            evidence=by_action[step["action"]].evidence,
            target=_TARGET,
        )
        for step in steps
    ]
    scope = Scope(
        targets=frozenset({_TARGET}),
        actions=frozenset(intent.action for intent in intents),
        paths=frozenset(intent.path for intent in intents if intent.path is not None),
        tools=frozenset(intent.tool for intent in intents if intent.tool is not None),
        domains=frozenset(intent.domain for intent in intents if intent.domain is not None),
    )
    authority = AuthorityEnvelope(
        id="sova:authorization:test-owned-fixture",
        issued_by=Principal("sova:principal:test-owner", PrincipalKind.HUMAN, "test owner"),
        subject=Principal("sova:principal:test-agent", PrincipalKind.AGENT, "test agent"),
        scope=scope,
        max_effect=EffectClass.DESTRUCTIVE,
        budget=EffectBudget(
            max_steps=max(1, len(intents)),
            max_duration_ms=max(1, sum(intent.cost.duration_ms for intent in intents)),
            max_mutations=sum(intent.cost.mutations for intent in intents),
            max_processes=sum(intent.cost.processes for intent in intents),
            max_files=sum(intent.cost.files for intent in intents),
            max_network_requests=sum(intent.cost.network_requests for intent in intents),
        ),
        valid_from=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
        single_use=True,
        ownership="self",
        required_containment_digest=_CONTAINMENT,
    )
    challenge = "sova-control:test-owned-fixture"
    proof = ControlProof(
        method=ControlProofMethod.SANDBOX,
        subject=_TARGET,
        challenge=challenge,
        evidence={"challenge": challenge, "synthetic": True},
        observed_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
        verifier="sova.test-fixture/0.1",
    )
    approver = Principal("sova:principal:test-reviewer", PrincipalKind.HUMAN, "test reviewer")
    approval_authority = OutOfBandApprovalAuthority(b"test-only-approval-channel-key!!" * 2)
    approvals: dict[str, ApprovalToken] = {}
    for step, intent in zip(steps, intents, strict=True):
        level = (
            ApprovalLevel.DESTRUCTIVE
            if intent.offensive or intent.effect == EffectClass.DESTRUCTIVE
            else ApprovalLevel.EXTERNAL
            if intent.effect == EffectClass.EXTERNAL
            else ApprovalLevel.NORMAL
            if intent.effect == EffectClass.MUTATE
            else None
        )
        if level is None:
            continue
        approval_challenge = approval_authority.challenge(
            authority,
            intent,
            level=level,
            now=now,
        )
        approvals[step["id"]] = approval_authority.approve(
            approval_challenge,
            approver=approver,
            exact_phrase=approval_challenge.exact_phrase,
            reviewed_effects=True,
        )
    session = AuthorizationSession(
        authority=authority,
        proof=proof,
        containment_allowed=True,
        containment_digest=_CONTAINMENT,
        kernel=AuthorizationKernel(approval_authority),
    )
    return TestAuthorization(session, approvals)


__all__ = ["TestAuthorization", "authorize_synthetic_steps"]
