# SPDX-License-Identifier: Apache-2.0
"""Pre-scoped authority profiles built strictly on top of the authorization kernel.

These are convenience constructors, not new trust logic.  Every profile still
produces an ordinary `AuthorityEnvelope` that passes through the same
`__post_init__` invariants and the same `AuthorizationKernel.decide` per-action
checks as any hand-built authority.  A profile can only narrow or organize what
the kernel already enforces; it never grants an effect, approval, or proof the
kernel would not otherwise honor.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sova.formats.errors import FormatError
from sova.safety.authorization import (
    AuthorityEnvelope,
    ControlProofMethod,
    EffectClass,
    Principal,
    PrincipalKind,
    Scope,
    validate_control_proof,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sova.safety.authorization import ControlProof, EffectBudget

_OWNED_OWNERSHIP = frozenset({"self", "explicit"})
_KNOWN_OWNERSHIP = frozenset({"self", "explicit", "legal-offline"})

#: A broad but explicit action set spanning browser, desktop computer-use,
#: filesystem, and process surfaces.  Callers testing a narrower mission
#: should pass their own `action_classes` (e.g. `mission.allowed_actions`)
#: rather than relying on this default in production authorizations.
DEFAULT_FULL_CAPABILITY_ACTIONS = frozenset(
    {
        "browser.navigate",
        "browser.click",
        "browser.type",
        "browser.drag",
        "browser.scroll",
        "browser.snapshot",
        "browser.screenshot",
        "browser.observe",
        "browser.interact",
        "browser.submit",
        "computer.snapshot",
        "computer.inspect",
        "computer.click",
        "computer.type",
        "computer.scroll",
        "computer.drag",
        "computer.key",
        "filesystem.read",
        "filesystem.write",
        "filesystem.delete",
        "filesystem.move",
        "process.exec",
    }
)


def full_capability_authority(  # noqa: PLR0913 - each input is an independent trust dimension
    *,
    target: str,
    subject: Principal,
    issued_by: Principal,
    proof: ControlProof,
    containment_digest: str,
    budget: EffectBudget,
    action_classes: Iterable[str] = DEFAULT_FULL_CAPABILITY_ACTIONS,
    domains: frozenset[str] = frozenset(),
    paths: frozenset[str] = frozenset(),
    tools: frozenset[str] = frozenset(),
    identities: frozenset[str] = frozenset(),
    max_effect: EffectClass = EffectClass.EXTERNAL,
    ttl_minutes: int = 60,
    ownership: str = "self",
    allow_offensive: bool = False,
    allow_irreversible: bool = False,
    single_use: bool = True,
    now: datetime | None = None,
) -> AuthorityEnvelope:
    """Build one authority pre-scoped to a proven-owned/authorized target with a
    high effect ceiling.

    This never bypasses the kernel: `proof` must already validate for `target`,
    ownership must be internally consistent with the proof method, and
    `allow_offensive`/`allow_irreversible` still require self/explicit ownership.
    Every action the resulting authority admits still requires the matching
    per-intent human approval level at decision time (`_approval_level` in
    `sova.safety.authorization`); this profile only assembles the scope,
    ceiling, and irreversible opt-in. It never sets `intent.offensive` itself —
    that remains a per-mission/per-intent declaration the kernel checks
    independently.
    """
    current = now or datetime.now(UTC)
    valid, reasons = validate_control_proof(proof, target=target, now=current)
    if not valid:
        raise FormatError(
            "SOVA-AUTH-PROFILE-PROOF",
            "full-capability authority requires an already-valid control proof",
            details={"reasons": list(reasons)},
        )
    if issued_by.kind == PrincipalKind.AGENT:
        raise FormatError(
            "SOVA-AUTH-PROFILE-ISSUER",
            "full-capability authority cannot be issued by an agent",
        )
    if ownership not in _KNOWN_OWNERSHIP:
        raise FormatError(
            "SOVA-AUTH-PROFILE-OWNERSHIP",
            "full-capability authority ownership basis is unsupported",
        )
    is_legal_proof = proof.method == ControlProofMethod.LEGAL_ACQUISITION
    if is_legal_proof != (ownership == "legal-offline"):
        raise FormatError(
            "SOVA-AUTH-PROFILE-OWNERSHIP",
            "ownership basis must match the control proof method exactly",
        )
    if (allow_offensive or allow_irreversible) and ownership not in _OWNED_OWNERSHIP:
        raise FormatError(
            "SOVA-AUTH-PROFILE-OWNERSHIP",
            "offensive or irreversible full-capability authority requires proven"
            " self/explicit ownership, not an offline legal-acquisition proof",
        )
    actions = frozenset(action_classes)
    if not actions:
        raise FormatError(
            "SOVA-AUTH-PROFILE-ACTIONS",
            "full-capability authority requires at least one action class",
        )
    scope = Scope(
        targets=frozenset({target}),
        actions=actions,
        paths=paths,
        tools=tools,
        identities=identities,
        domains=domains,
    )
    return AuthorityEnvelope(
        id=f"sova:authorization:full-capability:{target}:{proof.digest[7:23]}",
        issued_by=issued_by,
        subject=subject,
        scope=scope,
        max_effect=max_effect,
        budget=budget,
        valid_from=current,
        expires_at=current + timedelta(minutes=ttl_minutes),
        single_use=single_use,
        ownership=ownership,
        required_containment_digest=containment_digest,
        allow_irreversible=allow_irreversible,
    )


__all__ = ["DEFAULT_FULL_CAPABILITY_ACTIONS", "full_capability_authority"]
