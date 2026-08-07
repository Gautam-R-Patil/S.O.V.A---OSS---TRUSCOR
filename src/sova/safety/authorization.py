# SPDX-License-Identifier: Apache-2.0
"""Authority-containment-evidence authorization contracts.

The reference kernel deliberately treats authorization as more than an allow
Boolean.  Authority provenance, proof of target control, exact scope, effect
budgets, containment posture, fresh human approval, and required evidence are
bound into one decision.  The design is experimental; it does not prove that a
claimed human identity or control-plane observation is truthful.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Mapping


def _utc_now() -> datetime:
    return datetime.now(UTC)


_HTTP_OK = 200
_MINIMUM_APPROVAL_KEY_BYTES = 32
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise FormatError("SOVA-AUTH-TIMEZONE", "authorization time must include a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


class PrincipalKind(StrEnum):
    """Software actors cannot assert human approval."""

    HUMAN = "human"
    SERVICE = "service"
    AGENT = "agent"


class EffectClass(IntEnum):
    """Ordered maximum consequence class."""

    OBSERVE = 0
    READ = 1
    MUTATE = 2
    EXTERNAL = 3
    DESTRUCTIVE = 4


class ControlProofMethod(StrEnum):
    """Supported target-control evidence families."""

    LOOPBACK = "loopback"
    SANDBOX = "sandbox"
    SIGNED_MANIFEST = "signed-manifest"
    WELL_KNOWN = "well-known"
    DNS = "dns"
    SCOPED_DOCUMENT = "scoped-document"
    LEGAL_ACQUISITION = "legal-acquisition"


class ApprovalLevel(IntEnum):
    """Destructive approval is deliberately distinct from normal approval."""

    NORMAL = 1
    EXTERNAL = 2
    DESTRUCTIVE = 3


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    kind: PrincipalKind
    display_name: str

    def __post_init__(self) -> None:
        if not self.id or not self.display_name:
            raise FormatError("SOVA-AUTH-PRINCIPAL", "principal fields must be non-empty")


def _normalized_path(value: str) -> str:
    rendered = value.replace("\\", "/").rstrip("/") or "/"
    parts = rendered.split("/")
    if ".." in parts or "\x00" in rendered:
        raise FormatError("SOVA-AUTH-PATH", "authorization path is not normalized")
    return rendered.casefold()


def _path_within(candidate: str, root: str) -> bool:
    normalized = _normalized_path(candidate)
    parent = _normalized_path(root)
    return normalized == parent or normalized.startswith(parent.rstrip("/") + "/")


def _domain_allowed(candidate: str, allowed: frozenset[str]) -> bool:
    value = candidate.rstrip(".").casefold()
    for pattern in allowed:
        normalized = pattern.rstrip(".").casefold()
        if normalized.startswith("*."):
            suffix = normalized[2:]
            if value.endswith("." + suffix) and value != suffix:
                return True
        elif value == normalized:
            return True
    return False


@dataclass(frozen=True, slots=True)
class Scope:
    """Exact, independently checked authorization dimensions."""

    targets: frozenset[str]
    actions: frozenset[str]
    paths: frozenset[str] = frozenset()
    tools: frozenset[str] = frozenset()
    identities: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.targets or not self.actions:
            raise FormatError(
                "SOVA-AUTH-SCOPE",
                "authorization requires at least one exact target and action",
            )
        dimensions = (
            self.targets,
            self.actions,
            self.paths,
            self.tools,
            self.identities,
            self.domains,
        )
        if any(not item for values in dimensions for item in values):
            raise FormatError("SOVA-AUTH-SCOPE", "scope values must be non-empty")
        for path in self.paths:
            _normalized_path(path)
        if any(domain == "*." or "\x00" in domain for domain in self.domains):
            raise FormatError("SOVA-AUTH-DOMAIN", "authorization domain is not valid")

    def allows(self, intent: ActionIntent) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if intent.target not in self.targets:
            reasons.append("target-out-of-scope")
        if intent.action not in self.actions:
            reasons.append("action-out-of-scope")
        if intent.path is not None and not any(
            _path_within(intent.path, root) for root in self.paths
        ):
            reasons.append("path-out-of-scope")
        if intent.tool is not None and intent.tool not in self.tools:
            reasons.append("tool-out-of-scope")
        if intent.identity is not None and intent.identity not in self.identities:
            reasons.append("identity-out-of-scope")
        if intent.domain is not None and not _domain_allowed(intent.domain, self.domains):
            reasons.append("domain-out-of-scope")
        return not reasons, tuple(reasons)

    def to_mapping(self) -> dict[str, list[str]]:
        return {
            "targets": sorted(self.targets),
            "actions": sorted(self.actions),
            "paths": sorted(self.paths),
            "tools": sorted(self.tools),
            "identities": sorted(self.identities),
            "domains": sorted(self.domains),
        }


@dataclass(frozen=True, slots=True)
class EffectBudget:
    """Multi-dimensional blast-radius ceiling."""

    max_steps: int
    max_duration_ms: int
    max_tokens: int = 0
    max_mutations: int = 0
    max_processes: int = 0
    max_files: int = 0
    max_network_requests: int = 0
    max_transaction_minor_units: int = 0

    def __post_init__(self) -> None:
        if self.max_steps < 1 or self.max_duration_ms < 1:
            raise FormatError("SOVA-AUTH-BUDGET", "step and duration budgets must be positive")
        values = asdict(self)
        if any(value < 0 for value in values.values()):
            raise FormatError("SOVA-AUTH-BUDGET", "effect budgets cannot be negative")


@dataclass(frozen=True, slots=True)
class BudgetCost:
    steps: int = 1
    duration_ms: int = 0
    tokens: int = 0
    mutations: int = 0
    processes: int = 0
    files: int = 0
    network_requests: int = 0
    transaction_minor_units: int = 0

    def __post_init__(self) -> None:
        if any(value < 0 for value in asdict(self).values()):
            raise FormatError("SOVA-AUTH-COST", "effect costs cannot be negative")


class BudgetLedger:
    """Thread-safe monotone consumption ledger."""

    def __init__(self, budget: EffectBudget) -> None:
        self._budget = budget
        self._used = BudgetCost(steps=0)
        self._lock = threading.Lock()

    @property
    def used(self) -> BudgetCost:
        with self._lock:
            return self._used

    def can_consume(self, cost: BudgetCost) -> tuple[bool, tuple[str, ...]]:
        with self._lock:
            return self._can_consume_unlocked(cost)

    def _can_consume_unlocked(self, cost: BudgetCost) -> tuple[bool, tuple[str, ...]]:
        candidate = {
            name: getattr(self._used, name) + getattr(cost, name) for name in asdict(self._used)
        }
        limits = {
            "steps": self._budget.max_steps,
            "duration_ms": self._budget.max_duration_ms,
            "tokens": self._budget.max_tokens,
            "mutations": self._budget.max_mutations,
            "processes": self._budget.max_processes,
            "files": self._budget.max_files,
            "network_requests": self._budget.max_network_requests,
            "transaction_minor_units": self._budget.max_transaction_minor_units,
        }
        exceeded = tuple(name for name, value in candidate.items() if value > limits[name])
        return not exceeded, exceeded

    def consume(self, cost: BudgetCost) -> None:
        with self._lock:
            allowed, exceeded = self._can_consume_unlocked(cost)
            if not allowed:
                raise FormatError(
                    "SOVA-AUTH-BUDGET-EXCEEDED",
                    "effect budget would be exceeded",
                    details={"dimensions": list(exceeded)},
                )
            self._used = BudgetCost(
                **{
                    name: getattr(self._used, name) + getattr(cost, name)
                    for name in asdict(self._used)
                }
            )


@dataclass(frozen=True, slots=True)
class ControlProof:
    """Bound result from a proof collector; a URL alone is never sufficient."""

    method: ControlProofMethod
    subject: str
    challenge: str
    evidence: Mapping[str, Any]
    observed_at: datetime
    expires_at: datetime
    verifier: str

    def __post_init__(self) -> None:
        if not self.subject or not self.challenge or not self.verifier:
            raise FormatError("SOVA-AUTH-PROOF", "control proof fields must be non-empty")
        if self.observed_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise FormatError("SOVA-AUTH-TIMEZONE", "control proof times must include timezones")
        if self.expires_at <= self.observed_at:
            raise FormatError("SOVA-AUTH-PROOF-WINDOW", "proof expiration must follow observation")

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "subject": self.subject,
            "challenge": self.challenge,
            "evidence": dict(self.evidence),
            "observedAt": _timestamp(self.observed_at),
            "expiresAt": _timestamp(self.expires_at),
            "verifier": self.verifier,
        }


def validate_control_proof(  # noqa: PLR0912 - proof families are explicit and fail closed
    proof: ControlProof,
    *,
    target: str,
    now: datetime | None = None,
    trusted_key_ids: frozenset[str] = frozenset(),
) -> tuple[bool, tuple[str, ...]]:
    """Validate captured proof semantics without making live network requests."""
    current = now or _utc_now()
    reasons: list[str] = []
    if proof.subject != target:
        reasons.append("proof-subject-mismatch")
    if current < proof.observed_at or current >= proof.expires_at:
        reasons.append("proof-not-current")
    evidence = proof.evidence
    method = proof.method
    if method == ControlProofMethod.LOOPBACK:
        if target.casefold() not in {"localhost", "127.0.0.1", "::1", "sova:loopback"}:
            reasons.append("not-loopback")
    elif method == ControlProofMethod.SANDBOX:
        if not target.startswith("sova:sandbox:") or evidence.get("challenge") != proof.challenge:
            reasons.append("sandbox-challenge-mismatch")
    elif method == ControlProofMethod.WELL_KNOWN:
        if (
            evidence.get("https") is not True
            or evidence.get("statusCode") != _HTTP_OK
            or evidence.get("finalHost") != target
            or evidence.get("redirected") is not False
            or evidence.get("body") != proof.challenge
        ):
            reasons.append("well-known-proof-invalid")
    elif method == ControlProofMethod.DNS:
        txt_values = evidence.get("txtValues")
        if not isinstance(txt_values, list) or proof.challenge not in txt_values:
            reasons.append("dns-proof-invalid")
    elif method in {ControlProofMethod.SIGNED_MANIFEST, ControlProofMethod.SCOPED_DOCUMENT}:
        key_id = evidence.get("keyId")
        if not isinstance(key_id, str) or key_id not in trusted_key_ids:
            reasons.append("untrusted-control-key")
        if evidence.get("signatureValid") is not True:
            reasons.append("control-signature-invalid")
        if evidence.get("challenge") != proof.challenge:
            reasons.append("signed-challenge-mismatch")
    elif method == ControlProofMethod.LEGAL_ACQUISITION and (
        evidence.get("offlineOnly") is not True
        or not isinstance(evidence.get("source"), str)
        or not evidence.get("source")
        or not isinstance(evidence.get("licenseOrAuthority"), str)
        or not evidence.get("licenseOrAuthority")
    ):
        reasons.append("legal-acquisition-proof-invalid")
    return not reasons, tuple(reasons)


@dataclass(frozen=True, slots=True)
class ActionIntent:
    """Canonical requested effect before executor-specific translation."""

    id: str
    target: str
    action: str
    effect: EffectClass
    required_evidence: frozenset[str]
    cost: BudgetCost = BudgetCost()
    path: str | None = None
    tool: str | None = None
    identity: str | None = None
    domain: str | None = None
    offensive: bool = False
    irreversible: bool = False

    def __post_init__(self) -> None:
        if not self.id or not self.target or not self.action:
            raise FormatError(
                "SOVA-AUTH-INTENT",
                "intent identity, target, and action are required",
            )
        if self.path is not None:
            _normalized_path(self.path)
        if not self.required_evidence:
            raise FormatError(
                "SOVA-AUTH-EVIDENCE-OBLIGATION",
                "every executable intent requires declared post-action evidence",
            )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "action": self.action,
            "effect": self.effect.name.lower(),
            "requiredEvidence": sorted(self.required_evidence),
            "cost": asdict(self.cost),
            "path": self.path,
            "tool": self.tool,
            "identity": self.identity,
            "domain": self.domain,
            "offensive": self.offensive,
            "irreversible": self.irreversible,
        }


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    """Fresh authority, scope, consequence ceiling, and proof provenance."""

    id: str
    issued_by: Principal
    subject: Principal
    scope: Scope
    max_effect: EffectClass
    budget: EffectBudget
    valid_from: datetime
    expires_at: datetime
    single_use: bool
    ownership: str
    required_containment_digest: str

    def __post_init__(self) -> None:
        if not self.id:
            raise FormatError("SOVA-AUTH-AUTHORITY", "authority identity must be non-empty")
        if self.issued_by.kind == PrincipalKind.AGENT:
            raise FormatError("SOVA-AUTH-AGENT-ISSUER", "an agent cannot issue authority")
        if self.valid_from.tzinfo is None or self.expires_at.tzinfo is None:
            raise FormatError("SOVA-AUTH-TIMEZONE", "authority times must include timezones")
        if self.expires_at <= self.valid_from:
            raise FormatError("SOVA-AUTH-WINDOW", "authority expiration must follow issuance")
        if self.ownership not in {"self", "explicit", "legal-offline"}:
            raise FormatError("SOVA-AUTH-OWNERSHIP", "unsupported ownership basis")
        if _SHA256.fullmatch(self.required_containment_digest) is None:
            raise FormatError(
                "SOVA-AUTH-CONTAINMENT-DIGEST",
                "authority requires a lowercase SHA-256 containment digest",
            )

    @property
    def digest(self) -> str:
        return sha256_digest(canonical_json_bytes(self.to_mapping()))

    def to_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "issuedBy": asdict(self.issued_by),
            "subject": asdict(self.subject),
            "scope": self.scope.to_mapping(),
            "maxEffect": self.max_effect.name.lower(),
            "budget": asdict(self.budget),
            "validFrom": _timestamp(self.valid_from),
            "expiresAt": _timestamp(self.expires_at),
            "singleUse": self.single_use,
            "ownership": self.ownership,
            "requiredContainmentDigest": self.required_containment_digest,
        }


@dataclass(frozen=True, slots=True)
class ApprovalChallenge:
    id: str
    authority_id: str
    intent_digest: str
    level: ApprovalLevel
    exact_phrase: str
    expires_at: datetime
    nonce: str


@dataclass(frozen=True, slots=True)
class ApprovalBatchItem:
    intent_digest: str
    level: ApprovalLevel


@dataclass(frozen=True, slots=True)
class ApprovalBatchChallenge:
    """One human review bound to a closed set of exact action intents."""

    id: str
    authority_id: str
    items: tuple[ApprovalBatchItem, ...]
    exact_phrase: str
    expires_at: datetime
    nonce: str


@dataclass(frozen=True, slots=True)
class ApprovalToken:
    id: str
    challenge_id: str
    authority_id: str
    intent_digest: str
    level: ApprovalLevel
    approver: Principal
    channel: str
    expires_at: datetime
    nonce: str
    reviewed_effects: bool
    signature: str

    def unsigned_mapping(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "challengeId": self.challenge_id,
            "authorityId": self.authority_id,
            "intentDigest": self.intent_digest,
            "level": self.level.name.lower(),
            "approver": asdict(self.approver),
            "channel": self.channel,
            "expiresAt": _timestamp(self.expires_at),
            "nonce": self.nonce,
            "reviewedEffects": self.reviewed_effects,
        }


class _SignedApprovalAuthority:
    """Shared signer for explicit human approval channels.

    The HMAC proves channel-key possession, not that a person actually read the
    displayed challenge. Channel-specific subclasses state where review occurs.
    """

    def __init__(self, key: bytes, *, channel: str) -> None:
        if len(key) < _MINIMUM_APPROVAL_KEY_BYTES:
            raise FormatError("SOVA-AUTH-CHANNEL-KEY", "approval channel key needs 32 bytes")
        self._key = key
        self.channel = channel
        self._used: set[str] = set()
        self._approved_batches: set[str] = set()
        self._lock = threading.Lock()

    def challenge(
        self,
        authority: AuthorityEnvelope,
        intent: ActionIntent,
        *,
        level: ApprovalLevel,
        ttl: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ApprovalChallenge:
        current = now or _utc_now()
        nonce = secrets.token_urlsafe(18)
        challenge_id = "sova:approval:" + secrets.token_hex(16)
        phrase = f"APPROVE {level.name} {intent.digest[7:19]} {nonce[:8]}"
        return ApprovalChallenge(
            challenge_id,
            authority.id,
            intent.digest,
            level,
            phrase,
            current + ttl,
            nonce,
        )

    def approve(
        self,
        challenge: ApprovalChallenge,
        *,
        approver: Principal,
        exact_phrase: str,
        reviewed_effects: bool,
    ) -> ApprovalToken:
        if approver.kind != PrincipalKind.HUMAN:
            raise FormatError("SOVA-AUTH-SELF-APPROVAL", "agents and services cannot approve")
        if exact_phrase != challenge.exact_phrase:
            raise FormatError("SOVA-AUTH-APPROVAL-PHRASE", "approval phrase did not match")
        if challenge.level == ApprovalLevel.DESTRUCTIVE and not reviewed_effects:
            raise FormatError(
                "SOVA-AUTH-DESTRUCTIVE-REVIEW",
                "destructive approval requires explicit effect review",
            )
        token_id = "sova:approval-token:" + secrets.token_hex(16)
        unsigned = {
            "id": token_id,
            "challengeId": challenge.id,
            "authorityId": challenge.authority_id,
            "intentDigest": challenge.intent_digest,
            "level": challenge.level.name.lower(),
            "approver": asdict(approver),
            "channel": self.channel,
            "expiresAt": _timestamp(challenge.expires_at),
            "nonce": challenge.nonce,
            "reviewedEffects": reviewed_effects,
        }
        signature = base64.urlsafe_b64encode(
            hmac.digest(self._key, canonical_json_bytes(unsigned), hashlib.sha256)
        ).decode("ascii")
        return ApprovalToken(
            id=token_id,
            challenge_id=challenge.id,
            authority_id=challenge.authority_id,
            intent_digest=challenge.intent_digest,
            level=challenge.level,
            approver=approver,
            channel=self.channel,
            expires_at=challenge.expires_at,
            nonce=challenge.nonce,
            reviewed_effects=reviewed_effects,
            signature=signature,
        )

    def batch_challenge(
        self,
        authority: AuthorityEnvelope,
        items: tuple[tuple[ActionIntent, ApprovalLevel], ...],
        *,
        ttl: timedelta = timedelta(minutes=5),
        now: datetime | None = None,
    ) -> ApprovalBatchChallenge:
        """Bind one review phrase to every exact intent in a bounded run."""
        if not items:
            raise FormatError("SOVA-AUTH-APPROVAL-BATCH", "approval batch cannot be empty")
        current = now or _utc_now()
        batch_items = tuple(ApprovalBatchItem(intent.digest, level) for intent, level in items)
        digest = sha256_digest(
            canonical_json_bytes(
                [
                    {"intentDigest": item.intent_digest, "level": item.level.name.lower()}
                    for item in batch_items
                ]
            )
        )
        nonce = secrets.token_urlsafe(18)
        challenge_id = "sova:approval-batch:" + secrets.token_hex(16)
        level = max(item.level for item in batch_items)
        phrase = f"APPROVE {level.name} BATCH {digest[7:19]} {nonce[:8]}"
        return ApprovalBatchChallenge(
            challenge_id,
            authority.id,
            batch_items,
            phrase,
            current + ttl,
            nonce,
        )

    def approve_batch(
        self,
        challenge: ApprovalBatchChallenge,
        *,
        approver: Principal,
        exact_phrase: str,
        reviewed_effects: bool,
    ) -> tuple[ApprovalToken, ...]:
        """Issue individually consumable tokens after one exact batch review."""
        if approver.kind != PrincipalKind.HUMAN:
            raise FormatError("SOVA-AUTH-SELF-APPROVAL", "agents and services cannot approve")
        if exact_phrase != challenge.exact_phrase:
            raise FormatError("SOVA-AUTH-APPROVAL-PHRASE", "approval phrase did not match")
        if any(item.level == ApprovalLevel.DESTRUCTIVE for item in challenge.items) and not (
            reviewed_effects
        ):
            raise FormatError(
                "SOVA-AUTH-DESTRUCTIVE-REVIEW",
                "destructive approval requires explicit effect review",
            )
        with self._lock:
            if challenge.id in self._approved_batches:
                raise FormatError(
                    "SOVA-AUTH-APPROVAL-BATCH-REPLAY",
                    "approval batch was already issued",
                )
            self._approved_batches.add(challenge.id)
        tokens: list[ApprovalToken] = []
        for index, item in enumerate(challenge.items):
            token_id = "sova:approval-token:" + secrets.token_hex(16)
            token_challenge_id = f"{challenge.id}:{index}"
            unsigned = {
                "id": token_id,
                "challengeId": token_challenge_id,
                "authorityId": challenge.authority_id,
                "intentDigest": item.intent_digest,
                "level": item.level.name.lower(),
                "approver": asdict(approver),
                "channel": self.channel,
                "expiresAt": _timestamp(challenge.expires_at),
                "nonce": challenge.nonce,
                "reviewedEffects": reviewed_effects,
            }
            signature = base64.urlsafe_b64encode(
                hmac.digest(self._key, canonical_json_bytes(unsigned), hashlib.sha256)
            ).decode("ascii")
            tokens.append(
                ApprovalToken(
                    id=token_id,
                    challenge_id=token_challenge_id,
                    authority_id=challenge.authority_id,
                    intent_digest=item.intent_digest,
                    level=item.level,
                    approver=approver,
                    channel=self.channel,
                    expires_at=challenge.expires_at,
                    nonce=challenge.nonce,
                    reviewed_effects=reviewed_effects,
                    signature=signature,
                )
            )
        return tuple(tokens)

    def consume(
        self,
        token: ApprovalToken,
        *,
        authority_id: str,
        intent_digest: str,
        minimum_level: ApprovalLevel,
        now: datetime | None = None,
    ) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        unsigned = token.unsigned_mapping()
        expected = base64.urlsafe_b64encode(
            hmac.digest(self._key, canonical_json_bytes(unsigned), hashlib.sha256)
        ).decode("ascii")
        if not hmac.compare_digest(token.signature, expected):
            reasons.append("approval-signature-invalid")
        if token.authority_id != authority_id or token.intent_digest != intent_digest:
            reasons.append("approval-scope-mismatch")
        if token.approver.kind != PrincipalKind.HUMAN or token.channel != self.channel:
            reasons.append(
                "approval-not-human-out-of-band"
                if self.channel == "out-of-band"
                else "approval-not-human-interactive-terminal"
            )
        if token.level < minimum_level:
            reasons.append("approval-level-insufficient")
        if (now or _utc_now()) >= token.expires_at:
            reasons.append("approval-expired")
        if minimum_level == ApprovalLevel.DESTRUCTIVE and not token.reviewed_effects:
            reasons.append("destructive-effects-not-reviewed")
        with self._lock:
            if token.id in self._used:
                reasons.append("approval-already-used")
            if not reasons:
                self._used.add(token.id)
        return not reasons, tuple(reasons)


class OutOfBandApprovalAuthority(_SignedApprovalAuthority):
    """Reference control channel using an externally held HMAC key."""

    def __init__(self, key: bytes, *, channel: str = "out-of-band") -> None:
        if channel != "out-of-band":
            raise FormatError("SOVA-AUTH-CHANNEL", "reference approvals must be out-of-band")
        super().__init__(key, channel=channel)


class InteractiveTerminalApprovalAuthority(_SignedApprovalAuthority):
    """Same-process terminal review; explicit, but not an out-of-band channel."""

    def __init__(self, key: bytes) -> None:
        super().__init__(key, channel="interactive-terminal")


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    status: str
    authority_id: str
    authority_digest: str
    issued_by_id: str
    issued_by_kind: PrincipalKind
    subject_id: str
    subject_kind: PrincipalKind
    ownership: str
    scope_digest: str
    intent_digest: str
    proof_digest: str
    containment_digest: str
    reasons: tuple[str, ...]
    required_evidence: tuple[str, ...]
    budget_before: BudgetCost
    budget_after: BudgetCost | None
    approval_token_digest: str | None
    decided_at: datetime

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    def to_mapping(self) -> dict[str, Any]:
        return {
            "contractVersion": "0.1",
            "decision": self.status,
            "authorizationId": self.authority_id,
            "authorizationDigest": self.authority_digest,
            "issuedBy": {"id": self.issued_by_id, "kind": self.issued_by_kind.value},
            "subject": {"id": self.subject_id, "kind": self.subject_kind.value},
            "ownership": self.ownership,
            "intentDigest": self.intent_digest,
            "scopeDigest": self.scope_digest,
            "proofDigest": self.proof_digest,
            "containmentDigest": self.containment_digest,
            "reasons": list(self.reasons),
            "requiredEvidence": list(self.required_evidence),
            "budgetBefore": asdict(self.budget_before),
            "budgetAfter": asdict(self.budget_after) if self.budget_after else None,
            "approvalTokenDigest": self.approval_token_digest,
            "decidedAt": _timestamp(self.decided_at),
            "decidedBy": "sova.authorization-kernel/0.1",
        }


def _approval_level(intent: ActionIntent) -> ApprovalLevel | None:
    if intent.offensive or intent.effect == EffectClass.DESTRUCTIVE:
        return ApprovalLevel.DESTRUCTIVE
    if intent.effect == EffectClass.EXTERNAL:
        return ApprovalLevel.EXTERNAL
    if intent.effect == EffectClass.MUTATE:
        return ApprovalLevel.NORMAL
    return None


class AuthorizationKernel:
    """Compute and consume one fail-closed authorization decision."""

    def __init__(self, approval_authority: _SignedApprovalAuthority | None = None) -> None:
        self.approval_authority = approval_authority

    def decide(  # noqa: PLR0912, PLR0913 - trust inputs and checks stay explicit
        self,
        *,
        authority: AuthorityEnvelope,
        intent: ActionIntent,
        proof: ControlProof,
        containment_allowed: bool,
        containment_digest: str,
        ledger: BudgetLedger,
        approval: ApprovalToken | None = None,
        trusted_control_keys: frozenset[str] = frozenset(),
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        current = now or _utc_now()
        reasons: list[str] = []
        if current < authority.valid_from or current >= authority.expires_at:
            reasons.append("authority-not-current")
        if authority.required_containment_digest != containment_digest:
            reasons.append("containment-binding-mismatch")
        if not containment_allowed:
            reasons.append("containment-not-admissible")
        scope_allowed, scope_reasons = authority.scope.allows(intent)
        if not scope_allowed:
            reasons.extend(scope_reasons)
        if intent.effect > authority.max_effect:
            reasons.append("effect-exceeds-authority")
        if intent.irreversible:
            reasons.append("irreversible-effect-prohibited")
        proof_allowed, proof_reasons = validate_control_proof(
            proof,
            target=intent.target,
            now=current,
            trusted_key_ids=trusted_control_keys,
        )
        if not proof_allowed:
            reasons.extend(proof_reasons)
        if (
            authority.ownership == "legal-offline"
            and proof.method != ControlProofMethod.LEGAL_ACQUISITION
        ):
            reasons.append("legal-offline-proof-required")
        if (
            proof.method == ControlProofMethod.LEGAL_ACQUISITION
            and intent.effect >= EffectClass.EXTERNAL
        ):
            reasons.append("legal-acquisition-is-offline-only")
        budget_allowed, budget_reasons = ledger.can_consume(intent.cost)
        if not budget_allowed:
            reasons.extend(f"budget-exceeded:{name}" for name in budget_reasons)
        required_level = _approval_level(intent)
        approval_digest: str | None = None
        if required_level is not None:
            if approval is None or self.approval_authority is None:
                reasons.append("fresh-out-of-band-approval-required")
            else:
                approval_ok, approval_reasons = self.approval_authority.consume(
                    approval,
                    authority_id=authority.id,
                    intent_digest=intent.digest,
                    minimum_level=required_level,
                    now=current,
                )
                if not approval_ok:
                    reasons.extend(approval_reasons)
                approval_digest = sha256_digest(canonical_json_bytes(approval.unsigned_mapping()))
        before = ledger.used
        after: BudgetCost | None = None
        if not reasons:
            ledger.consume(intent.cost)
            after = ledger.used
        return AuthorizationDecision(
            "allowed" if not reasons else "denied",
            authority.id,
            authority.digest,
            authority.issued_by.id,
            authority.issued_by.kind,
            authority.subject.id,
            authority.subject.kind,
            authority.ownership,
            sha256_digest(canonical_json_bytes(authority.scope.to_mapping())),
            intent.digest,
            proof.digest,
            containment_digest,
            tuple(reasons),
            tuple(sorted(intent.required_evidence)),
            before,
            after,
            approval_digest,
            current,
        )


@dataclass(slots=True)
class AuthorizationSession:
    """Runtime holder for immutable authority and monotone budget state."""

    authority: AuthorityEnvelope
    proof: ControlProof
    containment_allowed: bool
    containment_digest: str
    kernel: AuthorizationKernel
    trusted_control_keys: frozenset[str] = frozenset()
    ledger: BudgetLedger = field(init=False)
    _claimed_invocation: str | None = field(init=False, default=None)
    _claim_lock: threading.Lock = field(init=False, default_factory=threading.Lock)

    def __post_init__(self) -> None:
        self.ledger = BudgetLedger(self.authority.budget)

    def authorize(
        self,
        intent: ActionIntent,
        *,
        approval: ApprovalToken | None = None,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        return self.kernel.decide(
            authority=self.authority,
            intent=intent,
            proof=self.proof,
            containment_allowed=self.containment_allowed,
            containment_digest=self.containment_digest,
            ledger=self.ledger,
            approval=approval,
            trusted_control_keys=self.trusted_control_keys,
            now=now,
        )

    def claim_invocation(self, invocation_id: str) -> None:
        """Bind a single-use envelope to one runner invocation."""
        if not invocation_id:
            raise FormatError("SOVA-AUTH-INVOCATION", "invocation id cannot be empty")
        with self._claim_lock:
            if self.authority.single_use and self._claimed_invocation is not None:
                raise FormatError(
                    "SOVA-AUTH-AUTHORITY-REUSED",
                    "single-use authority was already claimed by a runner invocation",
                )
            self._claimed_invocation = invocation_id


__all__ = [
    "ActionIntent",
    "ApprovalBatchChallenge",
    "ApprovalBatchItem",
    "ApprovalChallenge",
    "ApprovalLevel",
    "ApprovalToken",
    "AuthorityEnvelope",
    "AuthorizationDecision",
    "AuthorizationKernel",
    "AuthorizationSession",
    "BudgetCost",
    "BudgetLedger",
    "ControlProof",
    "ControlProofMethod",
    "EffectBudget",
    "EffectClass",
    "InteractiveTerminalApprovalAuthority",
    "OutOfBandApprovalAuthority",
    "Principal",
    "PrincipalKind",
    "Scope",
    "validate_control_proof",
]
