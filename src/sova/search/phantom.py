# SPDX-License-Identifier: Apache-2.0
"""Owned-target-only authenticated fuzzing harness with ephemeral tokens."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from sova.formats import sha256_digest
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sova.trace import TraceWriter

_MAX_PHANTOM_ATTEMPTS = 1000
_MAX_PHANTOM_PAYLOAD_BYTES = 1024 * 1024
_MAX_PHANTOM_EVIDENCE_BYTES = 16 * 1024 * 1024


class OwnedApplicationHarness(Protocol):
    """Application-specific boundary supplied only after control proof."""

    def backend_attempt(self, token: str, payload: bytes) -> tuple[bool, bytes]: ...

    def browser_confirm(self) -> bytes: ...


class EphemeralToken:
    """Mutable in-memory token buffer that is zeroized after the bounded run."""

    def __init__(self, value: str) -> None:
        if not value:
            raise FormatError("SOVA-PHANTOM-TOKEN", "session token cannot be empty")
        self._value = bytearray(value.encode("utf-8"))
        self._closed = False

    def reveal(self) -> str:
        if self._closed:
            raise FormatError("SOVA-PHANTOM-TOKEN", "session token has been zeroized")
        return self._value.decode("utf-8")

    def close(self) -> None:
        for index in range(len(self._value)):
            self._value[index] = 0
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed


@dataclass(frozen=True, slots=True)
class PhantomResult:
    attempts: int
    confirmed: bool
    payload_digest: str | None
    backend_evidence_digest: str | None
    browser_confirmation_digest: str
    token_persisted: bool
    limitations: tuple[str, ...]

    def to_mapping(self) -> dict[str, object]:
        return {
            "artifactType": "sova.phantom-result",
            "attempts": self.attempts,
            "confirmed": self.confirmed,
            "payloadDigest": self.payload_digest,
            "backendEvidenceDigest": self.backend_evidence_digest,
            "browserConfirmationDigest": self.browser_confirmation_digest,
            "tokenPersisted": self.token_persisted,
            "limitations": list(self.limitations),
        }


class PhantomFuzzer:
    """Bounded API-speed harness that fails closed without explicit owned-target proof."""

    def __init__(self, *, target_control_verified: bool, max_attempts: int = 100) -> None:
        if not target_control_verified:
            raise FormatError(
                "SOVA-PHANTOM-CONTROL",
                "Phantom Fuzzer requires a verified owned-target control proof",
            )
        if not 1 <= max_attempts <= _MAX_PHANTOM_ATTEMPTS:
            raise FormatError("SOVA-PHANTOM-BUDGET", "invalid Phantom Fuzzer attempt budget")
        self.max_attempts = max_attempts

    def run(
        self,
        token: EphemeralToken,
        payloads: Sequence[bytes],
        harness: OwnedApplicationHarness,
        *,
        trace_writer: TraceWriter | None = None,
    ) -> PhantomResult:
        """Fuzz a controlled backend, then record secret-free browser confirmation evidence."""
        confirmed = False
        selected_digest: str | None = None
        backend_digest: str | None = None
        attempted = 0
        try:
            if not payloads:
                raise FormatError("SOVA-PHANTOM-PAYLOADS", "at least one inert payload is required")
            for payload in payloads[: self.max_attempts]:
                if not payload or len(payload) > _MAX_PHANTOM_PAYLOAD_BYTES:
                    raise FormatError(
                        "SOVA-PHANTOM-PAYLOADS",
                        "payload must be non-empty and at most 1 MiB",
                    )
                attempted += 1
                triggered, evidence = harness.backend_attempt(token.reveal(), payload)
                if len(evidence) > _MAX_PHANTOM_EVIDENCE_BYTES:
                    raise FormatError(
                        "SOVA-PHANTOM-EVIDENCE",
                        "backend evidence exceeds the 16 MiB budget",
                    )
                if trace_writer is not None:
                    trace_writer.append(
                        "attempt.completed",
                        {
                            "attempt": attempted,
                            "triggered": triggered,
                            "payloadDigest": sha256_digest(payload),
                            "backendEvidenceDigest": sha256_digest(evidence),
                            "rawPayloadStored": False,
                            "sessionMaterialStored": False,
                        },
                    )
                if triggered:
                    confirmed = True
                    selected_digest = sha256_digest(payload)
                    backend_digest = sha256_digest(evidence)
                    break
            screenshot = harness.browser_confirm()
            if len(screenshot) > _MAX_PHANTOM_EVIDENCE_BYTES:
                raise FormatError(
                    "SOVA-PHANTOM-EVIDENCE",
                    "browser confirmation exceeds the 16 MiB budget",
                )
            screenshot_digest = sha256_digest(screenshot)
            if trace_writer is not None:
                trace_writer.append(
                    "oracle.completed",
                    {
                        "oracle": "owned-target-browser-confirmation",
                        "status": "pass" if confirmed else "not-confirmed",
                        "browserConfirmationDigest": screenshot_digest,
                        "rawScreenshotStored": False,
                        "sessionMaterialStored": False,
                    },
                )
        finally:
            token.close()
        return PhantomResult(
            attempts=attempted,
            confirmed=confirmed,
            payload_digest=selected_digest,
            backend_evidence_digest=backend_digest,
            browser_confirmation_digest=screenshot_digest,
            token_persisted=False,
            limitations=(
                "No session token, cookie, authorization header, or raw payload is persisted.",
                "Best-effort zeroization clears SOVA's byte buffer; Python, provider, or "
                "operating-system copies cannot be guaranteed erased.",
                "HttpOnly/proof-of-possession tokens, CSRF, WebSockets, bot protection, "
                "third parties, and irreversible transactions may prevent or prohibit use.",
                "The harness is not authorized for third-party targets.",
            ),
        )


__all__ = [
    "EphemeralToken",
    "OwnedApplicationHarness",
    "PhantomFuzzer",
    "PhantomResult",
]
