# SPDX-License-Identifier: Apache-2.0
"""Signed probe responses that separate assertions from SOVA observations."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from sova.formats import canonical_json_bytes, sha256_digest, strict_json_loads
from sova.formats.errors import FormatError
from sova.trace import Redactor, generate_ed25519_keypair, sign_dsse_payload, verify_dsse_payload

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sova.trace.integrity import Ed25519Keypair

_PROBE_PAYLOAD_TYPE = "application/vnd.sova.probe-response+json;version=0.1"
_MAX_TTL = timedelta(minutes=15)


def _time(value: datetime) -> str:
    if value.tzinfo is None:
        raise FormatError("SOVA-PROBE-TIME", "probe time must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str):
        raise FormatError("SOVA-PROBE-TIME", "probe time is malformed")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise FormatError("SOVA-PROBE-TIME", "probe time is malformed") from error
    if parsed.tzinfo is None:
        raise FormatError("SOVA-PROBE-TIME", "probe time must include an offset")
    return parsed.astimezone(UTC)


def issue_probe_response(  # noqa: PLR0913 - explicit security bindings are intentional
    keypair: Ed25519Keypair,
    *,
    subject: str,
    nonce: str,
    scope: Sequence[str],
    assertions: Sequence[dict[str, Any]],
    observations: Sequence[dict[str, Any]],
    conformance_status: str,
    now: datetime,
    ttl: timedelta = timedelta(minutes=5),
    revocation_list_digest: str | None = None,
) -> dict[str, Any]:
    """Issue an offline-verifiable response; issuance does not establish subject trust."""
    if not subject or not nonce or not scope:
        raise FormatError("SOVA-PROBE-REQUEST", "subject, nonce, and scope are required")
    if any(not isinstance(item, dict) for item in (*assertions, *observations)):
        raise FormatError("SOVA-PROBE-EVIDENCE", "probe evidence entries must be objects")
    if not timedelta(0) < ttl <= _MAX_TTL:
        raise FormatError("SOVA-PROBE-TTL", "probe response TTL must be within 15 minutes")
    if conformance_status not in {
        "passed",
        "failed",
        "unsupported",
        "inconclusive",
    }:
        raise FormatError("SOVA-PROBE-STATUS", "probe conformance status is invalid")
    body = {
        "artifactType": "sova.probe-response",
        "schemaVersion": "0.1.0",
        "subject": subject,
        "nonce": nonce,
        "scope": sorted(set(scope)),
        "issuedAt": _time(now),
        "expiresAt": _time(now + ttl),
        "conformanceStatus": conformance_status,
        "thirdPartyAssertions": [
            {**item, "evidenceClass": "third-party-self-asserted"} for item in assertions
        ],
        "sovaObservations": [{**item, "evidenceClass": "sova-observed"} for item in observations],
        "revocation": {
            "status": "not-checked",
            "listDigest": revocation_list_digest,
        },
        "limitations": [
            "Included-key verification proves integrity only, not subject identity or trust.",
            "Conformance is limited to the declared scope and observation window.",
        ],
    }
    payload = canonical_json_bytes(body)
    return {
        "artifactType": "sova.signed-probe-response",
        "schemaVersion": "0.1.0",
        "envelope": sign_dsse_payload(_PROBE_PAYLOAD_TYPE, payload, keypair),
        "publicKey": {
            "algorithm": "ed25519",
            "keyid": keypair.key_id,
            "raw": base64.b64encode(keypair.public_key).decode("ascii"),
        },
        "trustPolicy": "included-key-integrity-only",
    }


def issue_probe_document(value: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    """Strictly parse a secret-free issuance request and sign it with an ephemeral key."""
    required = {
        "artifactType",
        "schemaVersion",
        "subject",
        "nonce",
        "scope",
        "assertions",
        "observations",
        "conformanceStatus",
        "ttlSeconds",
    }
    if set(value) != required:
        raise FormatError(
            "SOVA-PROBE-ISSUANCE-FIELDS",
            "probe issuance request has missing or unknown fields",
            details={"fields": sorted(value)},
        )
    if value.get("artifactType") != "sova.probe-issuance" or value.get("schemaVersion") != "0.1.0":
        raise FormatError("SOVA-PROBE-ISSUANCE-VERSION", "probe issuance version is unsupported")
    subject = value.get("subject")
    nonce = value.get("nonce")
    scope = value.get("scope")
    assertions = value.get("assertions")
    observations = value.get("observations")
    status = value.get("conformanceStatus")
    ttl_seconds = value.get("ttlSeconds")
    if not isinstance(subject, str) or not isinstance(nonce, str):
        raise FormatError("SOVA-PROBE-REQUEST", "subject and nonce must be strings")
    if not isinstance(scope, list) or not scope or any(not isinstance(item, str) for item in scope):
        raise FormatError("SOVA-PROBE-REQUEST", "scope must be a non-empty string array")
    if not isinstance(assertions, list) or any(not isinstance(item, dict) for item in assertions):
        raise FormatError("SOVA-PROBE-EVIDENCE", "assertions must be an object array")
    if not isinstance(observations, list) or any(
        not isinstance(item, dict) for item in observations
    ):
        raise FormatError("SOVA-PROBE-EVIDENCE", "observations must be an object array")
    if not isinstance(status, str):
        raise FormatError("SOVA-PROBE-STATUS", "conformanceStatus must be a string")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise FormatError("SOVA-PROBE-TTL", "ttlSeconds must be an integer")
    _, sensitive = Redactor(context_id="sova-probe-issuance").redact(value)
    if sensitive:
        raise FormatError(
            "SOVA-PROBE-SENSITIVE",
            "probe issuance requests cannot contain credential-shaped material",
        )
    return issue_probe_response(
        generate_ed25519_keypair(),
        subject=subject,
        nonce=nonce,
        scope=tuple(scope),
        assertions=tuple(assertions),
        observations=tuple(observations),
        conformance_status=status,
        now=now,
        ttl=timedelta(seconds=ttl_seconds),
    )


def verify_probe_response(  # noqa: PLR0913 - explicit verifier expectations are intentional
    document: dict[str, Any],
    *,
    expected_nonce: str,
    expected_scope: Sequence[str],
    now: datetime,
    required_key_id: str | None = None,
    revoked_key_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Verify signature, freshness, binding, and local revocation information offline."""
    try:
        key = document["publicKey"]
        envelope = document["envelope"]
        raw_key = base64.b64decode(key["raw"], validate=True)
    except (KeyError, TypeError, ValueError) as error:
        raise FormatError("SOVA-PROBE-MALFORMED", "signed probe response is malformed") from error
    key_id = sha256_digest(raw_key)
    if (
        document.get("artifactType") != "sova.signed-probe-response"
        or document.get("schemaVersion") != "0.1.0"
        or document.get("trustPolicy") != "included-key-integrity-only"
        or key.get("algorithm") != "ed25519"
        or key.get("keyid") != key_id
    ):
        raise FormatError("SOVA-PROBE-KEY", "probe key material is inconsistent")
    if required_key_id is not None and key_id != required_key_id:
        raise FormatError("SOVA-PROBE-IDENTITY", "probe signing key is not the pinned key")
    if key_id in set(revoked_key_ids):
        raise FormatError("SOVA-PROBE-REVOKED", "probe signing key is locally revoked")
    payload = verify_dsse_payload(envelope, raw_key, expected_payload_type=_PROBE_PAYLOAD_TYPE)
    body = strict_json_loads(payload)
    if not isinstance(body, dict) or body.get("artifactType") != "sova.probe-response":
        raise FormatError("SOVA-PROBE-PAYLOAD", "probe payload is invalid")
    issued = _parse_time(body.get("issuedAt"))
    expires = _parse_time(body.get("expiresAt"))
    if now.tzinfo is None:
        raise FormatError("SOVA-PROBE-TIME", "verification time must be timezone-aware")
    current = now.astimezone(UTC)
    if expires <= issued or expires - issued > _MAX_TTL:
        raise FormatError("SOVA-PROBE-FRESHNESS", "probe validity window is invalid")
    if current < issued or current >= expires:
        raise FormatError("SOVA-PROBE-FRESHNESS", "probe response is not currently fresh")
    if body.get("nonce") != expected_nonce:
        raise FormatError("SOVA-PROBE-NONCE", "probe nonce does not match request")
    if body.get("scope") != sorted(set(expected_scope)):
        raise FormatError("SOVA-PROBE-SCOPE", "probe scope does not match request")
    status = body.get("conformanceStatus")
    observations = body.get("sovaObservations", [])
    assertions = body.get("thirdPartyAssertions", [])
    if status not in {"passed", "failed", "unsupported", "inconclusive"}:
        raise FormatError("SOVA-PROBE-STATUS", "probe status is invalid")
    if (
        not isinstance(observations, list)
        or not isinstance(assertions, list)
        or not all(
            isinstance(item, dict) and item.get("evidenceClass") == "third-party-self-asserted"
            for item in assertions
        )
        or not all(
            isinstance(item, dict) and item.get("evidenceClass") == "sova-observed"
            for item in observations
        )
    ):
        raise FormatError("SOVA-PROBE-EVIDENCE", "probe evidence arrays are invalid")
    return {
        "artifactType": "sova.probe-verification",
        "verified": True,
        "fresh": True,
        "keyId": key_id,
        "identityTrust": "pinned-key" if required_key_id is not None else "not-established",
        "conformanceStatus": status,
        "assertionCount": len(assertions),
        "observationCount": len(observations),
        "observationsIndependentOfAssertions": all(
            isinstance(item, dict) and item.get("evidenceClass") == "sova-observed"
            for item in observations
        ),
        "revocation": "locally-not-revoked",
        "limitations": body.get("limitations", []),
    }
