# SPDX-License-Identifier: Apache-2.0
"""Bounded website control challenges for authorized external assessment."""

from __future__ import annotations

import secrets
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from sova.formats.errors import FormatError
from sova.safety import ControlProof, ControlProofMethod
from sova.targets import TargetKind, TargetManifest

if TYPE_CHECKING:
    from collections.abc import Mapping

_MAX_PROOF_BYTES = 16 * 1024
_MAX_PROOF_TIMEOUT_SECONDS = 30
_HTTP_OK = 200
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise FormatError("SOVA-CONTROL-TIME", "control timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise FormatError("SOVA-CONTROL-TIME", "control timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise FormatError("SOVA-CONTROL-TIME", "control timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise FormatError("SOVA-CONTROL-TIME", "control timestamp requires a timezone")
    return parsed


def _target_origin(target: TargetManifest) -> tuple[str, str]:
    if target.kind != TargetKind.BROWSER_AGENT:
        raise FormatError("SOVA-CONTROL-TARGET", "website control proof needs browser-agent")
    values = target.configuration.get("allowedOrigins")
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise FormatError(
            "SOVA-CONTROL-ORIGIN",
            "control proof currently requires exactly one allowed website origin",
        )
    parsed = urlsplit(values[0])
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise FormatError("SOVA-CONTROL-ORIGIN", "allowed website origin is invalid")
    if parsed.scheme != "https" and parsed.hostname.casefold() not in _LOOPBACK:
        raise FormatError("SOVA-CONTROL-TLS", "external website proof requires HTTPS")
    default_port = 80 if parsed.scheme == "http" else 443
    try:
        port = parsed.port or default_port
    except ValueError as error:
        raise FormatError(
            "SOVA-CONTROL-ORIGIN", "allowed website origin port is invalid"
        ) from error
    rendered_port = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.casefold()}{rendered_port}", parsed.hostname


@dataclass(frozen=True, slots=True)
class WebsiteControlChallenge:
    """Public token that the operator places on the exact target origin."""

    identifier: str
    origin: str
    host: str
    token: str
    proof_url: str
    created_at: datetime
    expires_at: datetime

    def to_mapping(self) -> dict[str, Any]:
        return {
            "artifactType": "sova.website-control-challenge",
            "schemaVersion": "0.1.0",
            "id": self.identifier,
            "origin": self.origin,
            "host": self.host,
            "token": self.token,
            "proofUrl": self.proof_url,
            "createdAt": _timestamp(self.created_at),
            "expiresAt": _timestamp(self.expires_at),
            "instructions": (
                "Serve the token as UTF-8 text at proofUrl without redirects, then run "
                "sova target prove before the challenge expires. Remove it after proof."
            ),
        }


def create_website_control_challenge(
    target: TargetManifest,
    *,
    now: datetime | None = None,
    ttl: timedelta = timedelta(minutes=15),
) -> WebsiteControlChallenge:
    """Create a short-lived public well-known challenge without contacting the site."""
    if not timedelta(minutes=1) <= ttl <= timedelta(hours=1):
        raise FormatError("SOVA-CONTROL-TTL", "control challenge TTL must be 1..60 minutes")
    origin, host = _target_origin(target)
    if host.casefold() in _LOOPBACK:
        raise FormatError(
            "SOVA-CONTROL-LOOPBACK",
            "loopback targets use the built-in loopback proof and need no hosted challenge",
        )
    current = now or datetime.now(UTC)
    identifier = secrets.token_hex(16)
    token = "sova-control-v1:" + secrets.token_urlsafe(32)
    proof_url = f"{origin}/.well-known/sova-control/{identifier}.txt"
    return WebsiteControlChallenge(
        identifier,
        origin,
        host,
        token,
        proof_url,
        current,
        current + ttl,
    )


def challenge_from_mapping(value: Mapping[str, Any]) -> WebsiteControlChallenge:
    required = {
        "artifactType",
        "schemaVersion",
        "id",
        "origin",
        "host",
        "token",
        "proofUrl",
        "createdAt",
        "expiresAt",
        "instructions",
    }
    if set(value) != required:
        raise FormatError("SOVA-CONTROL-CHALLENGE", "challenge fields are invalid")
    if (
        value.get("artifactType") != "sova.website-control-challenge"
        or value.get("schemaVersion") != "0.1.0"
    ):
        raise FormatError("SOVA-CONTROL-CHALLENGE", "challenge type or version is invalid")
    strings = ("id", "origin", "host", "token", "proofUrl")
    if any(not isinstance(value.get(name), str) or not value[name] for name in strings):
        raise FormatError("SOVA-CONTROL-CHALLENGE", "challenge text field is invalid")
    challenge = WebsiteControlChallenge(
        str(value["id"]),
        str(value["origin"]),
        str(value["host"]),
        str(value["token"]),
        str(value["proofUrl"]),
        _parse_timestamp(value["createdAt"]),
        _parse_timestamp(value["expiresAt"]),
    )
    if challenge.proof_url != (
        f"{challenge.origin}/.well-known/sova-control/{challenge.identifier}.txt"
    ):
        raise FormatError("SOVA-CONTROL-CHALLENGE", "challenge URL binding is invalid")
    if challenge.expires_at <= challenge.created_at:
        raise FormatError("SOVA-CONTROL-CHALLENGE", "challenge time window is invalid")
    return challenge


@dataclass(frozen=True, slots=True)
class ControlFetchResult:
    status: int
    final_url: str
    body: bytes
    redirected: bool


class ControlFetcher(Protocol):
    def fetch(self, url: str, *, timeout_seconds: float) -> ControlFetchResult: ...


class UrllibControlFetcher:
    """HTTPS verifier with certificate validation, no redirects, and bounded body."""

    def fetch(self, url: str, *, timeout_seconds: float) -> ControlFetchResult:
        if not 0 < timeout_seconds <= _MAX_PROOF_TIMEOUT_SECONDS:
            raise FormatError("SOVA-CONTROL-TIMEOUT", "proof timeout must be within 30 seconds")

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(
                self,
                _req: Any,
                _fp: Any,
                _code: int,
                _msg: str,
                _headers: Any,
                _newurl: str,
            ) -> None:
                return None

        opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        request = urllib.request.Request(  # noqa: S310 - URL was target-derived and pinned
            url,
            method="GET",
            headers={"accept": "text/plain", "user-agent": "sova-oss-control-verifier/0.1"},
        )
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                body = response.read(_MAX_PROOF_BYTES + 1)
                if len(body) > _MAX_PROOF_BYTES:
                    raise FormatError("SOVA-CONTROL-SIZE", "proof body exceeds 16 KiB")
                final_url = response.geturl()
                return ControlFetchResult(
                    int(response.status),
                    final_url,
                    body,
                    final_url != url,
                )
        except urllib.error.HTTPError as error:
            raise FormatError(
                "SOVA-CONTROL-HTTP",
                "control endpoint returned a non-success status",
                details={"status": error.code},
            ) from error
        except urllib.error.URLError as error:
            raise FormatError(
                "SOVA-CONTROL-NETWORK", "control endpoint could not be verified"
            ) from error


def collect_website_control_proof(
    challenge: WebsiteControlChallenge,
    *,
    fetcher: ControlFetcher | None = None,
    now: datetime | None = None,
) -> ControlProof:
    """Fetch and bind a well-known challenge; no redirect or origin change is accepted."""
    current = now or datetime.now(UTC)
    if current < challenge.created_at or current >= challenge.expires_at:
        raise FormatError("SOVA-CONTROL-EXPIRED", "website control challenge is not current")
    parsed = urlsplit(challenge.proof_url)
    if parsed.hostname != challenge.host or not challenge.proof_url.startswith(
        challenge.origin + "/"
    ):
        raise FormatError("SOVA-CONTROL-BINDING", "challenge origin binding is invalid")
    result = (fetcher or UrllibControlFetcher()).fetch(
        challenge.proof_url,
        timeout_seconds=10,
    )
    try:
        body = result.body.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise FormatError("SOVA-CONTROL-BODY", "control proof must be UTF-8 text") from error
    if (
        result.status != _HTTP_OK
        or result.redirected
        or result.final_url != challenge.proof_url
        or body != challenge.token
    ):
        raise FormatError("SOVA-CONTROL-MISMATCH", "control proof response did not match")
    return ControlProof(
        ControlProofMethod.WELL_KNOWN,
        challenge.host,
        challenge.token,
        {
            "https": urlsplit(challenge.origin).scheme == "https",
            "statusCode": result.status,
            "finalHost": challenge.host,
            "redirected": result.redirected,
            "body": body,
            "proofUrl": challenge.proof_url,
        },
        current,
        min(challenge.expires_at, current + timedelta(minutes=10)),
        "sova.website-control-verifier/0.1",
    )


def control_proof_from_mapping(value: Mapping[str, Any]) -> ControlProof:
    required = {
        "method",
        "subject",
        "challenge",
        "evidence",
        "observedAt",
        "expiresAt",
        "verifier",
    }
    if set(value) != required or not isinstance(value.get("evidence"), dict):
        raise FormatError("SOVA-CONTROL-PROOF", "control proof fields are invalid")
    try:
        method = ControlProofMethod(str(value["method"]))
    except ValueError as error:
        raise FormatError("SOVA-CONTROL-PROOF", "control proof method is invalid") from error
    strings = ("subject", "challenge", "verifier")
    if any(not isinstance(value.get(name), str) or not value[name] for name in strings):
        raise FormatError("SOVA-CONTROL-PROOF", "control proof text field is invalid")
    return ControlProof(
        method,
        str(value["subject"]),
        str(value["challenge"]),
        dict(value["evidence"]),
        _parse_timestamp(value["observedAt"]),
        _parse_timestamp(value["expiresAt"]),
        str(value["verifier"]),
    )


__all__ = [
    "ControlFetchResult",
    "ControlFetcher",
    "UrllibControlFetcher",
    "WebsiteControlChallenge",
    "challenge_from_mapping",
    "collect_website_control_proof",
    "control_proof_from_mapping",
    "create_website_control_challenge",
]
