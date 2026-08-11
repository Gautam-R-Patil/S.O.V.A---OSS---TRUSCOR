# SPDX-License-Identifier: Apache-2.0
"""Authenticated, acknowledged webhook delivery for monitor alerts."""

from __future__ import annotations

import hashlib
import hmac
import json
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.client import HTTPConnection, HTTPSConnection
from typing import Any, Protocol, cast
from urllib.parse import SplitResult, urlsplit

from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError

_MAX_RESPONSE_BYTES = 64 * 1024
_MIN_SECRET_BYTES = 32
_HTTP_SUCCESS_MIN = 200
_HTTP_SUCCESS_MAX = 300
_MAX_ATTEMPTS = 3


class AlertTransport(Protocol):
    def post(
        self,
        endpoint: str,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout_seconds: float,
    ) -> tuple[int, bytes]: ...


class AlertNotifier(Protocol):
    def notify(self, alert: dict[str, Any]) -> dict[str, Any]: ...


class StrictWebhookTransport:
    """HTTP transport with TLS by default, no redirects, and bounded responses."""

    def post(
        self,
        endpoint: str,
        body: bytes,
        headers: dict[str, str],
        *,
        timeout_seconds: float,
    ) -> tuple[int, bytes]:
        parsed = _validated_endpoint(endpoint)
        hostname = cast("str", parsed.hostname)
        if parsed.scheme == "https":
            connection: HTTPConnection = HTTPSConnection(
                hostname,
                parsed.port,
                timeout=timeout_seconds,
                context=ssl.create_default_context(),
            )
        else:
            connection = HTTPConnection(hostname, parsed.port, timeout=timeout_seconds)
        path = parsed.path or "/"
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            response_body = response.read(_MAX_RESPONSE_BYTES + 1)
        except OSError as error:
            raise FormatError("SOVA-ALERT-TRANSPORT", "webhook delivery failed") from error
        finally:
            connection.close()
        if len(response_body) > _MAX_RESPONSE_BYTES:
            raise FormatError("SOVA-ALERT-RESPONSE", "webhook acknowledgement exceeds 64 KiB")
        return response.status, response_body


def _validated_endpoint(endpoint: str) -> SplitResult:
    parsed = urlsplit(endpoint)
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or (parsed.scheme == "http" and not loopback)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise FormatError(
            "SOVA-ALERT-ENDPOINT",
            "webhooks require HTTPS, except for credential-free loopback fixtures",
        )
    return parsed


@dataclass(frozen=True, slots=True)
class WebhookAlertNotifier:
    endpoint: str
    secret: bytes
    transport: AlertTransport = field(default_factory=StrictWebhookTransport)
    timeout_seconds: float = 10.0
    max_attempts: int = 3

    def __post_init__(self) -> None:
        _validated_endpoint(self.endpoint)
        if len(self.secret) < _MIN_SECRET_BYTES:
            raise FormatError("SOVA-ALERT-SECRET", "webhook secret must contain at least 32 bytes")
        if self.timeout_seconds <= 0 or not 1 <= self.max_attempts <= _MAX_ATTEMPTS:
            raise FormatError("SOVA-ALERT-CONFIG", "webhook retry or timeout bounds are invalid")

    def notify(self, alert: dict[str, Any]) -> dict[str, Any]:
        body = canonical_json_bytes(alert)
        identifier = sha256_digest(body)
        timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        signed = timestamp.encode() + b"\n" + identifier.encode() + b"\n" + body
        signature = hmac.new(self.secret, signed, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": identifier,
            "X-SOVA-Timestamp": timestamp,
            "X-SOVA-Signature": f"hmac-sha256={signature}",
        }
        failures: list[str] = []
        for attempt in range(1, self.max_attempts + 1):
            try:
                status, response = self.transport.post(
                    self.endpoint,
                    body,
                    headers,
                    timeout_seconds=self.timeout_seconds,
                )
                acknowledgement = json.loads(response)
                accepted = (
                    _HTTP_SUCCESS_MIN <= status < _HTTP_SUCCESS_MAX
                    and isinstance(acknowledgement, dict)
                    and acknowledgement.get("accepted") is True
                    and acknowledgement.get("idempotencyKey") == identifier
                )
                if accepted:
                    return {
                        "mode": "authenticated-webhook",
                        "status": "acknowledged",
                        "attempts": attempt,
                        "idempotencyKey": identifier,
                        "payloadDigest": identifier,
                        "endpointOrigin": _endpoint_origin(self.endpoint),
                        "secretRecorded": False,
                    }
                failures.append(f"attempt-{attempt}:unacknowledged-{status}")
            except (FormatError, UnicodeDecodeError, json.JSONDecodeError):
                failures.append(f"attempt-{attempt}:transport-or-acknowledgement-error")
        return {
            "mode": "authenticated-webhook",
            "status": "failed",
            "attempts": self.max_attempts,
            "idempotencyKey": identifier,
            "payloadDigest": identifier,
            "endpointOrigin": _endpoint_origin(self.endpoint),
            "secretRecorded": False,
            "failureClasses": failures,
        }


def _endpoint_origin(endpoint: str) -> str:
    parsed = _validated_endpoint(endpoint)
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


__all__ = [
    "AlertNotifier",
    "AlertTransport",
    "StrictWebhookTransport",
    "WebhookAlertNotifier",
]
