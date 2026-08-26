# SPDX-License-Identifier: Apache-2.0
"""HTTP client for the operator-run, loopback-bound SOVA community registry service.

This client speaks the exact contract `sova.registry.service.CommunityHTTPService`
implements: `GET /v1/health` (verified via `check_community_service_health`),
`POST /v1/submissions` (Bearer-token-gated, exactly one capsule plus one trace
per submission, built via `prepare_community_submission`/
`serialize_community_submission`), and `GET /v1/submissions/<id>` for status
polling.  No other route is assumed.  Uses the standard library only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError
from sova.registry.service import (
    CommunityServiceLimits,
    check_community_service_health,
    prepare_community_submission,
    serialize_community_submission,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MIN_TOKEN_CHARS = 24
_TERMINAL_STATUSES = frozenset({"accepted", "rejected"})


@dataclass(frozen=True, slots=True)
class RegistryEndpoint:
    """One operator-supplied loopback registry service origin and bearer token."""

    base_url: str
    token: str

    def __post_init__(self) -> None:
        if not self.base_url.startswith("http://127.0.0.1:"):
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-URL",
                "registry base url must be an exact literal-IPv4 loopback HTTP origin",
            )
        if len(self.token) < _MIN_TOKEN_CHARS:
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-TOKEN",
                "operator token must contain at least 24 characters",
            )


class RegistryClient:
    """Thin client over the token-gated staged-upload registry service contract."""

    def __init__(self, endpoint: RegistryEndpoint, *, timeout_s: float = 30.0) -> None:
        if type(endpoint) is not RegistryEndpoint or timeout_s <= 0:
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-CONFIG",
                "registry client requires one exact endpoint and a positive timeout",
            )
        self._endpoint = endpoint
        self._timeout_s = timeout_s

    def _url(self, route: str) -> str:
        return urljoin(self._endpoint.base_url.rstrip("/") + "/", route.lstrip("/"))

    def _read_json(self, request: Request) -> dict[str, Any]:
        try:
            with urlopen(request, timeout=self._timeout_s) as response:  # noqa: S310 - operator-configured loopback endpoint only
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            body = error.read(_MAX_RESPONSE_BYTES)
            details: dict[str, Any] = {"httpStatus": error.code}
            try:
                parsed_error = strict_json_loads(body, max_bytes=_MAX_RESPONSE_BYTES)
            except FormatError:
                parsed_error = None
            if isinstance(parsed_error, dict):
                details["response"] = parsed_error
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-HTTP",
                f"registry service returned HTTP {error.code}",
                details=details,
            ) from error
        except URLError as error:
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-UNAVAILABLE",
                "registry service is unavailable",
            ) from error
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-SIZE",
                "registry response exceeds the client size limit",
            )
        parsed = strict_json_loads(raw, max_bytes=_MAX_RESPONSE_BYTES)
        if not isinstance(parsed, dict):
            raise FormatError(
                "SOVA-REGISTRY-CLIENT-BODY",
                "registry response is not a JSON object",
            )
        return parsed

    def health(self) -> dict[str, Any]:
        """Verify the service is exactly ready; never trust advertised limits unchecked."""
        return check_community_service_health(self._url("/v1/health"))

    def limits(self) -> CommunityServiceLimits:
        """Return upload limits from a freshly verified health response."""
        verified = self.health()
        raw = verified["uploadLimits"]
        return CommunityServiceLimits(
            max_body_bytes=raw["maxRequestBodyBytes"],
            max_file_bytes=raw["maxRawFileBytes"],
            max_files=raw["maxFiles"],
        )

    def submit_capsule_and_trace(
        self,
        *,
        kind: str,
        metadata: dict[str, Any],
        capsule: Path,
        trace: Path,
        limits: CommunityServiceLimits | None = None,
    ) -> dict[str, Any]:
        """Build and submit the exact two-file submission; returns the queued status doc.

        The submission is built entirely offline (`prepare_community_submission`)
        and validated against `limits` before any network call, so oversize or
        malformed inputs never reach the service.
        """
        selected = limits if limits is not None else self.limits()
        document = prepare_community_submission(
            kind=kind,
            metadata=metadata,
            capsule=capsule,
            trace=trace,
            limits=selected,
        )
        body = serialize_community_submission(document, limits=selected)
        request = Request(  # noqa: S310 - operator-configured loopback endpoint only
            self._url("/v1/submissions"),
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._endpoint.token}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        return self._read_json(request)

    def submission_status(self, submission_id: str) -> dict[str, Any]:
        request = Request(  # noqa: S310 - operator-configured loopback endpoint only
            self._url(f"/v1/submissions/{submission_id}"), method="GET"
        )
        return self._read_json(request)

    def wait_until_terminal(
        self,
        submission_id: str,
        *,
        poll_interval_s: float = 2.0,
        timeout_s: float = 120.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> dict[str, Any]:
        """Poll until `accepted`/`rejected` or the deadline; never blocks past `timeout_s`."""
        deadline = clock() + timeout_s
        status = self.submission_status(submission_id)
        while status["status"] not in _TERMINAL_STATUSES and clock() < deadline:
            sleep(poll_interval_s)
            status = self.submission_status(submission_id)
        return status


__all__ = ["RegistryClient", "RegistryEndpoint"]
