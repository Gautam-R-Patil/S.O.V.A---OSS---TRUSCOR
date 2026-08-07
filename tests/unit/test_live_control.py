# SPDX-License-Identifier: Apache-2.0
"""External website control-challenge and proof contracts."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from email.message import Message
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Self
from urllib.request import urlopen

import pytest

import sova.live.control as control_module
from sova.formats.errors import FormatError
from sova.live import (
    ControlFetchResult,
    OwnedWebFixture,
    UrllibControlFetcher,
    challenge_from_mapping,
    collect_website_control_proof,
    control_proof_from_mapping,
    create_website_control_challenge,
)
from sova.safety import validate_control_proof
from sova.targets import TargetKind, TargetManifest

if TYPE_CHECKING:
    from types import TracebackType


class _Fetcher:
    def __init__(self, result: ControlFetchResult) -> None:
        self.result = result
        self.urls: list[str] = []

    def fetch(self, url: str, *, timeout_seconds: float) -> ControlFetchResult:
        assert timeout_seconds == 10
        self.urls.append(url)
        return self.result


def _target(origin: str = "https://owned.example") -> TargetManifest:
    return TargetManifest(
        "sova:target:owned-example",
        TargetKind.BROWSER_AGENT,
        "1.2.3",
        ("browser.observe", "browser.navigate"),
        "operator-owned external website",
        {"allowedOrigins": [origin], "browserProfile": "ephemeral"},
    )


def test_well_known_challenge_roundtrip_and_proof_validation() -> None:
    now = datetime(2026, 8, 7, 6, 0, tzinfo=UTC)
    challenge = create_website_control_challenge(_target(), now=now)
    parsed = challenge_from_mapping(challenge.to_mapping())
    fetcher = _Fetcher(
        ControlFetchResult(
            200,
            parsed.proof_url,
            (parsed.token + "\n").encode(),
            redirected=False,
        )
    )
    proof = collect_website_control_proof(parsed, fetcher=fetcher, now=now)
    restored = control_proof_from_mapping(proof.to_mapping())

    accepted, reasons = validate_control_proof(
        restored,
        target="owned.example",
        now=now,
    )
    assert accepted
    assert reasons == ()
    assert fetcher.urls == [challenge.proof_url]
    assert restored.evidence["proofUrl"] == challenge.proof_url


@pytest.mark.parametrize(
    "result",
    [
        ControlFetchResult(
            200,
            "https://attacker.example/proof",
            b"wrong",
            redirected=True,
        ),
        ControlFetchResult(
            200,
            "https://owned.example/wrong",
            b"wrong",
            redirected=False,
        ),
        ControlFetchResult(
            200,
            "https://owned.example/wrong",
            b"token",
            redirected=False,
        ),
    ],
)
def test_control_proof_rejects_redirect_substitution_and_wrong_body(
    result: ControlFetchResult,
) -> None:
    now = datetime(2026, 8, 7, 6, 0, tzinfo=UTC)
    challenge = create_website_control_challenge(_target(), now=now)
    with pytest.raises(FormatError, match="did not match"):
        collect_website_control_proof(challenge, fetcher=_Fetcher(result), now=now)


def test_control_challenge_rejects_loopback_http_and_multi_origin() -> None:
    with pytest.raises(FormatError, match="need no hosted challenge"):
        create_website_control_challenge(_target("http://127.0.0.1:8080"))
    target = _target()
    multi = TargetManifest(
        target.identifier,
        target.kind,
        target.version,
        target.capabilities,
        target.authorization_scope,
        {"allowedOrigins": ["https://one.example", "https://two.example"]},
    )
    with pytest.raises(FormatError, match="exactly one"):
        create_website_control_challenge(multi)


@pytest.mark.parametrize(
    ("origin", "code"),
    [
        ("ftp://owned.example", "SOVA-CONTROL-ORIGIN"),
        ("https://user@owned.example", "SOVA-CONTROL-ORIGIN"),
        ("https://owned.example/path", "SOVA-CONTROL-ORIGIN"),
        ("https://owned.example?query=1", "SOVA-CONTROL-ORIGIN"),
        ("https://owned.example#fragment", "SOVA-CONTROL-ORIGIN"),
        ("http://owned.example", "SOVA-CONTROL-TLS"),
        ("https://owned.example:99999", "SOVA-CONTROL-ORIGIN"),
    ],
)
def test_control_challenge_rejects_ambiguous_or_unprotected_origins(
    origin: str,
    code: str,
) -> None:
    with pytest.raises(FormatError) as error:
        create_website_control_challenge(_target(origin))
    assert error.value.issue.code == code


def test_control_challenge_rejects_wrong_target_ttl_and_invalid_time_fields() -> None:
    software = TargetManifest(
        "sova:target:software",
        TargetKind.LOCAL_PROCESS,
        "1.0.0",
        ("process.invoke",),
        "owned fixture",
        {},
    )
    with pytest.raises(FormatError, match="browser-agent"):
        create_website_control_challenge(software)
    for ttl in (timedelta(seconds=59), timedelta(hours=1, seconds=1)):
        with pytest.raises(FormatError, match=r"1\.\.60"):
            create_website_control_challenge(_target(), ttl=ttl)

    now = datetime(2026, 8, 7, 6, 0, tzinfo=UTC)
    value = create_website_control_challenge(_target(), now=now).to_mapping()
    for field, invalid in (
        ("createdAt", 7),
        ("createdAt", "not-a-time"),
        ("createdAt", "2026-08-07T06:00:00"),
    ):
        changed = {**value, field: invalid}
        with pytest.raises(FormatError) as error:
            challenge_from_mapping(changed)
        assert error.value.issue.code == "SOVA-CONTROL-TIME"
    with pytest.raises(FormatError, match="timezone"):
        control_module._timestamp(datetime(2026, 8, 7, 6, 0))  # noqa: DTZ001


def test_challenge_and_proof_mapping_reject_field_binding_and_type_failures() -> None:
    now = datetime(2026, 8, 7, 6, 0, tzinfo=UTC)
    challenge = create_website_control_challenge(_target(), now=now)
    value = challenge.to_mapping()
    mutations = (
        {key: item for key, item in value.items() if key != "instructions"},
        {**value, "schemaVersion": "9"},
        {**value, "token": ""},
        {**value, "proofUrl": value["proofUrl"] + "/wrong"},
        {**value, "expiresAt": value["createdAt"]},
    )
    for mutation in mutations:
        with pytest.raises(FormatError) as error:
            challenge_from_mapping(mutation)
        assert error.value.issue.code == "SOVA-CONTROL-CHALLENGE"

    fetcher = _Fetcher(
        ControlFetchResult(
            200,
            challenge.proof_url,
            challenge.token.encode(),
            redirected=False,
        )
    )
    proof = collect_website_control_proof(challenge, fetcher=fetcher, now=now).to_mapping()
    proof_mutations = (
        {key: item for key, item in proof.items() if key != "verifier"},
        {**proof, "method": "unknown"},
        {**proof, "subject": ""},
    )
    for mutation in proof_mutations:
        with pytest.raises(FormatError) as error:
            control_proof_from_mapping(mutation)
        assert error.value.issue.code == "SOVA-CONTROL-PROOF"


def test_control_collection_rejects_time_binding_and_non_utf8() -> None:
    now = datetime(2026, 8, 7, 6, 0, tzinfo=UTC)
    challenge = create_website_control_challenge(_target(), now=now)
    valid = ControlFetchResult(
        200,
        challenge.proof_url,
        challenge.token.encode(),
        redirected=False,
    )
    for instant in (now - timedelta(seconds=1), challenge.expires_at):
        with pytest.raises(FormatError) as error:
            collect_website_control_proof(challenge, fetcher=_Fetcher(valid), now=instant)
        assert error.value.issue.code == "SOVA-CONTROL-EXPIRED"
    rebound = type(challenge)(
        challenge.identifier,
        challenge.origin,
        "different.example",
        challenge.token,
        challenge.proof_url,
        challenge.created_at,
        challenge.expires_at,
    )
    with pytest.raises(FormatError) as binding:
        collect_website_control_proof(rebound, fetcher=_Fetcher(valid), now=now)
    assert binding.value.issue.code == "SOVA-CONTROL-BINDING"
    non_utf8 = ControlFetchResult(200, challenge.proof_url, b"\xff", redirected=False)
    with pytest.raises(FormatError) as body:
        collect_website_control_proof(challenge, fetcher=_Fetcher(non_utf8), now=now)
    assert body.value.issue.code == "SOVA-CONTROL-BODY"


class _Response:
    def __init__(self, body: bytes, url: str) -> None:
        self.status = HTTPStatus.OK
        self._body = body
        self._url = url

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _value: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self._body[:limit]

    def geturl(self) -> str:
        return self._url


class _Opener:
    def __init__(self, outcome: object) -> None:
        self.outcome = outcome

    def open(self, _request: object, *, timeout: float) -> Any:
        assert timeout > 0
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def test_urllib_control_fetcher_has_bounded_success_and_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://owned.example/.well-known/sova-control/proof.txt"
    fetcher = UrllibControlFetcher()
    with pytest.raises(FormatError, match="30 seconds"):
        fetcher.fetch(url, timeout_seconds=0)
    monkeypatch.setattr(ssl, "create_default_context", object)

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(_Response(b"token", url)),
    )
    assert fetcher.fetch(url, timeout_seconds=1) == ControlFetchResult(
        200, url, b"token", redirected=False
    )

    too_large = b"x" * (16 * 1024 + 1)
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: _Opener(_Response(too_large, url)),
    )
    with pytest.raises(FormatError) as size:
        fetcher.fetch(url, timeout_seconds=1)
    assert size.value.issue.code == "SOVA-CONTROL-SIZE"

    failures = (
        (urllib.error.HTTPError(url, 404, "missing", Message(), None), "SOVA-CONTROL-HTTP"),
        (urllib.error.URLError("offline"), "SOVA-CONTROL-NETWORK"),
    )
    for failure, code in failures:
        monkeypatch.setattr(
            urllib.request,
            "build_opener",
            lambda *_handlers, failure=failure: _Opener(failure),
        )
        with pytest.raises(FormatError) as error:
            fetcher.fetch(url, timeout_seconds=1)
        assert error.value.issue.code == code


def test_owned_web_fixture_serves_only_its_inert_loopback_page() -> None:
    unopened = OwnedWebFixture()
    assert unopened.url.startswith("http://127.0.0.1:")
    unopened.close()

    with OwnedWebFixture() as fixture:
        with urlopen(fixture.url, timeout=3) as response:  # noqa: S310 - self-owned loopback
            body = response.read()
        assert b"SOVA owned behavior fixture" in body
        with pytest.raises(urllib.error.HTTPError) as missing:
            urlopen(fixture.origin + "/missing", timeout=3)  # noqa: S310
        assert missing.value.code == HTTPStatus.NOT_FOUND
        fixture.start()
