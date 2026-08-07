# SPDX-License-Identifier: Apache-2.0
"""External website control-challenge and proof contracts."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sova.formats.errors import FormatError
from sova.live import (
    ControlFetchResult,
    challenge_from_mapping,
    collect_website_control_proof,
    control_proof_from_mapping,
    create_website_control_challenge,
)
from sova.safety import validate_control_proof
from sova.targets import TargetKind, TargetManifest


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
