# SPDX-License-Identifier: Apache-2.0
"""Signed worker protocol and mTLS configuration tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from sova.formats import FormatError, canonical_json_bytes, sha256_digest, validate_document
from sova.trace.integrity import generate_ed25519_keypair, sign_dsse_payload
from sova.worker.protocol import (
    WORKER_PROTOCOL_MEDIA_TYPE,
    ProtocolMessage,
    ProtocolMessageType,
    ProtocolRole,
    ReplayCache,
    build_controller_tls_context,
    build_worker_tls_context,
    certificate_digest,
    sign_protocol_message,
    verify_protocol_message,
)
from tests.support.worker import digest

if TYPE_CHECKING:
    from pathlib import Path

PEER_CERTIFICATE = b"deterministic-worker-certificate-der"
NOW = datetime(2026, 8, 27, 10, 0, 30, tzinfo=UTC)


def _message(*, certificate: bytes = PEER_CERTIFICATE) -> ProtocolMessage:
    return ProtocolMessage(
        message_type=ProtocolMessageType.SUBMIT_JOB,
        message_id="message:p5-1",
        job_id="job:p5-fixture",
        sender_role=ProtocolRole.CONTROLLER,
        sender_id="controller:primary",
        recipient_id="worker:primary",
        issued_at="2026-08-27T10:00:00Z",
        expires_at="2026-08-27T10:01:00Z",
        nonce="ABCDEFGHIJKLMNOPQRSTUV",
        sender_certificate_digest=certificate_digest(certificate),
        payload_digest=digest("job-manifest"),
    )


def test_protocol_message_is_signed_peer_bound_and_schema_valid() -> None:
    keypair = generate_ed25519_keypair()
    message = _message()
    envelope = sign_protocol_message(message, keypair)
    verified = verify_protocol_message(
        envelope,
        keypair.public_key,
        expected_sender_role=ProtocolRole.CONTROLLER,
        expected_sender_id="controller:primary",
        expected_recipient_id="worker:primary",
        peer_certificate_der=PEER_CERTIFICATE,
        now=NOW,
        replay_cache=ReplayCache(),
    )
    assert verified == message
    validate_document(verified.to_mapping())


def test_protocol_replay_is_denied() -> None:
    keypair = generate_ed25519_keypair()
    envelope = sign_protocol_message(_message(), keypair)
    cache = ReplayCache()
    verify_protocol_message(
        envelope,
        keypair.public_key,
        expected_sender_role=ProtocolRole.CONTROLLER,
        expected_sender_id="controller:primary",
        expected_recipient_id="worker:primary",
        peer_certificate_der=PEER_CERTIFICATE,
        now=NOW,
        replay_cache=cache,
    )
    with pytest.raises(FormatError, match="already admitted"):
        verify_protocol_message(
            envelope,
            keypair.public_key,
            expected_sender_role=ProtocolRole.CONTROLLER,
            expected_sender_id="controller:primary",
            expected_recipient_id="worker:primary",
            peer_certificate_der=PEER_CERTIFICATE,
            now=NOW,
            replay_cache=cache,
        )


def test_protocol_certificate_and_sender_mismatch_are_denied() -> None:
    keypair = generate_ed25519_keypair()
    envelope = sign_protocol_message(_message(), keypair)
    with pytest.raises(FormatError, match="TLS peer"):
        verify_protocol_message(
            envelope,
            keypair.public_key,
            expected_sender_role=ProtocolRole.CONTROLLER,
            expected_sender_id="controller:primary",
            expected_recipient_id="worker:primary",
            peer_certificate_der=b"another-certificate",
            now=NOW,
            replay_cache=ReplayCache(),
        )
    with pytest.raises(FormatError, match="sender identity"):
        verify_protocol_message(
            envelope,
            keypair.public_key,
            expected_sender_role=ProtocolRole.CONTROLLER,
            expected_sender_id="controller:secondary",
            expected_recipient_id="worker:primary",
            peer_certificate_der=PEER_CERTIFICATE,
            now=NOW,
            replay_cache=ReplayCache(),
        )


def test_protocol_rejects_expired_authority_and_wrong_direction() -> None:
    message = _message()
    cache = ReplayCache()
    with pytest.raises(FormatError, match="authority window"):
        cache.admit(message, now=NOW + timedelta(minutes=2))
    with pytest.raises(FormatError, match="sender role"):
        ProtocolMessage(
            message_type=ProtocolMessageType.SUBMIT_JOB,
            message_id="message:p5-2",
            job_id="job:p5-fixture",
            sender_role=ProtocolRole.WORKER,
            sender_id="worker:primary",
            recipient_id="controller:primary",
            issued_at="2026-08-27T10:00:00Z",
            expires_at="2026-08-27T10:01:00Z",
            nonce="ZYXWVUTSRQPONMLKJIHGFE",
            sender_certificate_digest=digest("cert"),
            payload_digest=digest("payload"),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"protocol_version": "9.9.9"},
        {"message_id": "BAD ID"},
        {"issued_at": "not-time"},
        {"expires_at": "2026-08-27T10:10:00Z"},
        {"nonce": "short"},
        {"payload_digest": "bad"},
    ],
)
def test_protocol_constructor_rejects_malformed_authority(changes: dict[str, Any]) -> None:
    values = {
        "message_type": ProtocolMessageType.SUBMIT_JOB,
        "message_id": "message:p5-adverse",
        "job_id": "job:p5-fixture",
        "sender_role": ProtocolRole.CONTROLLER,
        "sender_id": "controller:primary",
        "recipient_id": "worker:primary",
        "issued_at": "2026-08-27T10:00:00Z",
        "expires_at": "2026-08-27T10:01:00Z",
        "nonce": "ABCDEFGHIJKLMNOPQRSTUV",
        "sender_certificate_digest": digest("cert"),
        "payload_digest": digest("payload"),
    }
    values.update(changes)
    with pytest.raises(FormatError):
        ProtocolMessage(**values)  # type: ignore[arg-type]


def test_protocol_mapping_parser_rejects_structure_digest_sender_and_enum() -> None:
    mapping = _message().to_mapping()
    mutations = []
    missing = dict(mapping)
    missing.pop("jobId")
    mutations.append(missing)
    wrong_type = dict(mapping)
    wrong_type["artifactType"] = "wrong"
    mutations.append(wrong_type)
    wrong_digest = dict(mapping)
    wrong_digest["jobId"] = "job:changed"
    mutations.append(wrong_digest)
    bad_sender = dict(mapping)
    bad_sender["sender"] = {"role": "controller"}
    mutations.append(bad_sender)
    bad_enum = dict(mapping)
    bad_enum["sender"] = {"role": "invalid", "id": "controller:primary"}
    unsigned = dict(bad_enum)
    unsigned.pop("contentDigest")
    bad_enum["contentDigest"] = sha256_digest(canonical_json_bytes(unsigned))
    mutations.append(bad_enum)
    for mutation in mutations:
        with pytest.raises(FormatError):
            ProtocolMessage.from_mapping(mutation)


def test_replay_cache_rejects_naive_not_yet_valid_and_capacity() -> None:
    message = _message()
    with pytest.raises(FormatError, match="timezone-aware"):
        ReplayCache().admit(message, now=NOW.replace(tzinfo=None))
    with pytest.raises(FormatError, match="authority window"):
        ReplayCache().admit(message, now=datetime(2026, 8, 27, 9, 59, tzinfo=UTC))
    with pytest.raises(FormatError, match="capacity"):
        ReplayCache(maximum_entries=1).admit(message, now=NOW)


def test_certificate_digest_requires_certificate_bytes() -> None:
    with pytest.raises(FormatError, match="required"):
        certificate_digest(b"")


def test_tls_context_builders_require_tls13_and_mutual_verification(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ca = tmp_path / "ca.pem"
    certificate = tmp_path / "certificate.pem"
    private_key = tmp_path / "key.pem"
    for path in (ca, certificate, private_key):
        path.write_text("fixture", encoding="utf-8")

    class FakeContext:
        minimum_version: object = None
        maximum_version: object = None
        check_hostname: bool = False
        verify_mode: object = None

        def load_cert_chain(self, **kwargs: object) -> None:
            assert set(kwargs) == {"certfile", "keyfile"}

        def load_verify_locations(self, **kwargs: object) -> None:
            assert set(kwargs) == {"cafile"}

    controller = FakeContext()
    worker = FakeContext()
    monkeypatch.setattr(
        "sova.worker.protocol.ssl.create_default_context",
        lambda *_args, **_kwargs: controller,
    )
    monkeypatch.setattr(
        "sova.worker.protocol.ssl.SSLContext",
        lambda *_args, **_kwargs: worker,
    )
    build_controller_tls_context(
        ca_file=ca, certificate_file=certificate, private_key_file=private_key
    )
    build_worker_tls_context(ca_file=ca, certificate_file=certificate, private_key_file=private_key)
    assert controller.minimum_version == controller.maximum_version
    assert controller.check_hostname is True
    assert worker.minimum_version == worker.maximum_version


def test_protocol_verifier_rejects_non_object_signed_payload() -> None:
    keypair = generate_ed25519_keypair()
    envelope = sign_dsse_payload(WORKER_PROTOCOL_MEDIA_TYPE, canonical_json_bytes([]), keypair)
    with pytest.raises(FormatError, match="root must be an object"):
        verify_protocol_message(
            envelope,
            keypair.public_key,
            expected_sender_role=ProtocolRole.CONTROLLER,
            expected_sender_id="controller:primary",
            expected_recipient_id="worker:primary",
            peer_certificate_der=PEER_CERTIFICATE,
            now=NOW,
            replay_cache=ReplayCache(),
        )
