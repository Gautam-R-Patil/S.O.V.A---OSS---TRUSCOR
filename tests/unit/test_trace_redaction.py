# SPDX-License-Identifier: Apache-2.0
"""Capture-time privacy contracts."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sova.formats import canonical_json_bytes
from sova.formats.errors import FormatError
from sova.trace.redaction import (
    RedactionPolicy,
    RedactionVerifier,
    Redactor,
    decrypt_placeholder,
    safe_environment,
)


def test_default_redaction_omits_secret_values_before_persistence() -> None:
    source = {
        "authorization": "Bearer top-secret-token-value",
        "nested": {"api_key": "synthetic-secret-value"},
        "safe": "visible",
    }
    redacted, records = Redactor().redact(source)
    rendered = repr(redacted)
    assert "top-secret" not in rendered
    assert "supersecret" not in rendered
    assert redacted["safe"] == "visible"
    assert {item["path"] for item in records} == {"$.authorization", "$.nested.api_key"}
    assert all(item["method"] == "omitted" for item in records)


def test_keyed_commitments_are_explicit_and_not_plain_hashes() -> None:
    policy = RedactionPolicy(method="keyed-commitment", commitment_key=b"k" * 32)
    redacted, records = Redactor(policy).redact({"token": "same-secret"})
    assert records[0]["method"] == "keyed-commitment"
    assert "commitment" in redacted["token"]["$redacted"]
    assert "same-secret" not in repr(redacted)


def test_keyed_commitments_are_canonical_path_and_context_bound() -> None:
    policy = RedactionPolicy(
        method="keyed-commitment",
        commitment_key=b"k" * 32,
        key_id="fixture-key",
    )
    first, first_records = Redactor(policy, context_id="trace-a").redact(
        {"token": {"b": 2, "a": 1}}
    )
    same, _same_records = Redactor(policy, context_id="trace-a").redact({"token": {"a": 1, "b": 2}})
    other, _other_records = Redactor(policy, context_id="trace-b").redact(
        {"token": {"a": 1, "b": 2}}
    )
    assert first["token"]["$redacted"]["commitment"] == (same["token"]["$redacted"]["commitment"])
    assert first["token"]["$redacted"]["commitment"] != (other["token"]["$redacted"]["commitment"])
    report = RedactionVerifier().verify(first, first_records)
    assert report.placeholders == report.records == 1


def test_encrypted_redaction_keeps_secret_out_of_plaintext() -> None:
    policy = RedactionPolicy(method="encrypted", encryption_key=b"e" * 32)
    redacted, records = Redactor(policy).redact({"password": "private-value"})
    assert records[0]["method"] == "encrypted"
    assert redacted["password"]["$redacted"]["algorithm"] == "AES-256-GCM"
    assert "private-value" not in repr(redacted)
    assert decrypt_placeholder(redacted["password"], encryption_key=b"e" * 32) == "private-value"


def test_encrypted_redaction_can_bucket_length_with_authenticated_padding() -> None:
    policy = RedactionPolicy(
        method="encrypted",
        encryption_key=b"e" * 32,
        encryption_padding_bytes=64,
    )
    short, _short_records = Redactor(policy).redact({"password": "x"})
    longer, _longer_records = Redactor(policy).redact({"password": "x" * 40})
    short_marker = short["password"]["$redacted"]
    longer_marker = longer["password"]["$redacted"]
    assert short_marker["padding"] == "iso7816-4"
    assert short_marker["paddingBlockBytes"] == 64
    assert short_marker["lengthLeakage"] == "bucketed"
    assert len(short_marker["ciphertext"]) == len(longer_marker["ciphertext"])
    assert decrypt_placeholder(short["password"], encryption_key=b"e" * 32) == "x"
    assert decrypt_placeholder(longer["password"], encryption_key=b"e" * 32) == "x" * 40


def test_decrypt_placeholder_remains_compatible_with_unpadded_v01_aad() -> None:
    key = b"e" * 32
    nonce = b"n" * 12
    plaintext = canonical_json_bytes("legacy-private-value")
    aad = canonical_json_bytes(
        {
            "class": "credential",
            "encoding": "sova-canonical-json/0.1",
            "path": "$.password",
            "policy": "sova.default",
            "policyVersion": "0.1.0",
        }
    )
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    placeholder = {
        "$redacted": {
            "class": "credential",
            "method": "encrypted",
            "present": True,
            "encoding": "sova-canonical-json/0.1",
            "algorithm": "AES-256-GCM",
            "keyId": None,
            "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode("ascii"),
            "aad": base64.urlsafe_b64encode(aad).decode("ascii"),
            "recoverableSensitiveData": True,
        }
    }

    assert decrypt_placeholder(placeholder, encryption_key=key) == "legacy-private-value"


def test_raw_environment_is_never_snapshotted() -> None:
    captured = safe_environment(
        {
            "LANG": "en_US.UTF-8",
            "SOVA_TEST_SEED": "7",
            "OPENAI_API_KEY": "must-not-appear",
            "PATH": "also-not-captured",
        }
    )
    assert captured == {"LANG": "en_US.UTF-8", "SOVA_TEST_SEED": "7"}


@pytest.mark.parametrize(
    ("arguments", "code"),
    [
        ({"method": "unknown"}, "SOVA-REDACTION-METHOD"),
        ({"method": "keyed-commitment"}, "SOVA-REDACTION-KEY"),
        ({"method": "keyed-commitment", "commitment_key": b"low-entropy"}, "SOVA-REDACTION-KEY"),
        (
            {"method": "encrypted", "encryption_key": b"short"},
            "SOVA-REDACTION-ENCRYPTION-KEY",
        ),
        (
            {"method": "omitted", "encryption_padding_bytes": 64},
            "SOVA-REDACTION-PADDING",
        ),
        (
            {
                "method": "encrypted",
                "encryption_key": b"e" * 32,
                "encryption_padding_bytes": "64",
            },
            "SOVA-REDACTION-PADDING",
        ),
        (
            {
                "method": "encrypted",
                "encryption_key": b"e" * 32,
                "encryption_padding_bytes": 64.0,
            },
            "SOVA-REDACTION-PADDING",
        ),
        (
            {
                "method": "encrypted",
                "encryption_key": b"e" * 32,
                "encryption_padding_bytes": 48,
            },
            "SOVA-REDACTION-PADDING",
        ),
    ],
)
def test_invalid_redaction_policies_fail_closed(
    arguments: dict[str, object],
    code: str,
) -> None:
    with pytest.raises(FormatError) as error:
        RedactionPolicy(**arguments)  # type: ignore[arg-type]
    assert error.value.issue.code == code


def test_secret_shaped_values_and_list_members_are_redacted() -> None:
    redacted, records = Redactor().redact(
        ["visible", "Bearer abcdefghijklmnopqrstuvwxyz", {"safe": "ghp_" + "a" * 24}]
    )
    assert redacted[0] == "visible"
    assert "$redacted" in redacted[1]
    assert "$redacted" in redacted[2]["safe"]
    assert [record["path"] for record in records] == ["$[1]", "$[2].safe"]


def test_defensive_missing_key_checks_remain_active() -> None:
    commitment = RedactionPolicy(method="keyed-commitment", commitment_key=b"k" * 32)
    object.__setattr__(commitment, "commitment_key", None)
    with pytest.raises(FormatError) as commitment_error:
        Redactor(commitment).redact({"token": "secret"})
    assert commitment_error.value.issue.code == "SOVA-REDACTION-KEY"

    encrypted = RedactionPolicy(method="encrypted", encryption_key=b"e" * 32)
    object.__setattr__(encrypted, "encryption_key", None)
    with pytest.raises(FormatError) as encryption_error:
        Redactor(encrypted).redact({"token": "secret"})
    assert encryption_error.value.issue.code == "SOVA-REDACTION-ENCRYPTION-KEY"


def test_redaction_verifier_rejects_inconsistent_or_residual_secrets() -> None:
    verifier = RedactionVerifier()
    with pytest.raises(FormatError) as mismatch:
        verifier.verify(
            {"safe": "value"},
            [{"path": "$.missing", "class": "x", "method": "omitted"}],
        )
    assert mismatch.value.issue.code == "SOVA-REDACTION-RECORD-MISMATCH"

    with pytest.raises(FormatError) as body:
        verifier.verify({"$redacted": "invalid"}, [])
    assert body.value.issue.code == "SOVA-REDACTION-PLACEHOLDER"

    with pytest.raises(FormatError) as metadata:
        verifier.verify({"$redacted": {"method": "omitted"}}, [])
    assert metadata.value.issue.code == "SOVA-REDACTION-PLACEHOLDER"

    with pytest.raises(FormatError) as key:
        verifier.verify({"api_key": "plain"}, [])
    assert key.value.issue.code == "SOVA-REDACTION-RESIDUAL-SECRET"

    with pytest.raises(FormatError) as value:
        verifier.verify(["Bearer abcdefghijklmnopqrstuvwxyz"], [])
    assert value.value.issue.code == "SOVA-REDACTION-RESIDUAL-SECRET"


def test_decrypt_placeholder_rejects_wrong_shapes_keys_and_ciphertext() -> None:
    with pytest.raises(FormatError) as not_encrypted:
        decrypt_placeholder({"visible": True}, encryption_key=b"e" * 32)
    assert not_encrypted.value.issue.code == "SOVA-REDACTION-DECRYPT"

    encrypted, _records = Redactor(
        RedactionPolicy(method="encrypted", encryption_key=b"e" * 32)
    ).redact({"token": "secret"})
    placeholder = encrypted["token"]
    with pytest.raises(FormatError) as short_key:
        decrypt_placeholder(placeholder, encryption_key=b"short")
    assert short_key.value.issue.code == "SOVA-REDACTION-ENCRYPTION-KEY"
    with pytest.raises(FormatError) as wrong_key:
        decrypt_placeholder(placeholder, encryption_key=b"x" * 32)
    assert wrong_key.value.issue.code == "SOVA-REDACTION-DECRYPT"

    padded, _records = Redactor(
        RedactionPolicy(
            method="encrypted",
            encryption_key=b"e" * 32,
            encryption_padding_bytes=64,
        )
    ).redact({"token": "secret"})
    padded["token"]["$redacted"]["paddingBlockBytes"] = 48
    with pytest.raises(FormatError) as invalid_padding:
        decrypt_placeholder(padded["token"], encryption_key=b"e" * 32)
    assert invalid_padding.value.issue.code == "SOVA-REDACTION-DECRYPT"

    authenticated, _records = Redactor(
        RedactionPolicy(
            method="encrypted",
            encryption_key=b"e" * 32,
            encryption_padding_bytes=64,
        )
    ).redact({"token": "secret"})
    authenticated["token"]["$redacted"]["paddingBlockBytes"] = 32
    with pytest.raises(FormatError) as metadata_tamper:
        decrypt_placeholder(authenticated["token"], encryption_key=b"e" * 32)
    assert metadata_tamper.value.issue.code == "SOVA-REDACTION-DECRYPT"
