# SPDX-License-Identifier: Apache-2.0
"""Streaming trace, integrity, query, and playback contracts."""

from __future__ import annotations

import base64
import json
import zipfile
from typing import TYPE_CHECKING, Any, cast

import pytest

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.formats import PackageReader, PackageWriter, canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.trace import (
    TraceReader,
    TraceWriter,
    generate_ed25519_keypair,
    recover_trace,
)
from sova.trace import integrity as integrity_module
from sova.trace.integrity import unsigned_manifest_digest, verify_trace_signature
from sova.trace.kinds import EVENT_FAMILIES, event_registry_digest

if TYPE_CHECKING:
    from pathlib import Path


def _write_trace(
    path: Path,
    *,
    signed: bool = True,
    completion: str = "completed",
    profile: str = "standard",
) -> tuple[str, str | None]:
    key = generate_ed25519_keypair() if signed else None
    writer = TraceWriter(
        path,
        capture_profile=profile,
        segment_events=2,
        signing_key=key,
        authorization={
            "decision": "allowed",
            "scopeDigest": "sha256:" + "1" * 64,
            "decidedBy": "test-operator",
        },
    )
    first = writer.append("run.started", {"objective": "synthetic"})
    second = writer.append(
        "prompt.sent",
        {"text": "hello", "authorization": "Bearer secret-token-123456"},
        parents=[first] if first else [],
    )
    writer.append(
        "model.response",
        {"text": "observable response"},
        parents=[second] if second else [],
    )
    writer.append("tool.completed", {"tool": "fixture.read", "ok": True})
    writer.add_blob(b"same")
    writer.add_blob(b"same")
    digest = writer.finalize(completion=completion)
    return digest, key.key_id if key else None


def test_signed_trace_round_trip_and_offline_verification(tmp_path: Path) -> None:
    path = tmp_path / "run.sova-trace"
    digest, key_id = _write_trace(path)
    assert digest.startswith("sha256:")
    assert key_id is not None

    reader = TraceReader(path)
    report = reader.verify(require_signature=True, required_key_id=key_id)
    assert report.event_count == 4
    assert report.signature_valid
    assert report.trust_policy == "required-key"
    assert "non-repudiable" in report.limitations[-1]
    assert [event["sequence"] for event in reader.events()] == [0, 1, 2, 3]
    assert [event["kind"] for event in reader.query(kind_prefix="model.")] == [
        "model.response"
    ]
    assert reader.playback()[0].startswith("000000 ")
    view = reader.disclosure_view(sequences={0, 2}, include_payload=False)
    assert view["selectedEventCount"] == 2
    assert view["omittedEventCount"] == 2
    assert view["cryptographicSelectiveDisclosure"] is False
    assert all(event["payloadOmitted"] for event in view["events"])
    assert reader.manifest()["retention"]["policy"] == "operator-controlled"
    actor_id = reader.events()[0]["actor"]["id"]
    assert len(list(reader.query(actor_id=actor_id))) == 4
    assert list(reader.query(actor_id="sova:actor:missing")) == []
    payload_view = reader.disclosure_view(include_payload=True)
    assert payload_view["payloadsIncluded"] is True
    assert "payload" in payload_view["events"][0]

    package_objects = PackageReader(path).verify("sova.trace")
    blob_objects = [item for item in package_objects if item.role == "blob"]
    assert len(blob_objects) == 1
    persisted = b"".join(
        PackageReader(path).read_object(item)
        for item in package_objects
        if item.role == "event-segment"
    )
    assert b"secret-token" not in persisted
    assert b"$redacted" in persisted


@pytest.mark.parametrize(
    "completion",
    ["completed", "failed", "cancelled", "timeout", "crashed", "partial", "recovered"],
)
def test_every_terminal_path_uses_the_same_trace_family(
    tmp_path: Path,
    completion: str,
) -> None:
    path = tmp_path / f"{completion}.sova-trace"
    _write_trace(path, signed=False, completion=completion)
    report = TraceReader(path).verify()
    assert report.completion == completion
    assert not report.signature_present


def test_unsigned_trace_fails_when_trust_policy_requires_signature(tmp_path: Path) -> None:
    path = tmp_path / "unsigned.sova-trace"
    _write_trace(path, signed=False)
    with pytest.raises(FormatError) as error:
        TraceReader(path).verify(require_signature=True)
    assert error.value.issue.code == "SOVA-INTEGRITY-SIGNATURE-REQUIRED"


def test_required_signer_policy_rejects_a_different_valid_key(tmp_path: Path) -> None:
    path = tmp_path / "signed.sova-trace"
    _write_trace(path)
    with pytest.raises(FormatError) as error:
        TraceReader(path).verify(required_key_id="sha256:" + "0" * 64)
    assert error.value.issue.code == "SOVA-INTEGRITY-UNTRUSTED-SIGNER"


def test_signature_material_failure_modes_are_typed(tmp_path: Path) -> None:
    path = tmp_path / "signed.sova-trace"
    _write_trace(path)
    manifest = TraceReader(path).manifest()

    unsigned = json.loads(json.dumps(manifest))
    unsigned["integrity"]["signature"] = None
    with pytest.raises(FormatError) as no_signature:
        verify_trace_signature(unsigned)
    assert no_signature.value.issue.code == "SOVA-INTEGRITY-UNSIGNED"

    malformed = json.loads(json.dumps(manifest))
    del malformed["integrity"]["signature"]["envelope"]["payload"]
    with pytest.raises(FormatError) as malformed_error:
        verify_trace_signature(malformed)
    assert malformed_error.value.issue.code == "SOVA-INTEGRITY-MALFORMED-SIGNATURE"

    unsupported = json.loads(json.dumps(manifest))
    unsupported["integrity"]["signature"]["publicKey"]["algorithm"] = "rsa"
    with pytest.raises(FormatError) as unsupported_error:
        verify_trace_signature(unsupported)
    assert unsupported_error.value.issue.code == "SOVA-INTEGRITY-UNSUPPORTED-SIGNATURE"

    mismatch = json.loads(json.dumps(manifest))
    mismatch["integrity"]["signature"]["publicKey"]["keyid"] = "sha256:" + "0" * 64
    with pytest.raises(FormatError) as mismatch_error:
        verify_trace_signature(mismatch)
    assert mismatch_error.value.issue.code == "SOVA-INTEGRITY-KEY-MISMATCH"

    multiple = json.loads(json.dumps(manifest))
    multiple["integrity"]["signature"]["envelope"]["signatures"] = []
    with pytest.raises(FormatError) as multiple_error:
        verify_trace_signature(multiple)
    assert multiple_error.value.issue.code == "SOVA-INTEGRITY-MALFORMED-SIGNATURE"

    wrong_entry = json.loads(json.dumps(manifest))
    wrong_entry["integrity"]["signature"]["envelope"]["signatures"] = ["invalid"]
    with pytest.raises(FormatError) as entry_error:
        verify_trace_signature(wrong_entry)
    assert entry_error.value.issue.code == "SOVA-INTEGRITY-MALFORMED-SIGNATURE"

    missing_sig = json.loads(json.dumps(manifest))
    del missing_sig["integrity"]["signature"]["envelope"]["signatures"][0]["sig"]
    with pytest.raises(FormatError) as missing_sig_error:
        verify_trace_signature(missing_sig)
    assert missing_sig_error.value.issue.code == "SOVA-INTEGRITY-MALFORMED-SIGNATURE"


def test_signature_base64_decoder_accepts_urlsafe_and_rejects_bad_values() -> None:
    assert integrity_module._decode_base64("YWJj") == b"abc"
    assert integrity_module._decode_base64("_w") == b"\xff"
    with pytest.raises(FormatError) as wrong_type:
        integrity_module._decode_base64(1)
    assert wrong_type.value.issue.code == "SOVA-INTEGRITY-MALFORMED-SIGNATURE"
    with pytest.raises(FormatError) as invalid:
        integrity_module._decode_base64("%%%")
    assert invalid.value.issue.code == "SOVA-INTEGRITY-MALFORMED-SIGNATURE"


def test_signed_statement_shape_and_binding_are_verified(tmp_path: Path) -> None:
    key = generate_ed25519_keypair()
    path = tmp_path / "statement.sova-trace"
    writer = TraceWriter(path, signing_key=key)
    writer.append("run.started", {})
    writer.finalize()
    manifest = TraceReader(path).manifest()

    private_cls, _public_cls, _serialization = integrity_module._crypto()

    def replace_statement(value: object) -> dict[str, Any]:
        changed = cast("dict[str, Any]", json.loads(json.dumps(manifest)))
        material = changed["integrity"]["signature"]
        payload = canonical_json_bytes(value)
        signature = private_cls.from_private_bytes(key.private_key).sign(
            integrity_module._pae(
                material["envelope"]["payloadType"],
                payload,
            )
        )
        material["envelope"]["payload"] = base64.b64encode(payload).decode("ascii")
        material["envelope"]["signatures"][0]["sig"] = base64.b64encode(signature).decode(
            "ascii"
        )
        return changed

    with pytest.raises(FormatError) as non_object:
        verify_trace_signature(replace_statement([]))
    assert non_object.value.issue.code == "SOVA-INTEGRITY-STATEMENT"

    with pytest.raises(FormatError) as malformed:
        verify_trace_signature(replace_statement({}))
    assert malformed.value.issue.code == "SOVA-INTEGRITY-STATEMENT"

    original_statement = json.loads(
        base64.b64decode(
            manifest["integrity"]["signature"]["envelope"]["payload"],
            validate=True,
        )
    )
    original_statement["predicate"]["traceId"] = "sova:trace:wrong"
    with pytest.raises(FormatError) as mismatch:
        verify_trace_signature(replace_statement(original_statement))
    assert mismatch.value.issue.code == "SOVA-INTEGRITY-STATEMENT-MISMATCH"


def test_missing_signing_dependency_is_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_name: str) -> object:
        raise ImportError("fixture")

    monkeypatch.setattr(integrity_module.importlib, "import_module", unavailable)
    with pytest.raises(FormatError) as error:
        generate_ed25519_keypair()
    assert error.value.issue.code == "SOVA-INTEGRITY-SIGNING-UNAVAILABLE"


def test_lite_capture_is_intentionally_lossy_and_declared(tmp_path: Path) -> None:
    path = tmp_path / "lite.sova-trace"
    writer = TraceWriter(path, capture_profile="lite")
    assert writer.append("filesystem.observed", {"path": "fixture"}) is None
    assert writer.append("run.started", {"safe": True}) is not None
    writer.finalize()
    assert [event["kind"] for event in TraceReader(path).events()] == ["run.started"]
    assert TraceReader(path).manifest()["captureProfile"] == "lite"


def test_writer_lifecycle_and_configuration_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(FormatError) as profile:
        TraceWriter(tmp_path / "profile.sova-trace", capture_profile="unknown")
    assert profile.value.issue.code == "SOVA-TRACE-PROFILE"
    with pytest.raises(FormatError) as segment:
        TraceWriter(tmp_path / "segment.sova-trace", segment_events=0)
    assert segment.value.issue.code == "SOVA-TRACE-SEGMENT-SIZE"
    with pytest.raises(FormatError) as segment_bytes:
        TraceWriter(tmp_path / "segment-bytes.sova-trace", segment_bytes=100)
    assert segment_bytes.value.issue.code == "SOVA-TRACE-SEGMENT-BYTES"
    with pytest.raises(FormatError) as content:
        TraceWriter(tmp_path / "content.sova-trace", content_capture="unknown")
    assert content.value.issue.code == "SOVA-TRACE-CONTENT-CAPTURE"
    with pytest.raises(FormatError) as durability:
        TraceWriter(tmp_path / "durability.sova-trace", durability="unknown")
    assert durability.value.issue.code == "SOVA-TRACE-DURABILITY"
    with pytest.raises(FormatError) as material:
        TraceWriter(
            tmp_path / "material.sova-trace",
            verification_material={"timestamp": "fixture"},
        )
    assert material.value.issue.code == "SOVA-INTEGRITY-VERIFICATION-MATERIAL"

    staged_path = tmp_path / "staged.sova-trace"
    staged_path.with_name(".staged.sova-trace.partial").mkdir()
    with pytest.raises(FormatError) as staging:
        TraceWriter(staged_path)
    assert staging.value.issue.code == "SOVA-TRACE-STAGING-EXISTS"

    path = tmp_path / "closed.sova-trace"
    writer = TraceWriter(path)
    with pytest.raises(FormatError) as completion:
        writer.finalize(completion="unknown")
    assert completion.value.issue.code == "SOVA-TRACE-COMPLETION"
    writer.finalize()
    with pytest.raises(FormatError) as append:
        writer.append("run.started", {})
    assert append.value.issue.code == "SOVA-TRACE-CLOSED"
    with pytest.raises(FormatError) as blob:
        writer.add_blob(b"late")
    assert blob.value.issue.code == "SOVA-TRACE-CLOSED"
    with pytest.raises(FormatError) as finalized:
        writer.finalize()
    assert finalized.value.issue.code == "SOVA-TRACE-CLOSED"


def test_metadata_only_and_forensic_capture_declare_their_semantics(tmp_path: Path) -> None:
    path = tmp_path / "metadata.sova-trace"
    writer = TraceWriter(
        path,
        content_capture="metadata-only",
        durability="forensic",
        segment_events=1,
        segment_bytes=1024,
        reviewed_for_export=True,
    )
    assert writer.event_count == 0
    writer.append("run.started", {"secret": "must-not-persist"})
    writer.append("run.completed", {"large": "x" * 900})
    writer.add_blob(b"durable")
    writer.finalize()
    reader = TraceReader(path)
    events = reader.events()
    assert len(events) == 2
    assert events[0]["payload"]["$redacted"]["class"] == "event-content"
    manifest = reader.manifest()
    assert manifest["durability"] == "forensic"
    assert manifest["redactionPolicy"]["reviewedForExport"] is True
    assert "trace.metadata-only/0.1" in manifest["optionalFeatures"]
    assert len(manifest["segments"]) == 2


def _abandon(writer: TraceWriter) -> None:
    if writer._handle is not None:
        writer._handle.flush()
        writer._handle.close()
        writer._handle = None


def test_force_interruption_recovery_preserves_only_complete_records(tmp_path: Path) -> None:
    destination = tmp_path / "recovered.sova-trace"
    writer = TraceWriter(destination, segment_events=1)
    writer.append("run.started", {"value": 1})
    writer.append("run.completed", {"value": 2})
    writer.add_blob(b"recoverable blob")
    _abandon(writer)
    last_segment = max((writer._staging / "events").glob("*.jsonl"))
    with last_segment.open("ab") as handle:
        handle.write(b'{"incomplete":')

    digest = recover_trace(destination, signing_key=generate_ed25519_keypair())
    assert digest.startswith("sha256:")
    report = TraceReader(destination).verify(require_signature=True)
    assert report.completion == "recovered"
    assert report.event_count == 2
    manifest = TraceReader(destination).manifest()
    assert manifest["capturePolicy"]["droppedEventCount"] == 1
    assert manifest["extensions"]["x-sova-recovery"]["discardedTailBytes"] > 0
    assert writer._staging.exists()


def test_recovery_preconditions_and_empty_tail_are_explicit(tmp_path: Path) -> None:
    existing = tmp_path / "existing.sova-trace"
    existing.write_bytes(b"occupied")
    with pytest.raises(FormatError) as destination:
        recover_trace(existing)
    assert destination.value.issue.code == "SOVA-TRACE-RECOVERY-DESTINATION"

    missing = tmp_path / "missing.sova-trace"
    missing.with_name(".missing.sova-trace.partial").mkdir()
    with pytest.raises(FormatError) as session:
        recover_trace(missing)
    assert session.value.issue.code == "SOVA-TRACE-RECOVERY-SESSION"

    invalid = tmp_path / "invalid-session.sova-trace"
    invalid_staging = invalid.with_name(".invalid-session.sova-trace.partial")
    invalid_staging.mkdir()
    (invalid_staging / "session.json").write_bytes(b"[]")
    with pytest.raises(FormatError) as invalid_session:
        recover_trace(invalid)
    assert invalid_session.value.issue.code == "SOVA-TRACE-RECOVERY-SESSION"

    empty_tail = tmp_path / "empty-tail.sova-trace"
    writer = TraceWriter(empty_tail)
    _abandon(writer)
    (writer._staging / "events" / "000000.jsonl").write_bytes(b"partial")
    recover_trace(empty_tail)
    assert TraceReader(empty_tail).verify().event_count == 0


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        ("non-object", "SOVA-TRACE-RECOVERY-EVENT"),
        ("chain", "SOVA-TRACE-RECOVERY-CHAIN"),
        ("hash", "SOVA-TRACE-RECOVERY-HASH"),
    ],
)
def test_recovery_rejects_corrupt_events(
    tmp_path: Path,
    mutation: str,
    code: str,
) -> None:
    destination = tmp_path / f"{mutation}.sova-trace"
    writer = TraceWriter(destination)
    writer.append("run.started", {"value": "original"})
    _abandon(writer)
    segment = next((writer._staging / "events").glob("*.jsonl"))
    if mutation == "non-object":
        segment.write_bytes(b"[]\n")
    else:
        event = json.loads(segment.read_bytes())
        if mutation == "chain":
            event["sequence"] = 9
        else:
            event["payload"]["value"] = "changed"
        segment.write_bytes(canonical_json_bytes(event) + b"\n")
    with pytest.raises(FormatError) as error:
        recover_trace(destination)
    assert error.value.issue.code == code


def test_recovery_rejects_blob_name_substitution(tmp_path: Path) -> None:
    destination = tmp_path / "blob.sova-trace"
    writer = TraceWriter(destination)
    descriptor = writer.add_blob(b"blob")
    source = writer._staging / descriptor.path
    source.rename(source.with_name("0" * 64))
    _abandon(writer)
    with pytest.raises(FormatError) as error:
        recover_trace(destination)
    assert error.value.issue.code == "SOVA-TRACE-RECOVERY-BLOB"


def test_writer_context_manager_records_success_and_crash(tmp_path: Path) -> None:
    successful = tmp_path / "success.sova-trace"
    with TraceWriter(successful) as writer:
        writer.append("run.started", {})
    assert TraceReader(successful).verify().completion == "completed"

    crashed = tmp_path / "crash.sova-trace"
    with pytest.raises(RuntimeError, match="fixture"), TraceWriter(crashed) as writer:
        writer.append("run.started", {})
        raise RuntimeError("fixture")
    assert TraceReader(crashed).verify().completion == "crashed"

    already_closed = tmp_path / "already-closed.sova-trace"
    with TraceWriter(already_closed) as writer:
        writer.finalize()
    assert TraceReader(already_closed).verify().completion == "completed"


def test_package_level_event_substitution_is_detected(tmp_path: Path) -> None:
    original = tmp_path / "original.sova-trace"
    changed = tmp_path / "changed.sova-trace"
    _write_trace(original)
    with zipfile.ZipFile(original) as source, zipfile.ZipFile(changed, "w") as destination:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename.startswith("events/"):
                data = data.replace(b"observable response", b"substituted response")
            destination.writestr(item, data)
    with pytest.raises(FormatError) as error:
        TraceReader(changed).verify()
    assert error.value.issue.code == "SOVA-PACKAGE-INTEGRITY"


def test_reordering_is_detected_even_if_package_descriptor_is_recomputed(tmp_path: Path) -> None:
    original = tmp_path / "original.sova-trace"
    changed = tmp_path / "reordered.sova-trace"
    _write_trace(original, signed=False)
    reader = PackageReader(original)
    manifest = reader.manifest("sova.trace")
    objects = reader.verify()
    segment = next(item for item in objects if item.role == "event-segment")
    lines = reader.read_object(segment).splitlines()
    reversed_data = b"\n".join(reversed(lines)) + b"\n"

    manifest = json.loads(json.dumps(manifest))
    for index in ("segments", "objects"):
        for descriptor in manifest[index]:
            if descriptor["path"] == segment.path:
                descriptor["digest"] = sha256_digest(reversed_data)
                descriptor["size"] = len(reversed_data)
    manifest.pop("objects")
    manifest["integrity"]["manifestDigest"] = None
    manifest["integrity"]["signature"] = None
    writer = PackageWriter(manifest)
    for descriptor in objects:
        writer.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=(
                reversed_data
                if descriptor.path == segment.path
                else reader.read_object(descriptor)
            ),
        )
    complete = writer.finalized_manifest()
    complete["integrity"]["manifestDigest"] = unsigned_manifest_digest(complete)
    complete.pop("objects")
    final = PackageWriter(complete)
    for descriptor in objects:
        final.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=(
                reversed_data
                if descriptor.path == segment.path
                else reader.read_object(descriptor)
            ),
        )
    final.write(changed)
    with pytest.raises(FormatError) as error:
        TraceReader(changed).verify()
    assert error.value.issue.code == "SOVA-TRACE-SEQUENCE"


def test_signature_substitution_is_detected(tmp_path: Path) -> None:
    original = tmp_path / "signed.sova-trace"
    changed = tmp_path / "bad-signature.sova-trace"
    _write_trace(original)
    reader = PackageReader(original)
    manifest = reader.manifest("sova.trace")
    signature = manifest["integrity"]["signature"]["envelope"]["signatures"][0]["sig"]
    manifest["integrity"]["signature"]["envelope"]["signatures"][0]["sig"] = (
        ("A" if signature[0] != "A" else "B") + signature[1:]
    )
    manifest.pop("objects")
    writer = PackageWriter(manifest)
    for descriptor in reader.verify():
        writer.add_bytes(
            role=descriptor.role,
            path=descriptor.path,
            media_type=descriptor.mediaType,
            data=reader.read_object(descriptor),
        )
    writer.write(changed)
    with pytest.raises(FormatError) as error:
        TraceReader(changed).verify()
    assert error.value.issue.code == "SOVA-INTEGRITY-SIGNATURE-INVALID"


def test_event_segments_are_canonical_json_lines(tmp_path: Path) -> None:
    path = tmp_path / "canonical.sova-trace"
    _write_trace(path, signed=False)
    reader = PackageReader(path)
    for descriptor in reader.verify():
        if descriptor.role != "event-segment":
            continue
        for line in reader.read_object(descriptor).splitlines():
            assert canonical_json_bytes(json.loads(line)) == line


def test_verified_trace_can_be_embedded_in_outer_behavior_capsule(tmp_path: Path) -> None:
    trace_path = tmp_path / "run.sova-trace"
    _write_trace(trace_path, signed=True)
    capsule_path = tmp_path / "behavior.sova"
    manifest = capsule_manifest_template(
        title="Shareable synthetic behavior",
        summary="Scenario plus independently verifiable run evidence.",
        author="Test author",
    )
    build_capsule(
        capsule_path,
        manifest,
        scenario=scenario_template(title="Synthetic", purpose="Verify capsule layering"),
        traces=[trace_path],
    )
    descriptors = PackageReader(capsule_path).verify("sova.capsule")
    assert {item.role for item in descriptors} == {"scenario", "trace"}


def test_metadata_only_capture_external_links_and_indexes(tmp_path: Path) -> None:
    path = tmp_path / "metadata.sova-trace"
    writer = TraceWriter(
        path,
        content_capture="metadata-only",
        durability="lite",
        executor={
            "id": "fixture:executor",
            "name": "fixture",
            "version": "1",
            "capabilityDigest": "sha256:" + "7" * 64,
        },
    )
    event_id = writer.append(
        "model.response",
        {"text": "must not persist"},
        links=[
            {
                "relationship": "counterfactual-of",
                "scheme": "sova",
                "version": "0.1",
                "traceId": "external-trace",
                "spanId": None,
                "eventId": "external-event",
                "fidelity": "semantic",
                "trusted": False,
            }
        ],
    )
    writer.finalize()
    reader = TraceReader(path)
    event = reader.events()[0]
    assert event["payload"]["$redacted"]["class"] == "event-content"
    assert event["links"][0]["relationship"] == "counterfactual-of"
    assert reader.event(str(event_id)) == event
    assert reader.event("missing") is None
    assert reader.manifest()["contentCapture"] == "metadata-only"
    assert reader.manifest()["executor"]["id"] == "fixture:executor"


def test_recovery_preserves_only_valid_prefix_and_reports_tail(tmp_path: Path) -> None:
    destination = tmp_path / "recover.sova-trace"
    writer = TraceWriter(
        destination,
        durability="forensic",
        segment_events=1,
        segment_bytes=1024,
    )
    writer.append("run.started", {"fixture": True})
    writer.append("model.response", {"text": "observable"})
    writer.add_blob(b"recoverable")
    writer._close_segment()
    last_segment = max((writer._staging / "events").glob("*.jsonl"))
    with last_segment.open("ab") as handle:
        handle.write(b'{"incomplete":')
    digest = recover_trace(destination)
    assert digest.startswith("sha256:")
    report = TraceReader(destination).verify()
    assert report.completion == "recovered"
    assert report.event_count == 2
    manifest = TraceReader(destination).manifest()
    assert manifest["extensions"]["x-sova-recovery"]["discardedTailBytes"] > 0
    assert manifest["capturePolicy"]["droppedEventCount"] == 1
    assert writer._staging.is_dir()
    with pytest.raises(FormatError) as exists:
        recover_trace(destination)
    assert exists.value.issue.code == "SOVA-TRACE-RECOVERY-DESTINATION"


def test_verification_material_is_digest_bound_but_not_trusted(tmp_path: Path) -> None:
    path = tmp_path / "timestamped.sova-trace"
    key = generate_ed25519_keypair()
    writer = TraceWriter(
        path,
        signing_key=key,
        verification_material={
            "mediaType": "application/timestamp-reply",
            "kind": "rfc3161",
            "tokenDigest": "sha256:" + "8" * 64,
        },
    )
    writer.append("run.started", {})
    writer.finalize()
    report = TraceReader(path).verify(require_signature=True)
    assert report.verification_material_present
    assert not report.verification_material_verified


def test_new_trace_configuration_boundaries_fail_closed(tmp_path: Path) -> None:
    for arguments, code in (
        ({"segment_bytes": 1}, "SOVA-TRACE-SEGMENT-BYTES"),
        ({"content_capture": "unknown"}, "SOVA-TRACE-CONTENT-CAPTURE"),
        ({"durability": "unknown"}, "SOVA-TRACE-DURABILITY"),
        (
            {"verification_material": {"kind": "timestamp"}},
            "SOVA-INTEGRITY-VERIFICATION-MATERIAL",
        ),
    ):
        with pytest.raises(FormatError) as error:
            TraceWriter(tmp_path / f"{code}.sova-trace", **arguments)
        assert error.value.issue.code == code

    missing = tmp_path / "missing.sova-trace"
    with pytest.raises(FormatError) as recovery:
        recover_trace(missing)
    assert recovery.value.issue.code == "SOVA-TRACE-RECOVERY-SESSION"


def test_golden_trace_covers_every_pinned_event_family(tmp_path: Path) -> None:
    path = tmp_path / "all-event-families.sova-trace"
    writer = TraceWriter(path, capture_profile="forensic", durability="forensic")
    for prefix in EVENT_FAMILIES:
        writer.append(f"{prefix}fixture", {"synthetic": True, "family": prefix})
    writer.finalize()
    reader = TraceReader(path)
    assert {
        next(prefix for prefix in EVENT_FAMILIES if event["kind"].startswith(prefix))
        for event in reader.events()
    } == set(EVENT_FAMILIES)
    assert reader.manifest()["eventRegistry"]["digest"] == event_registry_digest()

    invalid = tmp_path / "invalid-family.sova-trace"
    invalid_writer = TraceWriter(invalid)
    with pytest.raises(FormatError) as error:
        invalid_writer.append("unknown.event", {})
    assert error.value.issue.code == "SOVA-TRACE-EVENT-FAMILY"
    invalid_writer.finalize(completion="failed")
