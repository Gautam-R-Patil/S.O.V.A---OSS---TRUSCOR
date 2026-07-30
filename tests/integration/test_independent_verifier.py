# SPDX-License-Identifier: Apache-2.0
"""The dependency-free verifier is an independent offline process/code path."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from sova.capsule import build_capsule, capsule_manifest_template, scenario_template
from sova.formats import canonical_json_bytes, sha256_digest
from sova.trace import TraceWriter, generate_ed25519_keypair

ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "scripts" / "sova_independent_verify.py"
NODE_VERIFIER = ROOT / "scripts" / "sova_independent_verify.mjs"


def _run(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(path), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _run_node(path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for the cross-language verifier lane")
    return subprocess.run(
        [node, str(NODE_VERIFIER), str(path), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _repackage_trace(
    source: Path,
    destination: Path,
    *,
    redactions_as_object: bool = False,
    remove_segment_newline: bool = False,
) -> None:
    with zipfile.ZipFile(source) as archive:
        members = {item.filename: archive.read(item.filename) for item in archive.infolist()}
    manifest = json.loads(members["manifest.json"])
    descriptor = next(item for item in manifest["objects"] if item["role"] == "event-segment")
    segment = members[descriptor["path"]]
    lines = segment.splitlines()
    event = json.loads(lines[0])
    if redactions_as_object:
        event["redactions"] = {}
        event["eventHash"] = sha256_digest(
            canonical_json_bytes({key: value for key, value in event.items() if key != "eventHash"})
        )
        manifest["chainRoot"] = event["eventHash"]
        lines[0] = canonical_json_bytes(event)
    segment = b"\n".join(lines) + (b"" if remove_segment_newline else b"\n")
    members[descriptor["path"]] = segment
    descriptor["digest"] = sha256_digest(segment)
    descriptor["size"] = len(segment)
    manifest["integrity"]["manifestDigest"] = None
    manifest["integrity"]["signature"] = None
    manifest["integrity"]["manifestDigest"] = sha256_digest(canonical_json_bytes(manifest))
    members["manifest.json"] = canonical_json_bytes(manifest)
    with zipfile.ZipFile(destination, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)


@pytest.mark.integration
def test_independent_process_validates_capsule_and_redacted_trace(tmp_path: Path) -> None:
    source = VERIFIER.read_text(encoding="utf-8")
    assert "from sova" not in source
    capsule = tmp_path / "fixture.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(
            title="Independent fixture",
            summary="Independent capsule verification.",
            author="Synthetic test author",
        ),
        scenario=scenario_template(title="Fixture", purpose="Independent validation"),
    )
    capsule_result = _run(capsule)
    assert capsule_result.returncode == 0, capsule_result.stderr
    assert json.loads(capsule_result.stdout)["artifactType"] == "sova.capsule"

    trace = tmp_path / "fixture.sova-trace"
    writer = TraceWriter(trace)
    writer.append("prompt.sent", {"api_key": "synthetic-secret-value"})
    writer.finalize()
    trace_result = _run(trace)
    assert trace_result.returncode == 0, trace_result.stderr
    report = json.loads(trace_result.stdout)
    assert report["artifactType"] == "sova.trace"
    assert report["eventCount"] == 1
    assert report["signatureChecked"] is False


@pytest.mark.integration
def test_independent_process_fails_visibly_on_substitution(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.sova"
    invalid.write_bytes(b"not a package")
    result = _run(invalid)
    assert result.returncode == 2
    assert "INDEPENDENT-VERIFY-FAILED" in result.stderr


@pytest.mark.integration
def test_independent_process_optionally_verifies_dsse_and_required_key(
    tmp_path: Path,
) -> None:
    key = generate_ed25519_keypair()
    trace = tmp_path / "signed.sova-trace"
    writer = TraceWriter(
        trace,
        signing_key=key,
        verification_material={"timestamp": {"kind": "synthetic-unverified"}},
    )
    writer.append("run.started", {"fixture": "signed"})
    writer.finalize()

    included_key = _run(trace, "--require-signature")
    assert included_key.returncode == 0, included_key.stderr
    included_report = json.loads(included_key.stdout)
    assert included_report["signatureChecked"] is True
    assert included_report["trustPolicy"] == "included-key-integrity-only"
    assert included_report["verificationMaterialPresent"] is True
    assert included_report["verificationMaterialVerified"] is False

    required_key = _run(trace, "--required-key-id", key.key_id)
    assert required_key.returncode == 0, required_key.stderr
    required_report = json.loads(required_key.stdout)
    assert required_report["trustPolicy"] == "required-key"
    assert required_report["signatureKeyId"] == key.key_id

    wrong_key = _run(trace, "--required-key-id", "sha256:" + ("0" * 64))
    assert wrong_key.returncode == 2
    assert "required key" in wrong_key.stderr

    unsigned = tmp_path / "unsigned.sova-trace"
    unsigned_writer = TraceWriter(unsigned)
    unsigned_writer.append("run.started", {})
    unsigned_writer.finalize()
    missing = _run(unsigned, "--require-signature")
    assert missing.returncode == 2
    assert "required but absent" in missing.stderr

    malformed = tmp_path / "malformed-signature.sova-trace"
    with zipfile.ZipFile(trace) as source, zipfile.ZipFile(malformed, "w") as destination:
        for item in source.infolist():
            data = source.read(item.filename)
            if item.filename == "manifest.json":
                manifest = json.loads(data)
                manifest["integrity"]["signature"]["publicKey"] = []
                data = canonical_json_bytes(manifest)
            destination.writestr(item, data)
    malformed_result = _run(malformed, "--require-signature")
    assert malformed_result.returncode == 2
    assert "malformed DSSE" in malformed_result.stderr
    assert "Traceback" not in malformed_result.stderr


@pytest.mark.integration
def test_node_process_independently_matches_python_integrity_and_dsse(
    tmp_path: Path,
) -> None:
    source = NODE_VERIFIER.read_text(encoding="utf-8")
    assert "from sova" not in source
    assert "import sova" not in source

    capsule = tmp_path / "cross-language.sova"
    build_capsule(
        capsule,
        capsule_manifest_template(
            title="Cross-language capsule",
            summary="Python and Node verify the same canonical capsule.",
            author="Synthetic test author",
        ),
        scenario=scenario_template(
            title="Cross-language fixture",
            purpose="Independent verifier parity",
        ),
    )
    python_capsule = _run(capsule)
    node_capsule = _run_node(capsule)
    assert python_capsule.returncode == node_capsule.returncode == 0
    python_capsule_report = json.loads(python_capsule.stdout)
    node_capsule_report = json.loads(node_capsule.stdout)
    assert node_capsule_report["contentDigest"] == python_capsule_report["contentDigest"]
    assert node_capsule_report["packageDigest"] == python_capsule_report["packageDigest"]

    key = generate_ed25519_keypair()
    trace = tmp_path / "cross-language.sova-trace"
    writer = TraceWriter(
        trace,
        signing_key=key,
        verification_material={"timestamp": {"kind": "synthetic-unverified"}},
    )
    writer.append("run.started", {"fixture": "node-cross-language"})
    writer.append("run.completed", {"status": "completed"})
    writer.finalize()

    python_result = _run(trace, "--required-key-id", key.key_id)
    node_result = _run_node(trace, "--required-key-id", key.key_id)
    assert python_result.returncode == node_result.returncode == 0
    python_report = json.loads(python_result.stdout)
    node_report = json.loads(node_result.stdout)
    assert node_report["verifier"] == "sova-independent-node/0.1"
    assert node_report["contentDigest"] == python_report["contentDigest"]
    assert node_report["packageDigest"] == python_report["packageDigest"]
    assert node_report["eventCount"] == python_report["eventCount"] == 2
    assert node_report["signatureKeyId"] == python_report["signatureKeyId"]
    assert node_report["trustPolicy"] == python_report["trustPolicy"] == "required-key"
    assert node_report["verificationMaterialVerified"] is False

    wrong = _run_node(trace, "--required-key-id", "sha256:" + ("0" * 64))
    assert wrong.returncode == 2
    assert "required key" in wrong.stderr

    invalid = tmp_path / "invalid-node.sova-trace"
    invalid.write_bytes(b"not a package")
    rejected = _run_node(invalid)
    assert rejected.returncode == 2
    assert "INDEPENDENT-NODE-VERIFY-FAILED" in rejected.stderr

    mismatched_name = tmp_path / "local-central-name-mismatch.sova"
    raw = bytearray(capsule.read_bytes())
    local_header = raw.find(b"PK\x03\x04")
    assert local_header >= 0
    local_name_length = int.from_bytes(raw[local_header + 26 : local_header + 28], "little")
    assert local_name_length > 0
    local_name_start = local_header + 30
    raw[local_name_start] = ord("x") if raw[local_name_start] != ord("x") else ord("y")
    mismatched_name.write_bytes(raw)
    mismatched = _run_node(mismatched_name)
    assert mismatched.returncode == 2
    assert "local and central filenames differ" in mismatched.stderr


@pytest.mark.integration
@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        ("redactions", "redactions are not an array"),
        ("newline", "event segment lacks final newline"),
    ],
)
def test_independent_verifiers_reject_rehashed_structural_mutations(
    tmp_path: Path,
    mutation: str,
    expected: str,
) -> None:
    trace = tmp_path / "source.sova-trace"
    writer = TraceWriter(trace)
    writer.append("run.started", {"fixture": "structural-mutation"})
    writer.finalize()
    mutated = tmp_path / f"{mutation}.sova-trace"
    _repackage_trace(
        trace,
        mutated,
        redactions_as_object=mutation == "redactions",
        remove_segment_newline=mutation == "newline",
    )
    python_result = _run(mutated)
    node_result = _run_node(mutated)
    assert python_result.returncode == node_result.returncode == 2
    assert expected in python_result.stderr
    assert expected in node_result.stderr
