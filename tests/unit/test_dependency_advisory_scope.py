# SPDX-License-Identifier: Apache-2.0
"""Regression guards for previously relevant dependency-advisory surfaces."""

from __future__ import annotations

from pathlib import Path


def test_pkcs7_decryption_advisory_surface_is_absent_from_shipped_source() -> None:
    """Keep unused PKCS#7 decryption out after retiring the former exception."""
    source_root = Path(__file__).resolve().parents[2] / "src" / "sova"
    forbidden = (
        "cryptography.hazmat.primitives.serialization.pkcs7",
        "pkcs7_decrypt_der",
        "pkcs7_decrypt_pem",
        "pkcs7_decrypt_smime",
    )
    violations: list[str] = []
    for path in sorted(source_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        violations.extend(
            f"{path.relative_to(source_root)}: {token}" for token in forbidden if token in text
        )
    assert violations == []
