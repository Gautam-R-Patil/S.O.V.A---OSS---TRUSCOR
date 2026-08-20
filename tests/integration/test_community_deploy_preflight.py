# SPDX-License-Identifier: Apache-2.0
"""Installed Docker Compose acceptance for the shipped community preflight."""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import TYPE_CHECKING

import pytest

from deploy.community import preflight

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.integration
def test_installed_docker_accepts_preflighted_compose_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is not installed")
    available = subprocess.run(
        [docker, "compose", "version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if available.returncode != 0:
        pytest.skip("Docker Compose plugin is not available")

    operator = tmp_path / "operator"
    operator.mkdir()
    token = operator / "service.token"
    token.write_bytes(b"synthetic-test-token-material-123456")
    token.chmod(0o600)
    (operator / "methodology.md").write_text("synthetic methodology\n", encoding="utf-8")
    assert (
        preflight.main(
            [
                "check",
                "--sova-image",
                "example.invalid/sova@sha256:" + "1" * 64,
                "--caddy-image",
                "example.invalid/caddy@sha256:" + "2" * 64,
                "--trusted-evidence-key-id",
                "sha256:" + "3" * 64,
                "--domain",
                "community.example.org",
                "--operator-dir",
                str(operator),
                "--docker",
                docker,
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "pass"
    assert report["launched"] is False
    assert report["secretContentsReadIntoReport"] is False
