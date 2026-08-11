# SPDX-License-Identifier: Apache-2.0
"""Opt-in installed-Chrome acceptance across representative owned websites."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sova.live import (
    OwnedWebMatrixFixture,
    WebApplicationClass,
    build_web_matrix_capsule,
    owned_web_target,
    run_live_browser_assessment,
)
from sova.replay import VerificationState, verify_artifact
from sova.trace import TraceReader


@pytest.mark.integration
@pytest.mark.parametrize("application_class", tuple(WebApplicationClass))
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_BROWSER") != "1",
    reason="set SOVA_RUN_REAL_BROWSER=1 for the optional installed-browser lane",
)
def test_optional_real_browser_matrix(
    tmp_path: Path,
    application_class: WebApplicationClass,
) -> None:
    package_runner = Path(os.environ.get("SOVA_NPX_PATH", r"C:\Program Files\nodejs\npx.cmd"))
    browser = Path(
        os.environ.get(
            "SOVA_BROWSER_PATH",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
    )
    if not package_runner.is_file() or not browser.is_file():
        pytest.skip("installed npx and Chrome paths are unavailable")
    with OwnedWebMatrixFixture() as fixture:
        capsule = tmp_path / f"{application_class.value}.sova"
        build_web_matrix_capsule(application_class, fixture.url(application_class), capsule)
        artifacts = run_live_browser_assessment(
            owned_web_target(fixture.origin),
            capsule,
            tmp_path / "run",
            package_runner=package_runner,
            browser_executable=browser,
            approval_prompt=lambda challenge, _intents: challenge.exact_phrase,
        )

    assert artifacts.status == "pass"
    assert TraceReader(artifacts.trace).verify(require_signature=True).signature_valid
    assert TraceReader(artifacts.reproduction_trace).verify(require_signature=True).signature_valid
    assert verify_artifact(artifacts.evidence_capsule).state in {
        VerificationState.VERIFIED,
        VerificationState.PARTIAL,
    }
