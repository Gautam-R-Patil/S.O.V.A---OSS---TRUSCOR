# SPDX-License-Identifier: Apache-2.0
"""P6 local acceptance must remain deterministic and refuse external launch claims."""

from __future__ import annotations

from scripts.validate_p6_launch import build_acceptance_receipt


def test_p6_acceptance_receipt_is_stable_and_fail_closed() -> None:
    first = build_acceptance_receipt()
    second = build_acceptance_receipt()
    assert first == second
    assert first["localImplementationAcceptancePassed"] is True
    assert first["adapterCount"] == 5
    assert first["targetClassCount"] == 8
    assert first["predeclaredRunCount"] == 32
    assert first["p6ExitGatePassed"] is False
    assert first["claims"]["tagOrPublishAllowed"] is False
    assert first["claims"]["externalReviewsObtained"] is False
    assert first["claims"]["allVulnerabilitiesFound"] is False
