# SPDX-License-Identifier: Apache-2.0
"""Every promised audience profile has an executable, inspectable capsule."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from sova.capsule import (
    DomainProfile,
    build_capsule,
    capsule_manifest_template,
    render_capsule,
)
from sova.formats import PackageReader
from sova.models import ScriptedModel, ScriptedTurn
from sova.reproduction import reproduce_with_scripted_model
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path


def _scenario(index: int, profile: DomainProfile) -> dict[str, Any]:
    return {
        "artifactType": "sova.scenario",
        "schemaVersion": "0.1.0",
        "id": f"sova:scenario:019fb500-0000-7000-8000-{index:012d}",
        "version": "0.1.0",
        "title": f"{profile.value} observable fixture",
        "purpose": f"Exercise the shared capsule core for {profile.value}.",
        "parameters": {},
        "preconditions": [{"kind": "fixture", "owned": True}],
        "sequences": [],
        "procedure": {
            "steps": [
                {
                    "id": "observe",
                    "action": "model.prompt",
                    "inputs": {"text": f"Return the {profile.value} fixture label."},
                    "onFailure": "inconclusive",
                    "requires": ["model.prompt/0.1"],
                }
            ]
        },
        "triggers": [],
        "mutations": [],
        "expectedEffects": [{"kind": "response-label", "value": "OBSERVED"}],
        "oracles": [{"kind": "exact-field", "path": "$.label", "equals": "OBSERVED"}],
        "evidenceRequirements": [
            "prompt.sent",
            "model.response",
            "oracle.completed",
        ],
        "safety": {
            "budgets": {"maxSteps": 1},
            "forbiddenEffects": ["network.egress", "host.write"],
            "stopConditions": [{"kind": "unexpected-tool-call"}],
        },
        "cleanup": [],
        "limitations": ["Synthetic profile-conformance fixture; not a domain validity claim."],
        "extensions": {},
    }


@pytest.mark.integration
@pytest.mark.parametrize("profile", list(DomainProfile))
def test_each_domain_profile_is_executable_and_inspectable(
    tmp_path: Path,
    profile: DomainProfile,
) -> None:
    index = list(DomainProfile).index(profile) + 1
    scenario = _scenario(index, profile)
    manifest = capsule_manifest_template(
        title=scenario["title"],
        summary=scenario["purpose"],
        author="SOVA OSS synthetic fixture authors",
        domain_profile=profile,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    source = tmp_path / f"{profile.value}.sova"
    build_capsule(source, manifest, scenario=scenario)
    model = ScriptedModel(
        [
            ScriptedTurn(
                scenario["procedure"]["steps"][0]["inputs"]["text"],
                "OBSERVED",
                {"label": "OBSERVED"},
            )
        ]
    )
    trace = tmp_path / f"{profile.value}.sova-trace"
    result = reproduce_with_scripted_model(
        source,
        trace,
        model=model,
        authorization={
            "decision": "allowed",
            "scopeDigest": "sha256:" + f"{index:x}".rjust(64, "0"),
            "decidedBy": "synthetic-test",
        },
    )

    assert result.completion == "completed"
    oracle = next(TraceReader(trace).query(kind_prefix="oracle.completed"))
    assert oracle["payload"]["status"] == "pass"
    evidence = tmp_path / f"{profile.value}-evidence.sova"
    build_capsule(evidence, manifest, scenario=scenario, traces=[trace])
    assert PackageReader(evidence).verify("sova.capsule")
    rendered = render_capsule(evidence)
    assert f"Profile: `{profile.value}`" in rendered
    assert "Objects: 2" in rendered
