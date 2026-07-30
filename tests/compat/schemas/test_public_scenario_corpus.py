# SPDX-License-Identifier: Apache-2.0
"""Independent JSON Schema validation of the public scenario corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from sova.capsule import build_capsule, capsule_manifest_template
from sova.formats import PackageReader, strict_json_loads, validate_document

ROOT = Path(__file__).resolve().parents[3]
SCENARIOS = sorted((ROOT / "examples" / "scenarios").glob("*.json"))


@pytest.mark.compat
@pytest.mark.parametrize("path", SCENARIOS, ids=lambda path: path.stem)
def test_each_example_passes_reference_and_independent_validator(
    path: Path,
    tmp_path: Path,
) -> None:
    raw = path.read_bytes()
    document = strict_json_loads(raw)
    validate_document(document, "sova.scenario")

    schema = json.loads(
        (ROOT / "src" / "sova" / "schemas" / "scenario-0.1.0.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema).validate(json.loads(raw))

    manifest = capsule_manifest_template(
        title=document["title"],
        summary=document["purpose"],
        author="SOVA OSS synthetic fixture authors",
    )
    capsule = tmp_path / f"{path.stem}.sova"
    build_capsule(capsule, manifest, scenario=document)
    assert any(item.role == "scenario" for item in PackageReader(capsule).verify())


def test_public_corpus_has_multiple_distinct_behavior_domains() -> None:
    assert len(SCENARIOS) >= 4
    actions = {
        step["action"]
        for path in SCENARIOS
        for step in strict_json_loads(path.read_bytes())["procedure"]["steps"]
    }
    assert {"model.prompt", "agent.request-tool", "model.prompt-with-context"} <= actions
