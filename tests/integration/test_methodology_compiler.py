# SPDX-License-Identifier: Apache-2.0
"""End-to-end deterministic methodology compilation and bounded replanning."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

from sova.cli import main
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.intake import (
    InputDescriptor,
    InputKind,
    ProfileTargetKind,
    SourceClass,
    TargetProfile,
    target_profile_template,
    validate_intake_report,
)
from sova.methodology import (
    MethodologyObservation,
    MethodologyObservationSet,
    MethodologyPhase,
    ObservationOutcome,
    compile_methodology,
    load_builtin_library,
    methodology_policy_template,
    replan_methodology,
    validate_methodology_plan,
)

if TYPE_CHECKING:
    from pathlib import Path

_DIGEST = "sha256:" + "1" * 64
_CLASS_CASES = (
    (ProfileTargetKind.WEB, InputKind.HTML, ("endpoint", "input", "trust-boundary"), "web"),
    (ProfileTargetKind.API, InputKind.OPENAPI, ("endpoint", "input", "protocol"), "api"),
    (
        ProfileTargetKind.NETWORK,
        InputKind.NETWORK_INVENTORY,
        ("endpoint", "protocol", "privilege", "trust-boundary"),
        "network-host-cloud",
    ),
    (
        ProfileTargetKind.SOURCE,
        InputKind.SOURCE_TREE,
        ("file", "dependency", "configuration"),
        "source-package-binary",
    ),
    (
        ProfileTargetKind.AI_MODEL,
        InputKind.AGENT_MANIFEST,
        ("model", "data-flow", "trust-boundary"),
        "ai-model",
    ),
    (
        ProfileTargetKind.AGENT,
        InputKind.AGENT_MANIFEST,
        ("agent", "tool", "identity", "trust-boundary"),
        "agentic",
    ),
)
_FOUNDATIONS = {
    "web": "sova.playbook.web.surface-inventory",
    "api": "sova.playbook.api.inventory",
    "network-host-cloud": "sova.playbook.network-host-cloud.service-inventory",
    "source-package-binary": "sova.playbook.source-package-binary.build-inventory",
    "ai-model": "sova.playbook.ai-model.system-inventory",
    "agentic": "sova.playbook.agentic.trust-inventory",
}


def _profile(target_kind: ProfileTargetKind, input_kind: InputKind) -> TargetProfile:
    return TargetProfile(
        identifier=f"owned.{target_kind.value}",
        version="0.1.0",
        title=f"Owned {target_kind.value} fixture",
        target_kinds=(target_kind,),
        authorization_scope="owned deterministic fixture only",
        inputs=(
            InputDescriptor(
                id="fixture-input",
                kind=input_kind,
                source_class=SourceClass.SUPPLIED,
                logical_locator="fixture-input.json",
                media_type="application/json",
                expected_digest=_DIGEST,
                required=True,
            ),
        ),
        provenance=({"source": "test-fixture", "evidenceClass": "declared"},),
    )


def _intake_report(
    profile: TargetProfile,
    input_kind: InputKind,
    surface_kinds: tuple[str, ...],
) -> dict[str, Any]:
    provenance = {
        "sourceId": "fixture-input",
        "pointer": "$/fixture",
        "sourceClass": "supplied",
        "evidenceClass": "declared",
        "projectionDigest": _DIGEST,
    }
    workflow_node = {
        "id": "intake:workflow-node:" + "2" * 32,
        "kind": "entry",
        "name": "owned entry",
        "attributes": {},
        "evidenceClass": "declared",
        "confidence": "1",
        "provenance": [provenance],
    }
    surface_nodes = [
        {
            "id": f"intake:attack-surface-node:{index:032x}",
            "kind": surface_kind,
            "name": f"owned {surface_kind} surface",
            "attributes": {},
            "evidenceClass": "declared",
            "confidence": "1",
            "provenance": [provenance],
        }
        for index, surface_kind in enumerate(surface_kinds, start=3)
    ]
    body: dict[str, Any] = {
        "artifactType": "sova.intake-report",
        "schemaVersion": "0.1.0",
        "id": "intake:report:" + "4" * 32,
        "profileDigest": profile.digest,
        "targetManifestDigest": None,
        "status": "complete",
        "inputs": [
            {
                "id": "fixture-input",
                "kind": input_kind.value,
                "sourceClass": "supplied",
                "digest": _DIGEST,
                "status": "parsed",
                "targetCodeExecuted": False,
            }
        ],
        "generation": {
            "state": "match",
            "fingerprints": [
                {
                    "inputId": "fixture-input",
                    "expectedDigest": _DIGEST,
                    "startDigest": _DIGEST,
                    "endDigest": _DIGEST,
                    "state": "match",
                    "reason": "test fixture unchanged",
                }
            ],
        },
        "workflowGraph": {"nodes": [workflow_node], "edges": []},
        "attackSurfaceGraph": {"nodes": surface_nodes, "edges": []},
        "coverage": {
            "items": [
                {
                    "subject": surface_node["id"],
                    "dimension": "attack-surface-node",
                    "state": "discovered",
                    "reason": "declared fixture",
                    "evidenceRefs": [_DIGEST],
                }
                for surface_node in surface_nodes
            ],
            "counts": {
                "declared": 0,
                "discovered": len(surface_nodes),
                "exercised": 0,
                "reproduced": 0,
                "blocked": 0,
                "unsupported": 0,
                "unknown": 0,
            },
            "partial": False,
            "allVulnerabilitiesFound": False,
            "safeOrClean": False,
        },
        "limitations": [],
        "errors": [],
        "claims": {
            "targetCodeExecuted": False,
            "activeObservationsIndependentlyAttested": False,
            "inferenceIsExecutionEvidence": False,
            "allWorkflowsUnderstood": False,
            "allAttackSurfacesEnumerated": False,
            "allVulnerabilitiesFound": False,
            "safeOrClean": False,
        },
    }
    body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    validate_intake_report(body)
    return body


@pytest.mark.parametrize(("target_kind", "input_kind", "surface_kinds", "domain"), _CLASS_CASES)
def test_every_initial_target_class_has_positive_negative_and_inconclusive_plan_paths(
    target_kind: ProfileTargetKind,
    input_kind: InputKind,
    surface_kinds: tuple[str, ...],
    domain: str,
) -> None:
    profile = _profile(target_kind, input_kind)
    report = _intake_report(profile, input_kind, surface_kinds)
    policy = methodology_policy_template(profile.digest)

    positive = compile_methodology(profile, policy, intake_report=report)
    domain_tasks = [task for task in positive["tasks"] if f".{domain}." in task["playbook"]["id"]]
    assert domain_tasks
    assert {task["phase"] for task in domain_tasks} == {phase.value for phase in MethodologyPhase}
    assert {task["status"] for task in domain_tasks} == {"planned"}
    assert positive["coverage"]["partial"] is False

    denied_policy = replace(policy, denied_playbooks=(_FOUNDATIONS[domain],))
    negative = compile_methodology(profile, denied_policy, intake_report=report)
    assert not [task for task in negative["tasks"] if f".{domain}." in task["playbook"]["id"]]
    assert {
        item["reason"] for item in negative["exclusions"] if f".{domain}." in item["playbookId"]
    } >= {"policy-denied", "dependency-excluded"}

    inconclusive = compile_methodology(profile, policy)
    inconclusive_tasks = [
        task for task in inconclusive["tasks"] if f".{domain}." in task["playbook"]["id"]
    ]
    assert any(
        task["phase"] == "discovery" and task["status"] == "planned" for task in inconclusive_tasks
    )
    assert any(
        task["phase"] != "discovery" and task["status"] == "blocked" for task in inconclusive_tasks
    )
    assert inconclusive["coverage"]["partial"] is True


def test_compilation_is_deterministic_dependency_aware_and_budget_bounded() -> None:
    profile = _profile(ProfileTargetKind.WEB, InputKind.HTML)
    report = _intake_report(profile, InputKind.HTML, ("endpoint", "input", "trust-boundary"))
    policy = methodology_policy_template(profile.digest)
    left = compile_methodology(profile, policy, intake_report=report)
    right = compile_methodology(profile, policy, intake_report=report)
    assert left == right
    assert left["contentDigest"] == right["contentDigest"]
    validate_methodology_plan(left, profile=profile, policy=policy, library=load_builtin_library())
    task_ids = {task["id"] for task in left["tasks"]}
    assert all(set(task["dependsOn"]).issubset(task_ids) for task in left["tasks"])
    assert left["budget"]["assigned"] <= left["budget"]["total"]
    assert all(value["assigned"] <= value["total"] for value in left["budget"]["byPhase"].values())
    assert all(task["oracleCalibrationStatus"] == "unvalidated-proposal" for task in left["tasks"])
    assert all(task["scores"]["priority"] in range(101) for task in left["tasks"])

    tiny_policy = methodology_policy_template(profile.digest, max_budget_units=6)
    exhausted = compile_methodology(profile, tiny_policy, intake_report=report)
    assert exhausted["tasks"] == []
    assert any(item["reason"] == "budget-exhausted" for item in exhausted["exclusions"])


def test_replanning_changes_only_status_and_scores() -> None:
    profile = _profile(ProfileTargetKind.WEB, InputKind.HTML)
    report = _intake_report(profile, InputKind.HTML, ("endpoint", "input", "trust-boundary"))
    policy = methodology_policy_template(profile.digest)
    plan = compile_methodology(profile, policy, intake_report=report)
    first = plan["tasks"][0]
    observations = MethodologyObservationSet(
        profile.digest,
        plan["contentDigest"],
        (_DIGEST,),
        (
            MethodologyObservation(
                first["playbook"]["id"],
                MethodologyPhase(first["phase"]),
                ObservationOutcome.OBSERVED,
                _DIGEST,
                profile.digest,
            ),
        ),
    )
    replanned = replan_methodology(
        profile,
        policy,
        plan,
        observations,
        intake_report=report,
    )
    changed = next(task for task in replanned["tasks"] if task["id"] == first["id"])
    assert changed["status"] == "completed"
    assert changed["scores"]["novelty"] == 20
    for key in (
        "playbook",
        "phase",
        "dependsOn",
        "preconditions",
        "allowedEffects",
        "toolCapabilities",
        "requiredEvidence",
        "budgetUnits",
        "executionCondition",
        "oracleCalibrationStatus",
    ):
        assert changed[key] == first[key]
    assert replanned["parentPlanDigest"] == plan["contentDigest"]
    assert replanned["observationSetDigest"] == observations.digest
    assert replanned["claims"]["authorityExpanded"] is False

    wrong_generation = replace(
        observations,
        observations=(replace(observations.observations[0], target_generation_digest=_DIGEST),),
    )
    with pytest.raises(FormatError, match="target generation"):
        replan_methodology(
            profile,
            policy,
            plan,
            wrong_generation,
            intake_report=report,
        )


def test_plan_tampering_cannot_expand_effects() -> None:
    profile = _profile(ProfileTargetKind.WEB, InputKind.HTML)
    report = _intake_report(profile, InputKind.HTML, ("endpoint", "input", "trust-boundary"))
    policy = methodology_policy_template(profile.digest)
    plan = compile_methodology(profile, policy, intake_report=report)
    plan["tasks"][0]["allowedEffects"].append("destructive")
    body = dict(plan)
    body.pop("contentDigest")
    plan["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    with pytest.raises(FormatError, match="effects exceed policy"):
        validate_methodology_plan(plan, profile=profile, policy=policy)


def test_methodology_cli_lifecycle(tmp_path: Path, capfd: pytest.CaptureFixture[str]) -> None:
    profile = target_profile_template(
        identifier="cli.web",
        title="CLI owned web fixture",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned fixture only",
    )
    profile_path = tmp_path / "profile.json"
    profile_path.write_bytes(canonical_json_bytes(profile.to_mapping()) + b"\n")
    library_path = tmp_path / "library.json"
    policy_path = tmp_path / "policy.json"
    plan_path = tmp_path / "plan.json"
    observations_path = tmp_path / "observations.json"
    replanned_path = tmp_path / "replanned.json"
    private_key = tmp_path / "private.key"
    public_key = tmp_path / "public.key"

    assert main(["methodology", "library-export", str(library_path)]) == 0
    capfd.readouterr()
    library = json.loads(library_path.read_text(encoding="utf-8"))
    playbook_path = tmp_path / "playbook.json"
    playbook_path.write_text(json.dumps(library["playbooks"][0]), encoding="utf-8")
    assert main(["methodology", "playbook-validate", str(playbook_path)]) == 0
    capfd.readouterr()
    assert main(["methodology", "policy-create", str(profile_path), str(policy_path)]) == 0
    capfd.readouterr()
    assert (
        main(["methodology", "compile", str(profile_path), str(policy_path), str(plan_path)]) == 0
    )
    capfd.readouterr()
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert (
        main(
            [
                "methodology",
                "observations-template",
                str(plan_path),
                str(observations_path),
                "--source-artifact-digest",
                plan["contentDigest"],
            ]
        )
        == 0
    )
    capfd.readouterr()
    assert (
        main(
            [
                "methodology",
                "replan",
                str(profile_path),
                str(policy_path),
                str(plan_path),
                str(observations_path),
                str(replanned_path),
            ]
        )
        == 0
    )
    capfd.readouterr()
    assert main(["methodology", "keygen", str(private_key), str(public_key)]) == 0
    capfd.readouterr()

    specification = tmp_path / "contribution.json"
    specification.write_text(
        json.dumps(
            {
                "contributor": {"name": "CLI reviewer", "identity": "local:cli"},
                "license": "Apache-2.0",
                "gates": {
                    "humanReviewed": True,
                    "publicDisclosureAllowed": True,
                    "authorizationRedacted": True,
                    "provenanceComplete": True,
                    "separateCorpusReuseConsent": False,
                },
            }
        ),
        encoding="utf-8",
    )
    staged = tmp_path / "staged"
    assert (
        main(
            [
                "methodology",
                "contribute",
                str(playbook_path),
                str(specification),
                str(private_key),
                str(public_key),
                str(staged),
                "--confirm",
            ]
        )
        == 0
    )
    result = json.loads(capfd.readouterr().out)
    assert result["uploadPerformed"] is False
    assert (staged / "registry-staging" / "contribution.json").is_file()
