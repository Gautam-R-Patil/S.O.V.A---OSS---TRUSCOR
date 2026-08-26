# SPDX-License-Identifier: Apache-2.0
"""Fail-closed edge coverage for methodology contracts and parsers."""

from __future__ import annotations

import base64
import copy
from dataclasses import replace
from typing import TYPE_CHECKING, Any

import pytest

import sova.methodology.contribution as contribution_module
from sova.formats import canonical_json_bytes, sha256_digest
from sova.formats.errors import FormatError
from sova.intake import (
    InputKind,
    ProfileTargetKind,
    TargetProfile,
    read_intake_report,
    run_universal_intake,
    target_profile_template,
)
from sova.methodology import (
    EffectClass,
    MethodologyLibrary,
    MethodologyObservation,
    MethodologyObservationSet,
    MethodologyPhase,
    ObservationOutcome,
    SchedulerKind,
    load_builtin_library,
    methodology_policy_from_mapping,
    methodology_policy_template,
    observation_set_from_mapping,
    playbook_from_mapping,
)
from sova.methodology.compiler import (
    _applicable_playbooks,
    _assert_contracts_unchanged,
    _intake_context,
    _schedule_playbooks,
    _scheduler_key,
    _scores,
    _validate_bound_task_contracts,
    _validate_phase_matrix,
    _validate_task_graph,
    compile_methodology,
    replan_methodology,
    validate_methodology_plan,
)
from sova.methodology.contracts import TargetPredicate
from sova.methodology.contribution import (
    _decode_base64,
    build_playbook_submission,
    prepare_playbook_contribution,
    verify_playbook_submission,
)
from sova.methodology.library import read_playbook
from sova.trace import generate_ed25519_keypair

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


_DIGEST = "sha256:" + "a" * 64


def _profile() -> TargetProfile:
    return target_profile_template(
        identifier="edge.web",
        title="Owned edge target",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned fixture only",
    )


def _redigest(plan: dict[str, Any]) -> dict[str, Any]:
    body = copy.deepcopy(plan)
    body.pop("contentDigest", None)
    body["contentDigest"] = sha256_digest(canonical_json_bytes(body))
    return body


def _change_leaf_task_id(plan: dict[str, Any]) -> None:
    depended_on = {dependency for task in plan["tasks"] for dependency in task["dependsOn"]}
    leaf = next(task for task in plan["tasks"] if task["id"] not in depended_on)
    leaf["id"] = "methodology:task:sha256:" + "0" * 64


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda item: replace(item, identifier="bad id"), "identifier"),
        (lambda item: replace(item, version="latest"), "version"),
        (lambda item: replace(item, depends_on=(item.identifier,)), "itself"),
        (
            lambda item: replace(
                item,
                target_predicate=replace(
                    item.target_predicate,
                    required_input_kinds=(InputKind.OPENAPI,),
                ),
            ),
            "discovery inputs",
        ),
        (lambda item: replace(item, severity=0), "risk"),
        (lambda item: replace(item, likelihood=6), "risk"),
        (lambda item: replace(item, base_cost=0), "cost"),
        (lambda item: replace(item, tags=("bad tag",)), "identifier"),
        (lambda item: replace(item, allowed_effects=()), "unique"),
    ],
)
def test_playbook_contract_rejects_invalid_mutations(
    mutation: Callable[[Any], Any],
    match: str,
) -> None:
    with pytest.raises(FormatError, match=match):
        mutation(load_builtin_library().playbooks[0])


def test_nested_contracts_reject_unsafe_values() -> None:
    playbook = load_builtin_library().playbooks[0]
    with pytest.raises(FormatError, match="unique"):
        TargetPredicate(())
    with pytest.raises(FormatError, match="identifier"):
        TargetPredicate((ProfileTargetKind.WEB,), ("bad surface",))
    with pytest.raises(FormatError, match="minimum"):
        replace(playbook.required_evidence[0], minimum=0)
    with pytest.raises(FormatError, match="unvalidated"):
        replace(playbook.oracle_proposal, calibration_status="validated")
    with pytest.raises(FormatError, match="relationship"):
        replace(playbook.mappings[0], relationship="same-as")
    with pytest.raises(FormatError, match="HTTPS"):
        replace(playbook.mappings[0], url="http://example.invalid")
    with pytest.raises(FormatError, match="origin"):
        replace(playbook.provenance, origin="copied")
    with pytest.raises(FormatError, match="third-party"):
        replace(playbook.provenance, third_party_prose_copied=True)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda policy: replace(policy, target_profile_digest="bad"), "SHA-256"),
        (lambda policy: replace(policy, max_budget_units=5), "total budget"),
        (
            lambda policy: replace(
                policy,
                phase_budgets={MethodologyPhase.DISCOVERY: 1},
            ),
            "every phase",
        ),
        (
            lambda policy: replace(
                policy,
                phase_budgets=dict.fromkeys(MethodologyPhase, -1),
            ),
            "phase budget",
        ),
        (
            lambda policy: replace(
                policy,
                allowed_effects=(EffectClass.OBSERVE, EffectClass.OBSERVE),
            ),
            "unique",
        ),
        (
            lambda policy: replace(
                policy,
                denied_playbooks=("sova.playbook.web.x",),
                required_playbooks=("sova.playbook.web.x",),
            ),
            "required and denied",
        ),
        (lambda policy: replace(policy, human_approval_required=False), "human approval"),
    ],
)
def test_policy_contract_rejects_invalid_mutations(
    mutation: Callable[[Any], Any],
    match: str,
) -> None:
    with pytest.raises(FormatError, match=match):
        mutation(methodology_policy_template(_profile().digest))


def test_policy_and_observation_parsers_reject_malformed_documents() -> None:
    profile = _profile()
    policy = methodology_policy_template(profile.digest)
    policy_document = policy.to_mapping()
    malformed_policies = [
        ({**policy_document, "extra": True}, "fields"),
        ({**policy_document, "schemaVersion": "9.9.9"}, "version"),
        ({**policy_document, "scheduler": "random"}, "unsupported"),
        ({**policy_document, "maxBudgetUnits": True}, "integer"),
        ({**policy_document, "humanApprovalRequired": 1}, "boolean"),
        ({**policy_document, "phaseBudgets": []}, "object"),
        ({**policy_document, "allowedEffects": [1]}, "string array"),
    ]
    for document, match in malformed_policies:
        with pytest.raises(FormatError, match=match):
            methodology_policy_from_mapping(document)

    observations = MethodologyObservationSet(
        profile.digest,
        _DIGEST,
        (_DIGEST,),
        (),
    ).to_mapping()
    malformed_observations = [
        ({**observations, "extra": True}, "fields"),
        ({**observations, "claims": {}}, "unsafe"),
        ({**observations, "observations": [1]}, "object array"),
    ]
    for document, match in malformed_observations:
        with pytest.raises(FormatError, match=match):
            observation_set_from_mapping(document)
    with pytest.raises(FormatError, match="playbook ID"):
        MethodologyObservation(
            "bad", MethodologyPhase.DISCOVERY, ObservationOutcome.OBSERVED, _DIGEST, _DIGEST
        )
    duplicate = MethodologyObservation(
        load_builtin_library().playbooks[0].identifier,
        MethodologyPhase.DISCOVERY,
        ObservationOutcome.BLOCKED,
        _DIGEST,
        _DIGEST,
    )
    with pytest.raises(FormatError, match="unique"):
        MethodologyObservationSet(profile.digest, _DIGEST, (_DIGEST,), (duplicate, duplicate))


def test_playbook_parser_helpers_and_file_root_fail_closed(tmp_path: Path) -> None:
    document = load_builtin_library().playbooks[0].to_mapping()
    malformed: list[tuple[dict[str, Any], str]] = []
    malformed.append(({**document, "extra": True}, "fields"))
    malformed.append(({**document, "schemaVersion": "9.9.9"}, "version"))
    for key, value, match in (
        ("title", 1, "string"),
        ("risk", [], "object"),
        ("dependsOn", [1], "string array"),
        ("prerequisites", [1], "object array"),
    ):
        malformed.append(({**document, key: value}, match))
    for item, match in malformed:
        with pytest.raises(FormatError, match=match):
            playbook_from_mapping(item)
    bad_bool = copy.deepcopy(document)
    bad_bool["prerequisites"][0]["required"] = "yes"
    with pytest.raises(FormatError, match="boolean"):
        playbook_from_mapping(bad_bool)
    bad_integer = copy.deepcopy(document)
    bad_integer["risk"]["severity"] = True
    with pytest.raises(FormatError, match="integer"):
        playbook_from_mapping(bad_integer)

    root = tmp_path / "root.json"
    root.write_text("[]", encoding="utf-8")
    with pytest.raises(FormatError, match="root"):
        read_playbook(root)


def test_library_rejects_empty_and_duplicate_identifiers() -> None:
    library = load_builtin_library()
    with pytest.raises(FormatError, match="non-empty"):
        MethodologyLibrary("empty", "0.1.0", "2026-08-26", library.sources, ())
    with pytest.raises(FormatError, match="unique"):
        MethodologyLibrary(
            "duplicate",
            "0.1.0",
            "2026-08-26",
            library.sources,
            (library.playbooks[0], library.playbooks[0]),
        )


def test_plan_validator_rejects_changed_bindings_budgets_and_graph() -> None:
    profile = _profile()
    policy = methodology_policy_template(profile.digest)
    library = load_builtin_library()
    plan = compile_methodology(profile, policy, library=library)

    mutations: list[tuple[Any, str]] = [
        (lambda item: item.update(targetProfileDigest=_DIGEST), "target profile"),
        (lambda item: item.update(policyDigest=_DIGEST), "policy"),
        (lambda item: item.update(libraryDigest=_DIGEST), "library"),
        (lambda item: item.update(scheduler="identifier-baseline"), "scheduler"),
        (lambda item: item["budget"].update(total=1), "budgets"),
        (lambda item: item["budget"].update(assigned=0), "assigned task"),
        (lambda item: item["budget"].update(remaining=0), "total budget"),
        (
            lambda item: item["budget"]["byPhase"]["discovery"].update(assigned=0),
            "phase budget",
        ),
        (lambda item: item["tasks"].append(copy.deepcopy(item["tasks"][0])), "non-unique"),
        (
            lambda item: item["tasks"][0]["dependsOn"].append(
                "methodology:task:sha256:" + "f" * 64
            ),
            "dangling",
        ),
        (lambda item: item["tasks"][0].update(toolCapabilities=["changed"]), "tools"),
        (lambda item: item["tasks"][0].update(budgetUnits=999), "cost"),
        (_change_leaf_task_id, "task ID"),
    ]
    for mutate, match in mutations:
        changed = copy.deepcopy(plan)
        mutate(changed)
        changed = _redigest(changed)
        with pytest.raises(FormatError, match=match):
            validate_methodology_plan(changed, profile=profile, policy=policy, library=library)


def test_submission_key_payload_and_destination_edges(tmp_path: Path) -> None:
    playbook = load_builtin_library().playbooks[0]
    keys = generate_ed25519_keypair()
    with pytest.raises(FormatError, match="raw Ed25519"):
        build_playbook_submission(playbook, b"short", keys.public_key)
    submission = build_playbook_submission(playbook, keys.private_key, keys.public_key)

    bad_key = copy.deepcopy(submission)
    bad_key["publicKey"]["raw"] = base64.b64encode(b"short").decode()
    with pytest.raises(FormatError, match="public key"):
        verify_playbook_submission(bad_key)
    for raw in (1, "not base64!"):
        with pytest.raises(FormatError, match="public key"):
            _decode_base64(raw)

    spec = {
        "contributor": {"name": "Reviewer", "identity": "local:reviewer"},
        "license": "Apache-2.0",
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": False,
        },
    }
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FormatError, match="must not exist"):
        prepare_playbook_contribution(
            playbook, spec, keys.private_key, keys.public_key, existing, confirmed=True
        )
    bad_spec = {**spec, "extra": True}
    with pytest.raises(FormatError, match="fields"):
        prepare_playbook_contribution(
            playbook,
            bad_spec,
            keys.private_key,
            keys.public_key,
            tmp_path / "bad-spec",
            confirmed=True,
        )
    partial_destination = tmp_path / "partial"
    partial_destination.with_name(".partial.partial").mkdir()
    with pytest.raises(FormatError, match="partial"):
        prepare_playbook_contribution(
            playbook,
            spec,
            keys.private_key,
            keys.public_key,
            partial_destination,
            confirmed=True,
        )


def test_replanning_rejects_every_untrusted_observation_binding() -> None:
    profile = _profile()
    policy = methodology_policy_template(profile.digest)
    plan = compile_methodology(profile, policy)
    planned = plan["tasks"][0]["playbook"]["id"]
    observation = MethodologyObservation(
        planned,
        MethodologyPhase.DISCOVERY,
        ObservationOutcome.INCONCLUSIVE,
        _DIGEST,
        profile.digest,
    )
    cases = [
        (
            MethodologyObservationSet(_DIGEST, plan["contentDigest"], (_DIGEST,), (observation,)),
            "target profile",
        ),
        (
            MethodologyObservationSet(profile.digest, _DIGEST, (_DIGEST,), (observation,)),
            "previous plan",
        ),
        (
            MethodologyObservationSet(
                profile.digest,
                plan["contentDigest"],
                (_DIGEST,),
                (
                    replace(
                        observation,
                        playbook_id="sova.playbook.api.surface-inventory",
                    ),
                ),
            ),
            "unplanned",
        ),
    ]
    for observations, match in cases:
        with pytest.raises(FormatError, match=match):
            replan_methodology(profile, policy, plan, observations)


def test_compiler_internal_fail_closed_graph_scheduler_and_exclusion_edges() -> None:
    profile = _profile()
    library = load_builtin_library()
    playbook = next(
        item
        for item in library.playbooks
        if ProfileTargetKind.WEB in item.target_predicate.any_target_kinds
    )
    context = _intake_context(profile, None)
    observation = MethodologyObservation(
        playbook.identifier,
        MethodologyPhase.DISCOVERY,
        ObservationOutcome.BLOCKED,
        _DIGEST,
        profile.digest,
    )
    assert _scores(playbook, context, observation)["evidenceGap"] == 100
    for scheduler in (SchedulerKind.IDENTIFIER_BASELINE, SchedulerKind.RISK_FIRST_BASELINE):
        policy = methodology_policy_template(profile.digest, scheduler=scheduler)
        assert _scheduler_key(playbook, _scores(playbook, context, None), policy)

    no_passive = methodology_policy_template(
        profile.digest,
        allowed_effects=(EffectClass.DESTRUCTIVE,),
    )
    applicable, exclusions = _applicable_playbooks(profile, no_passive, library)
    assert applicable == ()
    assert any(item["reason"] == "effect-not-authorized" for item in exclusions)

    first, second = library.playbooks[:2]
    cyclic_first = replace(first, depends_on=(second.identifier,))
    cyclic_second = replace(second, depends_on=(first.identifier,))
    with pytest.raises(FormatError, match="cycle"):
        _schedule_playbooks(
            (cyclic_first, cyclic_second),
            methodology_policy_template(profile.digest),
            context,
        )

    with pytest.raises(FormatError, match="cycle"):
        _validate_task_graph(
            [
                {"id": "a", "dependsOn": ["b"]},
                {"id": "b", "dependsOn": ["a"]},
            ]
        )
    with pytest.raises(FormatError, match="every scheduled"):
        _validate_phase_matrix([{"playbook": {"id": playbook.identifier}, "phase": "discovery"}])


def test_bound_plan_and_replan_mutation_guards_reject_coverage_lies() -> None:
    profile = _profile()
    policy = methodology_policy_template(profile.digest)
    library = load_builtin_library()
    plan = compile_methodology(profile, policy, library=library)
    _validate_bound_task_contracts(plan, profile, policy, None)

    mutations: list[Callable[[dict[str, Any]], Any]] = [
        lambda item: item["exclusions"].append(copy.deepcopy(item["exclusions"][0])),
        lambda item: item["exclusions"].append(
            {
                "playbookId": item["tasks"][0]["playbook"]["id"],
                "reason": "policy-denied",
                "details": ["test"],
            }
        ),
        lambda item: item["coverage"].update(libraryPlaybooks=0),
        lambda item: item["coverage"].update(applicablePlaybooks=0),
    ]
    for mutate in mutations:
        changed = copy.deepcopy(plan)
        mutate(changed)
        with pytest.raises(FormatError):
            _validate_bound_task_contracts(changed, profile, policy, library)

    changed_top = copy.deepcopy(plan)
    changed_top["scheduler"] = "changed"
    with pytest.raises(FormatError, match="immutable"):
        _assert_contracts_unchanged(plan, changed_top)
    introduced = copy.deepcopy(plan)
    introduced["tasks"][0]["id"] = "new"
    with pytest.raises(FormatError, match="introduced"):
        _assert_contracts_unchanged(plan, introduced)
    changed_task = copy.deepcopy(plan)
    changed_task["tasks"][0]["preconditions"] = ["changed"]
    with pytest.raises(FormatError, match="task contract"):
        _assert_contracts_unchanged(plan, changed_task)


def test_remaining_plan_validation_and_input_binding_guards(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    profile = _profile()
    policy = methodology_policy_template(profile.digest)
    library = load_builtin_library()
    plan = compile_methodology(profile, policy, library=library)

    bad_digest = copy.deepcopy(plan)
    bad_digest["contentDigest"] = _DIGEST
    with pytest.raises(FormatError, match="digest"):
        validate_methodology_plan(bad_digest)

    changed_identity = copy.deepcopy(plan)
    changed_identity["tasks"][0]["playbook"]["digest"] = _DIGEST
    changed_identity = _redigest(changed_identity)
    with pytest.raises(FormatError, match="identity"):
        validate_methodology_plan(changed_identity, library=library)

    changed_effects = copy.deepcopy(plan)
    changed_effects["tasks"][0]["allowedEffects"] = ["destructive"]
    changed_effects = _redigest(changed_effects)
    with pytest.raises(FormatError, match="playbook contract"):
        validate_methodology_plan(changed_effects, library=library)

    exceeded = copy.deepcopy(plan)
    phase = exceeded["tasks"][0]["phase"]
    phase_assigned = exceeded["budget"]["byPhase"][phase]["assigned"]
    exceeded["budget"]["byPhase"][phase]["total"] = phase_assigned - 1
    exceeded["budget"]["byPhase"][phase]["remaining"] = 0
    exceeded = _redigest(exceeded)
    with pytest.raises(FormatError, match="exceeded"):
        validate_methodology_plan(exceeded)

    other = target_profile_template(
        identifier="other.web",
        title="Other",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned fixture only",
    )
    with pytest.raises(FormatError, match="policy target"):
        compile_methodology(other, policy)
    other_artifacts = run_universal_intake(other, {}, tmp_path / "other-intake")
    other_report = read_intake_report(other_artifacts.report)
    with pytest.raises(FormatError, match="intake report target"):
        compile_methodology(profile, policy, intake_report=other_report)

    same_artifacts = run_universal_intake(profile, {}, tmp_path / "same-intake")
    same_report = read_intake_report(same_artifacts.report)
    intake_plan = compile_methodology(profile, policy, intake_report=same_report)
    changed_intake = copy.deepcopy(intake_plan)
    changed_intake["intakeReportDigest"] = _DIGEST
    changed_intake = _redigest(changed_intake)
    with pytest.raises(FormatError, match="intake report mismatch"):
        validate_methodology_plan(
            changed_intake,
            profile=profile,
            policy=policy,
            library=library,
            intake_report=same_report,
        )

    missing_coverage = copy.deepcopy(plan)
    missing_coverage["exclusions"].pop()
    with pytest.raises(FormatError, match="every library"):
        _validate_bound_task_contracts(missing_coverage, profile, policy, library)
    dependency_change = copy.deepcopy(plan)
    dependency_change["tasks"][1]["dependsOn"] = []
    with pytest.raises(FormatError, match="dependencies differ"):
        _validate_bound_task_contracts(dependency_change, profile, policy, library)
    effect_change = copy.deepcopy(plan)
    effect_change["tasks"][0]["allowedEffects"] = []
    with pytest.raises(FormatError, match="effects differ"):
        _validate_bound_task_contracts(effect_change, profile, policy, library)


def test_submission_rejects_non_object_and_noncanonical_signed_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    playbook = load_builtin_library().playbooks[0]
    keys = generate_ed25519_keypair()
    submission = build_playbook_submission(playbook, keys.private_key, keys.public_key)
    monkeypatch.setattr(contribution_module, "verify_dsse_payload", lambda *_args, **_kwargs: b"[]")
    with pytest.raises(FormatError, match="root"):
        verify_playbook_submission(submission)
    monkeypatch.setattr(
        contribution_module,
        "verify_dsse_payload",
        lambda *_args, **_kwargs: b" " + canonical_json_bytes(playbook.to_mapping()),
    )
    with pytest.raises(FormatError, match="canonical"):
        verify_playbook_submission(submission)
