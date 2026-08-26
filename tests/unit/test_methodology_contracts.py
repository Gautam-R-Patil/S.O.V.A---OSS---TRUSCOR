# SPDX-License-Identifier: Apache-2.0
"""Native playbook library, contract, and provenance invariants."""

from __future__ import annotations

import re
from dataclasses import replace

import pytest

from sova.formats import validate_document
from sova.formats.errors import FormatError
from sova.intake import ProfileTargetKind, target_profile_template
from sova.methodology import (
    EffectClass,
    MethodologyLibrary,
    load_builtin_library,
    methodology_policy_from_mapping,
    methodology_policy_template,
    playbook_from_mapping,
)


def test_builtin_library_is_complete_native_versioned_and_schema_valid() -> None:
    library = load_builtin_library()
    assert len(library.playbooks) == 74
    assert {
        domain: sum(item.domain.value == domain for item in library.playbooks)
        for domain in (
            "web",
            "api",
            "network-host-cloud",
            "source-package-binary",
            "ai-model",
            "agentic",
        )
    } == {
        "web": 14,
        "api": 16,
        "network-host-cloud": 11,
        "source-package-binary": 9,
        "ai-model": 12,
        "agentic": 12,
    }
    assert {source.key for source in library.sources} == {
        "NIST",
        "PTES",
        "WSTG",
        "ASVS",
        "OWASP-API",
        "AISVS",
        "AITG",
        "AGENTIC",
        "ATLAS",
        "CWE",
        "CAPEC",
    }
    assert all(
        "/main/" not in source.url and "/master/" not in source.url for source in library.sources
    )
    assert next(source for source in library.sources if source.key == "AISVS").catalog_version == (
        "1.0@78775233666a2022dcfb82037e5e029116955c00"
    )
    assert next(source for source in library.sources if source.key == "AITG").catalog_version == (
        "1.0@006e4e9ee060f2ca2176037499b824e47af5360e"
    )
    validate_document(library.to_mapping(), "sova.playbook-library")
    for playbook in library.playbooks:
        document = playbook.to_mapping()
        validate_document(document, "sova.playbook")
        assert playbook_from_mapping(document) == playbook
        assert playbook.oracle_proposal.calibration_status == "unvalidated-proposal"
        assert playbook.provenance.origin == "sova-native"
        assert playbook.provenance.third_party_prose_copied is False
        assert playbook.provenance.third_party_dataset_included is False
        assert playbook.evidence_limits.limitations
        assert playbook.evidence_limits.false_positive_risks
        assert playbook.evidence_limits.false_negative_risks
        for mapping in playbook.mappings:
            if mapping.framework == "OWASP AI Testing Guide":
                assert re.fullmatch(r"AITG-(?:APP|MOD|INF|DAT)-[0-9]{2}", mapping.identifier)


def test_policy_is_non_authorizing_and_rejects_unsafe_or_secret_shaped_changes() -> None:
    profile = target_profile_template(
        identifier="owned.web",
        title="Owned web target",
        target_kinds=(ProfileTargetKind.WEB,),
        authorization_scope="owned loopback fixture only",
    )
    policy = methodology_policy_template(
        profile.digest,
        allowed_effects=(EffectClass.OBSERVE, EffectClass.READ_TARGET),
    )
    document = policy.to_mapping()
    validate_document(document, "sova.methodology-policy")
    assert methodology_policy_from_mapping(document) == policy
    assert document["claims"] == {
        "executionAuthorized": False,
        "modelMayExpandAuthority": False,
        "policyMayExpandTargetScope": False,
    }
    unsafe = {**document, "claims": {**document["claims"], "executionAuthorized": True}}
    with pytest.raises(FormatError, match="unsafe"):
        methodology_policy_from_mapping(unsafe)

    playbook = load_builtin_library().playbooks[0].to_mapping()
    playbook["technique"]["summary"] = "Bearer abcdefghijklmnopqrstuvwxyz"
    with pytest.raises(FormatError, match="secret-shaped"):
        playbook_from_mapping(playbook)


def test_library_rejects_missing_dependencies_and_cycles() -> None:
    library = load_builtin_library()
    first, second = library.playbooks[:2]
    missing = replace(first, depends_on=("sova.playbook.web.absent",))
    with pytest.raises(FormatError, match="absent"):
        MethodologyLibrary(
            library.identifier,
            library.version,
            library.released,
            library.sources,
            (missing,),
        )
    cyclic_first = replace(first, depends_on=(second.identifier,))
    cyclic_second = replace(second, depends_on=(first.identifier,))
    with pytest.raises(FormatError, match="cycle"):
        MethodologyLibrary(
            library.identifier,
            library.version,
            library.released,
            library.sources,
            (cyclic_first, cyclic_second),
        )
