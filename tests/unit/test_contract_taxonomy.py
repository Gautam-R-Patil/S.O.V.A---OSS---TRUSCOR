# SPDX-License-Identifier: Apache-2.0
"""Unit contracts for the native attack taxonomy."""

from __future__ import annotations

import tomllib
from dataclasses import replace
from importlib.resources import files
from typing import TYPE_CHECKING

import pytest

import sova.contracts.taxonomy as taxonomy_module
from sova.contracts import (
    AttackTaxonomy,
    ContractError,
    ExternalMapping,
    MappingRelationship,
    Taxon,
    TaxonStatus,
    load_attack_taxonomy,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def test_packaged_taxonomy_is_complete_and_versioned() -> None:
    taxonomy = load_attack_taxonomy()
    assert taxonomy.identifier == "sova.attack"
    assert str(taxonomy.version) == "0.1.0"
    assert taxonomy.status == "experimental"
    assert len(taxonomy.taxa) == 12
    assert set(taxonomy.standard_profile) == {
        taxon.identifier for taxon in taxonomy.taxa if taxon.status is TaxonStatus.ACTIVE
    }
    assert taxonomy.by_id()["SOVA-ATK-009"].title == "Conditional and dormant triggers"


def test_every_taxon_has_versioned_external_mapping() -> None:
    taxonomy = load_attack_taxonomy()
    assert all(taxon.mappings for taxon in taxonomy.taxa)
    assert all(mapping.catalog_version for taxon in taxonomy.taxa for mapping in taxon.mappings)


def test_packaged_source_is_valid_toml() -> None:
    resource = files("sova.contracts.data").joinpath("attack-taxonomy-0.1.0.toml")
    parsed = tomllib.loads(resource.read_text(encoding="utf-8"))
    assert parsed["taxonomy_id"] == "sova.attack"


def test_taxonomy_can_load_an_explicit_offline_path(tmp_path: Path) -> None:
    resource = files("sova.contracts.data").joinpath("attack-taxonomy-0.1.0.toml")
    local = tmp_path / "taxonomy.toml"
    local.write_text(resource.read_text(encoding="utf-8"), encoding="utf-8")
    assert load_attack_taxonomy(local).identifier == "sova.attack"


def test_missing_taxonomy_field_has_stable_error() -> None:
    with pytest.raises(ContractError) as caught:
        taxonomy_module._parse_taxonomy({})
    assert caught.value.code == "SOVA-TAXONOMY-INVALID"


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda taxonomy: replace(taxonomy, identifier="other.attack"),
            "SOVA-TAXONOMY-INVALID",
        ),
        (
            lambda taxonomy: replace(taxonomy, status="draft"),
            "SOVA-TAXONOMY-INVALID",
        ),
        (
            lambda taxonomy: replace(taxonomy, owner=" "),
            "SOVA-TAXONOMY-INVALID",
        ),
        (
            lambda taxonomy: replace(
                taxonomy,
                standard_profile=("SOVA-ATK-001",),
            ),
            "SOVA-TAXONOMY-INVALID-STANDARD-PROFILE",
        ),
    ],
)
def test_taxonomy_header_invariants_fail_closed(
    mutator: Callable[[AttackTaxonomy], AttackTaxonomy],
    code: str,
) -> None:
    taxonomy = load_attack_taxonomy()
    invalid = mutator(taxonomy)
    with pytest.raises(ContractError) as caught:
        taxonomy_module._validate_taxonomy(invalid)
    assert caught.value.code == code


def test_duplicate_taxon_id_fails_closed() -> None:
    taxonomy = load_attack_taxonomy()
    invalid = replace(taxonomy, taxa=(taxonomy.taxa[0], taxonomy.taxa[0]))
    with pytest.raises(ContractError) as caught:
        taxonomy_module._validate_taxonomy(invalid)
    assert caught.value.code == "SOVA-TAXONOMY-DUPLICATE-ID"


@pytest.mark.parametrize(
    ("mutator", "code"),
    [
        (
            lambda taxon: replace(taxon, identifier="bad-id"),
            "SOVA-TAXONOMY-INVALID-ID",
        ),
        (
            lambda taxon: replace(taxon, title=""),
            "SOVA-TAXONOMY-INVALID",
        ),
        (
            lambda taxon: replace(
                taxon,
                status=TaxonStatus.RETIRED,
                replacement="SOVA-ATK-999",
            ),
            "SOVA-TAXONOMY-INVALID-REPLACEMENT",
        ),
        (
            lambda taxon: replace(taxon, replacement="SOVA-ATK-002"),
            "SOVA-TAXONOMY-INVALID-REPLACEMENT",
        ),
    ],
)
def test_taxon_invariants_fail_closed(
    mutator: Callable[[Taxon], Taxon],
    code: str,
) -> None:
    taxonomy = load_attack_taxonomy()
    taxon = mutator(taxonomy.taxa[0])
    with pytest.raises(ContractError) as caught:
        taxonomy_module._validate_taxon(
            taxon,
            {item.identifier for item in taxonomy.taxa},
        )
    assert caught.value.code == code


def test_duplicate_external_mapping_fails_closed() -> None:
    taxonomy = load_attack_taxonomy()
    taxon = taxonomy.taxa[0]
    invalid = replace(taxon, mappings=(taxon.mappings[0], taxon.mappings[0]))
    with pytest.raises(ContractError) as caught:
        taxonomy_module._validate_taxon(
            invalid,
            {item.identifier for item in taxonomy.taxa},
        )
    assert caught.value.code == "SOVA-TAXONOMY-DUPLICATE-MAPPING"


@pytest.mark.parametrize(
    "mutator",
    [
        lambda mapping: replace(mapping, framework=""),
        lambda mapping: replace(mapping, catalog_version=""),
        lambda mapping: replace(mapping, identifier=""),
        lambda mapping: replace(mapping, title=""),
        lambda mapping: replace(mapping, url="http://example.org"),
        lambda mapping: replace(mapping, url="https:///missing-host"),
    ],
)
def test_invalid_external_mapping_fails_closed(
    mutator: Callable[[ExternalMapping], ExternalMapping],
) -> None:
    taxonomy = load_attack_taxonomy()
    taxon = taxonomy.taxa[0]
    mapping = mutator(taxon.mappings[0])
    invalid = replace(taxon, mappings=(mapping,))
    with pytest.raises(ContractError) as caught:
        taxonomy_module._validate_taxon(
            invalid,
            {item.identifier for item in taxonomy.taxa},
        )
    assert caught.value.code == "SOVA-TAXONOMY-INVALID-MAPPING"


def test_all_mapping_relationships_are_representable() -> None:
    assert {item.value for item in MappingRelationship} == {
        "equivalent",
        "broader",
        "narrower",
        "related",
    }
