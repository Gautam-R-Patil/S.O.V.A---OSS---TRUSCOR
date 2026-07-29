# SPDX-License-Identifier: Apache-2.0
"""Loader and validator for the versioned SOVA attack taxonomy."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import files
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse

from sova.contracts.errors import ContractError
from sova.contracts.versions import SemanticVersion

if TYPE_CHECKING:
    from pathlib import Path

_TAXON_ID = re.compile(r"^SOVA-ATK-[0-9]{3}$")


class TaxonStatus(StrEnum):
    """Lifecycle state of a taxonomy entry."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    RETIRED = "retired"


class MappingRelationship(StrEnum):
    """Semantic relationship to an external taxonomy entry."""

    EQUIVALENT = "equivalent"
    BROADER = "broader"
    NARROWER = "narrower"
    RELATED = "related"


@dataclass(frozen=True, slots=True)
class ExternalMapping:
    """A version-pinned, non-authoritative external taxonomy mapping."""

    framework: str
    catalog_version: str
    identifier: str
    title: str
    relationship: MappingRelationship
    url: str


@dataclass(frozen=True, slots=True)
class Taxon:
    """One permanent SOVA attack-taxonomy entry."""

    identifier: str
    title: str
    definition: str
    status: TaxonStatus
    replacement: str | None
    mappings: tuple[ExternalMapping, ...]


@dataclass(frozen=True, slots=True)
class AttackTaxonomy:
    """The validated native taxonomy and its standard profile."""

    identifier: str
    version: SemanticVersion
    status: str
    owner: str
    released: str
    taxa: tuple[Taxon, ...]
    standard_profile: tuple[str, ...]

    def by_id(self) -> dict[str, Taxon]:
        """Return taxonomy entries keyed by permanent identifier."""
        return {taxon.identifier: taxon for taxon in self.taxa}


def load_attack_taxonomy(path: Path | None = None) -> AttackTaxonomy:
    """Load and validate the packaged attack taxonomy."""
    if path is None:
        resource = files("sova.contracts.data").joinpath("attack-taxonomy-0.1.0.toml")
        raw = tomllib.loads(resource.read_text(encoding="utf-8"))
    else:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return _parse_taxonomy(raw)


def _parse_taxonomy(raw: dict[str, Any]) -> AttackTaxonomy:
    try:
        taxon_rows = cast("list[dict[str, Any]]", raw["taxon"])
        profile = tuple(cast("list[str]", raw["standard_profile"]))
        taxa = tuple(_parse_taxon(row) for row in taxon_rows)
        taxonomy = AttackTaxonomy(
            identifier=str(raw["taxonomy_id"]),
            version=SemanticVersion.parse(str(raw["version"])),
            status=str(raw["status"]),
            owner=str(raw["owner"]),
            released=str(raw["released"]),
            taxa=taxa,
            standard_profile=profile,
        )
    except (KeyError, TypeError) as error:
        raise ContractError(
            "SOVA-TAXONOMY-INVALID",
            "taxonomy source is missing a required field",
            details={"error": str(error)},
        ) from error
    _validate_taxonomy(taxonomy)
    return taxonomy


def _parse_taxon(raw: dict[str, Any]) -> Taxon:
    mappings = tuple(
        ExternalMapping(
            framework=str(row["framework"]),
            catalog_version=str(row["catalog_version"]),
            identifier=str(row["identifier"]),
            title=str(row["title"]),
            relationship=MappingRelationship(str(row["relationship"])),
            url=str(row["url"]),
        )
        for row in cast("list[dict[str, Any]]", raw.get("mapping", []))
    )
    replacement = raw.get("replacement")
    return Taxon(
        identifier=str(raw["id"]),
        title=str(raw["title"]),
        definition=str(raw["definition"]),
        status=TaxonStatus(str(raw["status"])),
        replacement=str(replacement) if replacement is not None else None,
        mappings=mappings,
    )


def _validate_taxonomy(taxonomy: AttackTaxonomy) -> None:
    if taxonomy.identifier != "sova.attack":
        raise ContractError(
            "SOVA-TAXONOMY-INVALID",
            "native taxonomy identifier must be sova.attack",
            field="taxonomy_id",
        )
    if taxonomy.status not in {"experimental", "stable"}:
        raise ContractError(
            "SOVA-TAXONOMY-INVALID",
            "taxonomy status must be experimental or stable",
            field="status",
        )
    if not taxonomy.owner.strip():
        raise ContractError(
            "SOVA-TAXONOMY-INVALID",
            "taxonomy owner is required",
            field="owner",
        )
    identifiers = [taxon.identifier for taxon in taxonomy.taxa]
    if len(identifiers) != len(set(identifiers)):
        raise ContractError(
            "SOVA-TAXONOMY-DUPLICATE-ID",
            "taxonomy identifiers are permanent and cannot be duplicated",
            field="taxon.id",
        )
    for taxon in taxonomy.taxa:
        _validate_taxon(taxon, set(identifiers))
    active = {taxon.identifier for taxon in taxonomy.taxa if taxon.status is TaxonStatus.ACTIVE}
    if set(taxonomy.standard_profile) != active or len(taxonomy.standard_profile) != len(active):
        raise ContractError(
            "SOVA-TAXONOMY-INVALID-STANDARD-PROFILE",
            "the standard profile must contain every active taxon exactly once",
            field="standard_profile",
        )


def _validate_taxon(taxon: Taxon, known_identifiers: set[str]) -> None:
    if _TAXON_ID.fullmatch(taxon.identifier) is None:
        raise ContractError(
            "SOVA-TAXONOMY-INVALID-ID",
            "taxon identifiers require SOVA-ATK-NNN",
            field="taxon.id",
        )
    if not taxon.title.strip() or not taxon.definition.strip():
        raise ContractError(
            "SOVA-TAXONOMY-INVALID",
            "taxon title and definition are required",
            field=taxon.identifier,
        )
    if taxon.replacement is not None and taxon.replacement not in known_identifiers:
        raise ContractError(
            "SOVA-TAXONOMY-INVALID-REPLACEMENT",
            "replacement must identify another retained taxon",
            field=taxon.identifier,
        )
    if taxon.status is TaxonStatus.ACTIVE and taxon.replacement is not None:
        raise ContractError(
            "SOVA-TAXONOMY-INVALID-REPLACEMENT",
            "an active taxon cannot declare a replacement",
            field=taxon.identifier,
        )
    seen_mappings: set[tuple[str, str, str]] = set()
    for mapping in taxon.mappings:
        key = (mapping.framework, mapping.catalog_version, mapping.identifier)
        if key in seen_mappings:
            raise ContractError(
                "SOVA-TAXONOMY-DUPLICATE-MAPPING",
                "external mapping is duplicated",
                field=taxon.identifier,
            )
        seen_mappings.add(key)
        parsed = urlparse(mapping.url)
        if (
            not mapping.framework.strip()
            or not mapping.catalog_version.strip()
            or not mapping.identifier.strip()
            or not mapping.title.strip()
            or parsed.scheme != "https"
            or not parsed.netloc
        ):
            raise ContractError(
                "SOVA-TAXONOMY-INVALID-MAPPING",
                "external mappings require framework, version, ID, title, and HTTPS URL",
                field=taxon.identifier,
            )


__all__ = [
    "AttackTaxonomy",
    "ExternalMapping",
    "MappingRelationship",
    "Taxon",
    "TaxonStatus",
    "load_attack_taxonomy",
]
