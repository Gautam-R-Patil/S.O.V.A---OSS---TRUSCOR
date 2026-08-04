# SPDX-License-Identifier: Apache-2.0
"""Check repository structure, provenance, links, headers, and pinned actions."""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = {
    ".editorconfig",
    ".gitattributes",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/ISSUE_TEMPLATE/bug.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/ISSUE_TEMPLATE/feature.yml",
    ".github/ISSUE_TEMPLATE/research-result.yml",
    ".github/pull_request_template.md",
    ".github/workflows/ci.yml",
    ".github/workflows/codeql.yml",
    ".github/workflows/dependency-review.yml",
    ".github/workflows/public-boundary.yml",
    ".github/workflows/secret-scan.yml",
    ".pre-commit-config.yaml",
    ".python-version",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "MAINTAINERS.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "docs/decisions/README.md",
    "docs/decisions/0008-topic-03-domain-contracts.md",
    "docs/contracts/README.md",
    "docs/contracts/coverage-model.md",
    "docs/contracts/domain-model.md",
    "docs/contracts/finding-lifecycle.md",
    "docs/contracts/source-example-reconciliation.md",
    "docs/contracts/version-contracts.md",
    "docs/glossary.md",
    "docs/glossary.toml",
    "docs/governance/fixture-and-dataset-provenance.md",
    "docs/governance/independent-review.md",
    "docs/governance/invention-handling.md",
    "docs/governance/release-compatibility-matrix.md",
    "docs/governance/repository-controls.md",
    "docs/governance/schema-and-taxonomy-changes.md",
    "docs/guides/README.md",
    "docs/guides/authorized-target-testing.md",
    "docs/guides/command-reference.md",
    "docs/guides/first-five-minutes.md",
    "docs/guides/installation.md",
    "docs/long-horizon-roadmap.md",
    "docs/methodology/versions.toml",
    "docs/research/artifacts/index.toml",
    "docs/taxonomy/README.md",
    "docs/taxonomy/sova-attack-taxonomy.md",
    "pyproject.toml",
    "src/sova/cli.py",
    "src/sova/contracts/data/attack-taxonomy-0.1.0.toml",
    "tests/fixtures/provenance.toml",
}

HEADER_SUFFIXES = {".py", ".ps1"}
MARKDOWN_LINK = re.compile(r"!?\[[^\]]*]\(([^)]+)\)")
HTML_LINK = re.compile(r"(?:href|src)=[\"']([^\"']+)[\"']", re.IGNORECASE)
ACTION_REFERENCE = re.compile(r"^\s*uses:\s*([^#\s]+)", re.MULTILINE)
PINNED_ACTION = re.compile(r"^[^/@\s]+/[^@\s]+@[0-9a-f]{40}$")
DOC_STATUS = re.compile(
    r"^<!-- status: (implemented|planned|experiment|claim|decision) -->$",
    re.MULTILINE,
)
REQUIRED_TOPIC_03_TERMS = {
    "agent",
    "approval gate",
    "artifact",
    "attack",
    "attempt",
    "attribution",
    "bundled target",
    "campaign",
    "capability",
    "commitment",
    "component",
    "condition",
    "confidence",
    "controlled re-execution",
    "counterfactual",
    "custom profile",
    "decision point",
    "effect",
    "egress",
    "evidence",
    "finding",
    "harm",
    "hypothesis",
    "identity",
    "intervention",
    "judge",
    "mcp server",
    "methodology version",
    "model",
    "mutation",
    "observation",
    "observed coverage",
    "oracle",
    "owned target",
    "permission",
    "playback",
    "plugin",
    "provenance",
    "public component",
    "reconstruction",
    "redaction",
    "reproduction rate",
    "run",
    "semantic reproduction",
    "sequence",
    "severity",
    "signature",
    "skill",
    "standard profile",
    "sub-agent",
    "target",
    "target manifest",
    "taxonomy version",
    "timestamp",
    "tool",
    "trace",
    "transitive reach",
    "trigger",
    "verdict",
}


def git_candidates() -> set[str]:
    """Return tracked and unignored paths, normalized to POSIX separators."""
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return {line.replace("\\", "/") for line in result.stdout.splitlines() if line}


def _normalized_dependency(requirement: str) -> str:
    name = re.split(r"[\s\[<>=!~;@]", requirement, maxsplit=1)[0]
    return re.sub(r"[-_.]+", "-", name).lower()


def check_required_files(candidates: set[str], violations: list[str]) -> None:
    """Require all permanent Topic 02 control files."""
    violations.extend(
        f"required Topic 02 file is missing: {required}"
        for required in sorted(REQUIRED_FILES - candidates)
    )


def check_spdx_headers(candidates: set[str], violations: list[str]) -> None:
    """Require SPDX identifiers on source and executable test code."""
    for relative in sorted(candidates):
        path = Path(relative)
        if path.suffix.lower() not in HEADER_SUFFIXES:
            continue
        if not relative.startswith(("src/", "scripts/", "tests/")):
            continue
        content = (ROOT / path).read_text(encoding="utf-8")
        if not any(
            "SPDX-License-Identifier: Apache-2.0" in line for line in content.splitlines()[:5]
        ):
            violations.append(f"missing Apache-2.0 SPDX header: {relative}")


def _is_external(target: str) -> bool:
    lowered = target.lower()
    return lowered.startswith(("http://", "https://", "mailto:", "tel:", "data:", "thread://"))


def check_local_links(candidates: set[str], violations: list[str]) -> None:
    """Ensure local Markdown and HTML links resolve to public files."""
    public_lower = {candidate.lower() for candidate in candidates}
    for relative in sorted(candidates):
        if Path(relative).suffix.lower() != ".md":
            continue
        content = (ROOT / relative).read_text(encoding="utf-8")
        targets = MARKDOWN_LINK.findall(content) + HTML_LINK.findall(content)
        for raw_target in targets:
            target = raw_target.strip().strip("<>")
            if not target or target.startswith("#") or _is_external(target):
                continue
            path_part = unquote(target.split("#", maxsplit=1)[0].split("?", maxsplit=1)[0])
            resolved = ((ROOT / relative).parent / path_part).resolve()
            try:
                normalized = resolved.relative_to(ROOT).as_posix()
            except ValueError:
                violations.append(f"local link leaves repository: {relative} -> {target}")
                continue
            if normalized.lower() not in public_lower:
                violations.append(f"broken local link: {relative} -> {target}")


def check_documentation_status(candidates: set[str], violations: list[str]) -> None:
    """Require explicit evidence-state labels on foundation documentation."""
    controlled_prefixes = (
        "docs/contracts/",
        "docs/engineering/",
        "docs/methodology/",
        "docs/research/artifacts/",
        "docs/taxonomy/",
    )
    controlled_exact = {"docs/documentation-status.md", "docs/glossary.md"}
    for relative in sorted(candidates):
        if Path(relative).suffix.lower() != ".md":
            continue
        if relative not in controlled_exact and not relative.startswith(controlled_prefixes):
            continue
        content = (ROOT / relative).read_text(encoding="utf-8")
        if DOC_STATUS.search(content) is None:
            violations.append(f"documentation state marker is missing: {relative}")


def check_actions_are_pinned(candidates: set[str], violations: list[str]) -> None:
    """Require immutable full-length commits for third-party Actions."""
    for relative in sorted(candidates):
        if not relative.startswith(".github/workflows/"):
            continue
        if Path(relative).suffix.lower() not in {".yml", ".yaml"}:
            continue
        content = (ROOT / relative).read_text(encoding="utf-8")
        for action in ACTION_REFERENCE.findall(content):
            if action.startswith("./"):
                continue
            if PINNED_ACTION.fullmatch(action) is None:
                violations.append(
                    f"GitHub Action is not pinned to a full SHA: {relative}: {action}"
                )


def check_fixture_provenance(candidates: set[str], violations: list[str]) -> None:
    """Verify every fixture is declared and content-addressed."""
    manifest_path = ROOT / "tests" / "fixtures" / "provenance.toml"
    if not manifest_path.exists():
        return
    raw = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    entries = cast("list[dict[str, object]]", raw.get("fixture", []))
    declared: set[str] = set()
    for entry in entries:
        relative = str(entry.get("path", ""))
        declared.add(relative)
        if relative not in candidates:
            violations.append(f"fixture provenance points to a missing file: {relative}")
            continue
        expected_digest = str(entry.get("sha256", ""))
        actual_digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if expected_digest != actual_digest:
            violations.append(f"fixture digest mismatch: {relative}")
        if entry.get("provenance_class") not in {
            "synthetic",
            "public-source",
            "consented-publication",
            "generated-from-public-inputs",
        }:
            violations.append(f"invalid fixture provenance class: {relative}")
        if not entry.get("license") or not entry.get("purpose") or not entry.get("expected"):
            violations.append(f"incomplete fixture provenance: {relative}")

    fixture_files = {
        relative
        for relative in candidates
        if relative.startswith("tests/fixtures/")
        and Path(relative).name not in {"README.md", "provenance.toml"}
    }
    violations.extend(
        f"fixture lacks provenance entry: {undeclared}"
        for undeclared in sorted(fixture_files - declared)
    )


def check_dependency_notices(violations: list[str]) -> None:
    """Ensure direct build/development dependencies appear in the notice ledger."""
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = list(project["build-system"]["requires"])
    requirements.extend(project["project"].get("dependencies", []))
    groups = cast("dict[str, list[str]]", project.get("dependency-groups", {}))
    for group in groups.values():
        requirements.extend(group)
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8").lower()
    for requirement in requirements:
        dependency = _normalized_dependency(requirement)
        if f"`{dependency}`" not in notices:
            violations.append(
                f"direct dependency missing from THIRD_PARTY_NOTICES.md: {dependency}"
            )


def check_public_trace_locations(candidates: set[str], violations: list[str]) -> None:
    """Permit public raw-trace files only as declared synthetic golden fixtures."""
    allowed_prefix = "tests/fixtures/golden/trace/"
    violations.extend(
        f"raw trace outside the approved synthetic fixture path: {relative}"
        for relative in sorted(candidates)
        if ".sova-trace" in relative.lower() and not relative.startswith(allowed_prefix)
    )


def check_contract_sources(candidates: set[str], violations: list[str]) -> None:
    """Validate machine-readable Topic 03 sources and their public references."""
    glossary_path = ROOT / "docs" / "glossary.toml"
    glossary = tomllib.loads(glossary_path.read_text(encoding="utf-8"))
    terms = cast("list[dict[str, object]]", glossary.get("term", []))
    normalized = [str(item.get("term", "")).casefold() for item in terms]
    if len(normalized) != len(set(normalized)):
        violations.append("glossary terms are not unique ignoring case")
    violations.extend(
        f"required Topic 03 glossary term is missing: {term}"
        for term in sorted(REQUIRED_TOPIC_03_TERMS - set(normalized))
    )
    for item in terms:
        term = str(item.get("term", ""))
        definition = str(item.get("definition", ""))
        status = str(item.get("status", ""))
        source = f"docs/{item.get('source', '')}"
        if not term.strip() or not definition.strip():
            violations.append("glossary contains an empty term or definition")
        if status not in {"accepted", "planned", "deprecated"}:
            violations.append(f"glossary has invalid status: {term}: {status}")
        if source not in candidates:
            violations.append(f"glossary source is missing: {term}: {source}")

    methodology_path = ROOT / "docs" / "methodology" / "versions.toml"
    methodology = tomllib.loads(methodology_path.read_text(encoding="utf-8"))
    methods = cast("list[dict[str, object]]", methodology.get("methodology", []))
    method_keys = [(str(item.get("id", "")), str(item.get("version", ""))) for item in methods]
    if len(method_keys) != len(set(method_keys)):
        violations.append("methodology ID/version pairs are not unique")
    for method_id, version in method_keys:
        if re.fullmatch(r"[A-Z0-9]+(?:-[A-Z0-9]+)*", method_id) is None:
            violations.append(f"invalid methodology ID: {method_id}")
        if re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version) is None:
            violations.append(f"invalid methodology version: {method_id}: {version}")


def main() -> int:
    """Run repository policy checks."""
    violations: list[str] = []
    candidates = git_candidates()
    check_required_files(candidates, violations)
    check_spdx_headers(candidates, violations)
    check_local_links(candidates, violations)
    check_documentation_status(candidates, violations)
    check_actions_are_pinned(candidates, violations)
    check_fixture_provenance(candidates, violations)
    if (ROOT / "THIRD_PARTY_NOTICES.md").exists():
        check_dependency_notices(violations)
    check_public_trace_locations(candidates, violations)
    check_contract_sources(candidates, violations)

    if violations:
        print("REPOSITORY_POLICY_CHECK=FAILED")
        for violation in sorted(set(violations)):
            print(f" - {violation}")
        return 1
    print("REPOSITORY_POLICY_CHECK=PASS")
    print(f"TRACKED_OR_UNIGNORED_FILES_SCANNED={len(candidates)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
