# SPDX-License-Identifier: Apache-2.0
"""Local-only git-PR contribution fallback: prepare, never push or open anything.

When no registry service is configured, a contribution still has a path to
publication, but SOVA never runs `git push` or opens a pull request on the
operator's behalf -- that is a visible action on shared state and belongs to
a human.  This module renders a ready-to-use branch name, commit message, and
PR body next to the already-staged contribution directory (built by
`sova.registry.contribution.prepare_contribution`) and leaves every git and
hosting action to the operator.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.formats import strict_json_loads
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_TITLE_CHARS = 120


def _branch_name(seed: str) -> str:
    safe = "".join(char if char.isalnum() or char in "-_." else "-" for char in seed)
    return f"contribute/{safe.strip('-') or 'submission'}"


def prepare_pr_contribution(
    staged_destination: Path,
    *,
    title: str = "Contribute a SOVA capsule",
    remote: str = "origin",
    base_branch: str = "main",
) -> dict[str, Any]:
    """Render local PR instructions next to an already-staged contribution.

    Reads `staged_destination/contribution.json` (written by
    `prepare_contribution`) and writes `PR_INSTRUCTIONS.md` in the same
    directory.  Performs no git command and no network call; nothing is
    pushed or published without the operator explicitly running the printed
    commands themselves.
    """
    if not title or len(title) > _MAX_TITLE_CHARS:
        raise FormatError(
            "SOVA-REGISTRY-PR-TITLE",
            "contribution PR title must be a bounded non-empty string",
        )
    manifest_path = staged_destination / "contribution.json"
    if not manifest_path.is_file():
        raise FormatError(
            "SOVA-REGISTRY-PR-STAGING",
            "staged contribution.json is missing; run prepare_contribution first",
        )
    staged = strict_json_loads(manifest_path.read_bytes())
    if not isinstance(staged, dict) or staged.get("artifactType") != "sova.contribution-staging":
        raise FormatError(
            "SOVA-REGISTRY-PR-STAGING",
            "staged contribution.json is not a valid staging document",
        )
    raw_items = staged.get("items", [])
    item_names = [entry["name"] for entry in raw_items if isinstance(entry, dict)]
    item_digests = [
        entry["digest"]
        for entry in raw_items
        if isinstance(entry, dict) and isinstance(entry.get("digest"), str)
    ]
    contributor = staged.get("contributor", {})
    contributor_name = (
        contributor.get("name", "unknown") if isinstance(contributor, dict) else "unknown"
    )
    branch_seed = item_digests[0][7:23] if item_digests else "submission"
    branch = _branch_name(branch_seed)
    commit_message = f"{title}\n\nContributed-by: {contributor_name}"
    body_lines = [
        f"# {title}",
        "",
        f"Contributed by: {contributor_name}",
        "",
        "## Items",
        *[f"- `items/sha256/...` -> `{name}`" for name in item_names],
        "",
        "## Staged gates",
        *[f"- {key}: {value}" for key, value in staged.get("gates", {}).items()],
        "",
        "This PR was prepared locally by SOVA and has **not** been pushed or opened.",
        "Review the staged files, then run the commands below yourself.",
    ]
    body = "\n".join(body_lines) + "\n"
    commands = [
        f"git checkout -b {branch}",
        f"cp -r {staged_destination / 'items'} <your-registry-checkout>/items",
        "git add <copied files>",
        f'git commit -m "{title}"',
        f"git push {remote} {branch}",
        f'gh pr create --base {base_branch} --head {branch} --title "{title}" '
        f"--body-file {staged_destination / 'PR_INSTRUCTIONS.md'}",
    ]
    command_blocks = "\n".join(f"```\n{command}\n```" for command in commands)
    instructions = (
        body + "\n## Commands (run these yourself; nothing above was executed)\n\n" + command_blocks
    )
    instructions_path = staged_destination / "PR_INSTRUCTIONS.md"
    instructions_path.write_text(instructions, encoding="utf-8")
    return {
        "artifactType": "sova.contribution-pr-instructions",
        "schemaVersion": "0.1.0",
        "branch": branch,
        "baseBranch": base_branch,
        "remote": remote,
        "commitMessage": commit_message,
        "instructions": str(instructions_path),
        "pushed": False,
        "pullRequestOpened": False,
    }


__all__ = ["prepare_pr_contribution"]
