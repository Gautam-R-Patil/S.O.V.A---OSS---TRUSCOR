# SPDX-License-Identifier: Apache-2.0
"""Deterministic human-readable renderers for SOVA self-assessment evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.evidence.model import EvidenceBundle


def _clean(value: str) -> str:
    return " ".join(value.replace("|", "\\|").split())


def render_evidence_report(bundle: EvidenceBundle, *, audience: str = "technical") -> str:
    """Render technical, executive, reproduction, or methodology views."""
    if audience not in {"technical", "executive", "reproduction", "methodology"}:
        raise FormatError("SOVA-EVIDENCE-AUDIENCE", "unsupported evidence-report audience")
    heading = {
        "technical": "Technical evidence report",
        "executive": "Plain-language evidence summary",
        "reproduction": "Reproduction packet index",
        "methodology": "Methodology appendix",
    }[audience]
    lines = [
        f"# {heading}: {_clean(bundle.title)}",
        "",
        "> SELF-GENERATED SOVA EVIDENCE - NOT INDEPENDENT ATTESTATION",
        "",
        f"Finding: `{_clean(bundle.finding_id)}`",
        f"Affected component: `{_clean(bundle.component)}` version `{_clean(bundle.version)}`",
        f"Technical severity: **{bundle.severity.value}**",
        f"Harm category: `{_clean(bundle.harm_category)}`",
        "",
    ]
    if audience in {"technical", "executive"}:
        lines.extend((_clean(bundle.summary), ""))
    if audience in {"technical", "reproduction"}:
        lines.extend(("## Evidence index", ""))
        lines.extend(
            f"- `{item.role}`: `{_clean(item.uri)}` "
            f"({item.media_type}; verified={str(item.verified).lower()})"
            for item in bundle.references
        )
        lines.extend(("", "## Conditions tested", ""))
        lines.extend(f"- {_clean(item)}" for item in bundle.conditions_tested)
        lines.append("")
    if audience in {"technical", "methodology"}:
        lines.extend(("## Methodology", ""))
        lines.extend(
            f"- **{_clean(key)}:** {_clean(value)}" for key, value in bundle.methodology.items()
        )
        lines.append("")
    lines.extend(("## Limitations", ""))
    lines.extend(f"- {_clean(item)}" for item in bundle.limitations)
    lines.extend(
        (
            "",
            "This report does not establish independent certification, universal safety, "
            "or legal blame.",
            "",
        )
    )
    return "\n".join(lines)


__all__ = ["render_evidence_report"]
