# SPDX-License-Identifier: Apache-2.0
"""Small closed vocabularies shared across SOVA contract families."""

from enum import StrEnum


class ComponentKind(StrEnum):
    """Kinds of executable or decision-making system components."""

    AGENT = "agent"
    COMPONENT = "component"
    MCP_SERVER = "mcp-server"
    SKILL = "skill"
    PLUGIN = "plugin"
    SUB_AGENT = "sub-agent"
    TOOL = "tool"
    MODEL = "model"


class ProfileKind(StrEnum):
    """Comparability class of an attack profile."""

    STANDARD = "standard"
    CUSTOM = "custom"


class SeverityBand(StrEnum):
    """Qualitative severity under a separately named rubric."""

    UNRATED = "unrated"
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssertionBasis(StrEnum):
    """Provenance basis for a capability or relationship assertion."""

    DECLARED = "declared"
    OBSERVED = "observed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


__all__ = ["AssertionBasis", "ComponentKind", "ProfileKind", "SeverityBand"]
