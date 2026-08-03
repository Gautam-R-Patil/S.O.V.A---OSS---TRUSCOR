# SPDX-License-Identifier: Apache-2.0
"""User-agent proposal boundary for deterministic and external rehearsal adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from sova.formats.errors import FormatError
from sova.rehearsal.model import RehearsalAction, RehearsalSpecification
from sova.rehearsal.runner import run_rehearsal

if TYPE_CHECKING:
    from pathlib import Path

    from sova.rehearsal.model import RehearsalReport


class RehearsalAgentDriver(Protocol):
    """An agent proposes portable actions; it never receives production credentials."""

    @property
    def agent_id(self) -> str: ...

    def propose(
        self,
        task: str,
        environment: dict[str, Any],
    ) -> tuple[RehearsalAction, ...]: ...


@dataclass(frozen=True, slots=True)
class ScriptedRehearsalAgent:
    """Offline deterministic user-agent fixture used by mandatory tests."""

    agent_id: str
    actions: tuple[RehearsalAction, ...]

    def propose(
        self,
        task: str,
        environment: dict[str, Any],
    ) -> tuple[RehearsalAction, ...]:
        if not task or environment.get("productionCredentialsImported") is not False:
            raise FormatError(
                "SOVA-REHEARSE-AGENT-CONTEXT",
                "agent proposal context must be credential-free",
            )
        return self.actions


def run_agent_rehearsal(  # noqa: PLR0913 - all trust-relevant inputs remain explicit
    driver: RehearsalAgentDriver,
    task: str,
    workspace: Path,
    trace_path: Path,
    *,
    authorization_confirmed: bool,
    with_attack: bool = False,
    attack_profile: str | None = None,
) -> RehearsalReport:
    """Ask the user's adapter for actions, then enforce the normal SOVA gates."""
    context = {
        "workspaceKind": "prepared-rehearsal",
        "productionCredentialsImported": False,
        "productionServicesReachable": False,
    }
    actions = driver.propose(task, context)
    return run_rehearsal(
        RehearsalSpecification(
            task=task,
            agent_id=driver.agent_id,
            actions=actions,
            authorization_confirmed=authorization_confirmed,
            with_attack=with_attack,
            attack_profile=attack_profile,
        ),
        workspace,
        trace_path,
    )


__all__ = ["RehearsalAgentDriver", "ScriptedRehearsalAgent", "run_agent_rehearsal"]
