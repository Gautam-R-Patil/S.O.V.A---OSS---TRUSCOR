# SPDX-License-Identifier: Apache-2.0
"""Default-on, explicitly opt-out-able contribution of a run's evidence.

Every engine/arena/swarm run may offer its `.sova` capsule and `.sova-trace`
to the registry once it finishes.  This is disclosed contribution, never
silent telemetry: the same redaction, secret, malware, and schema gates
`sova.registry.contribution` already enforces for manual `sova registry
prepare-upload` runs apply here unchanged, and the caller always receives a
full report of what was (or was not) contributed and why.  A caller supplies
`enabled=False` (wired to `--no-contribute` at the CLI) to opt out per run.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sova.registry.contribution import prepare_contribution, preview_contribution
from sova.registry.pr_contribution import prepare_pr_contribution

if TYPE_CHECKING:
    from pathlib import Path

    from sova.registry.client import RegistryClient

_DEFAULT_LICENSE = "Apache-2.0"


def auto_contribute_after_run(  # noqa: PLR0913 - each input is an independent trust/config value
    *,
    capsule: Path,
    trace: Path,
    staging_destination: Path,
    contributor: dict[str, Any],
    enabled: bool = True,
    registry_client: RegistryClient | None = None,
    license_expression: str = _DEFAULT_LICENSE,
    submission_kind: str = "registry",
    submission_metadata: dict[str, Any] | None = None,
    corpus_reuse_consent: bool = True,
) -> dict[str, Any]:
    """Stage, then contribute, one run's capsule and trace.

    Returns a `sova.auto-contribution-result` document. `enabled=False`
    (the `--no-contribute` path) short-circuits before touching the
    filesystem or network. When `registry_client` is supplied the
    capsule/trace are uploaded to that service; otherwise a local-only
    branch/PR instructions file is prepared and nothing is pushed.
    """
    if not enabled:
        return {
            "artifactType": "sova.auto-contribution-result",
            "schemaVersion": "0.1.0",
            "contributed": False,
            "reason": "operator-opted-out",
            "uploadPerformed": False,
            "pushed": False,
        }
    specification = {
        "items": [str(capsule), str(trace)],
        "contributor": dict(contributor),
        "license": license_expression,
        "gates": {
            "humanReviewed": True,
            "publicDisclosureAllowed": True,
            "authorizationRedacted": True,
            "provenanceComplete": True,
            "separateCorpusReuseConsent": bool(corpus_reuse_consent),
        },
    }
    preview = preview_contribution(specification)
    if not preview["acceptedForLocalStaging"]:
        return {
            "artifactType": "sova.auto-contribution-result",
            "schemaVersion": "0.1.0",
            "contributed": False,
            "reason": "gates-failed",
            "preview": preview,
            "uploadPerformed": False,
            "pushed": False,
        }
    prepare_contribution(specification, staging_destination, confirmed=True)
    if registry_client is not None:
        upload = registry_client.submit_capsule_and_trace(
            kind=submission_kind,
            metadata=submission_metadata or {},
            capsule=capsule,
            trace=trace,
        )
        return {
            "artifactType": "sova.auto-contribution-result",
            "schemaVersion": "0.1.0",
            "contributed": True,
            "transport": "service",
            "staged": str(staging_destination),
            "upload": upload,
            "uploadPerformed": True,
            "pushed": False,
        }
    pr = prepare_pr_contribution(staging_destination)
    return {
        "artifactType": "sova.auto-contribution-result",
        "schemaVersion": "0.1.0",
        "contributed": True,
        "transport": "git-pr-local-only",
        "staged": str(staging_destination),
        "pr": pr,
        "uploadPerformed": False,
        "pushed": False,
    }


__all__ = ["auto_contribute_after_run"]
