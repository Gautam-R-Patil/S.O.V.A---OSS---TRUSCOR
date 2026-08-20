# SPDX-License-Identifier: Apache-2.0
"""Hardened signed-community-registry deployment blueprint checks."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import yaml  # type: ignore[import-untyped]

from deploy.community import preflight
from sova.registry.service import CommunityServiceLimits

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_DIGEST_A = "sha256:" + "1" * 64
_DIGEST_B = "sha256:" + "2" * 64
_KEY_ID = "sha256:" + "3" * 64


def _operator_directory(tmp_path: Path) -> Path:
    operator = tmp_path / "operator"
    operator.mkdir()
    token = operator / "service.token"
    token.write_bytes(b"synthetic-test-token-material-123456")
    token.chmod(0o600)
    (operator / "methodology.md").write_text("synthetic methodology\n", encoding="utf-8")
    return operator


def _settings(tmp_path: Path) -> preflight.DeploymentSettings:
    return preflight.load_deployment_settings(
        preflight.DeploymentOptions(
            sova_image=f"ghcr.io/sova/runtime@{_DIGEST_A}",
            caddy_image=f"caddy@{_DIGEST_B}",
            trusted_evidence_key_id=_KEY_ID,
            domain="community.example.org",
            operator_directory=str(_operator_directory(tmp_path)),
        ),
        environ={},
    )


def test_community_deployment_blueprint_is_digest_gated_loopback_and_health_checked() -> None:
    root = Path("deploy/community")
    compose = yaml.safe_load((root / "compose.yaml").read_text(encoding="utf-8"))
    assert compose["name"] == "sova-community"
    initializer = compose["services"]["registry-data-init"]
    registry = compose["services"]["registry"]
    edge = compose["services"]["edge"]

    assert initializer["image"] == registry["image"]
    assert ":?set SOVA_IMAGE" in registry["image"]
    assert ":?set CADDY_IMAGE" in edge["image"]
    assert initializer["user"] == "0:0"
    assert initializer["network_mode"] == "none"
    assert initializer["read_only"] is True
    assert initializer["cap_drop"] == ["ALL"]
    assert set(initializer["cap_add"]) == {
        "CHOWN",
        "DAC_OVERRIDE",
        "DAC_READ_SEARCH",
        "FOWNER",
    }
    assert "chown -R 65532:65532 /var/lib/sova" in initializer["command"][0]
    assert "install -o 65532 -g 65532 -m 0400" in initializer["command"][0]
    source_mount = next(mount for mount in initializer["volumes"] if isinstance(mount, dict))
    assert "SOVA_OPERATOR_DIR" in source_mount["source"]
    assert source_mount["target"] == "/run/sova/source"
    assert source_mount["read_only"] is True
    assert "registry-operator:/run/sova/operator" in initializer["volumes"]
    assert registry["depends_on"]["registry-data-init"]["condition"] == (
        "service_completed_successfully"
    )
    assert registry["read_only"] is True
    assert registry["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in registry["security_opt"]
    assert registry["user"] == "65532:65532"
    assert registry["ports"] == ["443:443"]
    assert "registry-operator:/run/sova/operator:ro" in registry["volumes"]
    assert not any(isinstance(mount, dict) for mount in registry["volumes"])

    command = registry["command"]
    assert command[0:2] == ["registry", "serve"]
    assert command[command.index("--host") + 1] == "127.0.0.1"
    assert command[command.index("--port") + 1] == "8736"
    assert registry["healthcheck"]["test"] == [
        "CMD",
        "sova",
        "registry",
        "healthcheck",
        "--url",
        "http://127.0.0.1:8736/v1/health",
    ]
    assert edge["network_mode"] == "service:registry"
    assert edge["read_only"] is True
    assert edge["cap_drop"] == ["ALL"]
    assert edge["cap_add"] == ["NET_BIND_SERVICE"]

    dockerfile = (root / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG SOVA_PYTHON_IMAGE" in dockerfile
    assert "FROM ${SOVA_PYTHON_IMAGE}" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert 'ENTRYPOINT ["sova"]' in dockerfile
    assert 'org.sova.runtime.data="/var/lib/sova"' in dockerfile
    assert 'org.sova.runtime.operator="/run/sova/operator"' in dockerfile
    assert (root / "Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines() == [
        "**",
        "!dist",
        "!dist/*.whl",
    ]


def test_edge_request_limit_equals_registry_encoded_body_limit() -> None:
    caddyfile = Path("deploy/community/Caddyfile").read_text(encoding="utf-8")
    match = re.search(r"(?m)^\s*max_size\s+([0-9]+)\s*$", caddyfile)
    assert match is not None
    assert int(match.group(1)) == CommunityServiceLimits().max_body_bytes == 50_331_648
    assert "127.0.0.1:8736" in caddyfile


def test_deploy_blueprint_is_included_in_source_distribution() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    included = project["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
    assert "/deploy" in included


@pytest.mark.parametrize(
    "reference",
    [
        "ghcr.io/sova/runtime:latest",
        "GHCR.IO/sova/runtime@" + _DIGEST_A,
        "ghcr.io/sova/runtime@sha256:" + "A" * 64,
        "ghcr.io/sova/runtime@sha256:1234",
        "ghcr.io:99999/sova/runtime@" + _DIGEST_A,
        "ghcr.io/sova/runtime@" + _DIGEST_A + " extra",
    ],
)
def test_preflight_rejects_noncanonical_or_mutable_image_references(reference: str) -> None:
    with pytest.raises(
        preflight.PreflightError,
        match=r"repository\[:tag\]@sha256|registry port|invalid image tag",
    ):
        preflight.validate_immutable_image(reference, label="test image")


def test_preflight_accepts_tag_plus_digest_as_immutable() -> None:
    reference = "python:3.11-slim@" + _DIGEST_A
    assert preflight.validate_immutable_image(reference, label="base") == reference


def test_compose_preflight_checks_fully_resolved_image_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    calls: list[list[str]] = []

    def fake_run(
        command: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> str:
        del environment, timeout_seconds
        calls.append(list(command))
        if command[-2:] == ["config", "--images"]:
            return f"{settings.sova_image}\n{settings.caddy_image}\n{settings.sova_image}\n"
        return ""

    monkeypatch.setattr(preflight, "_run", fake_run)
    preflight.validate_compose(settings, "C:/absolute/docker.exe", environ={})
    assert all("--project-name" in call and "sova-community" in call for call in calls)
    assert [call[-2:] for call in calls] == [
        ["config", "--quiet"],
        ["config", "--images"],
    ]

    def unexpected_image_run(
        command: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> str:
        del environment, timeout_seconds
        if command[-2:] == ["config", "--images"]:
            return f"{settings.sova_image}\nexample.org/unreviewed@{_DIGEST_B}\n"
        return ""

    monkeypatch.setattr(preflight, "_run", unexpected_image_run)
    with pytest.raises(preflight.PreflightError, match="image set differs"):
        preflight.validate_compose(settings, "C:/absolute/docker.exe", environ={})


def test_launch_pulls_and_verifies_digests_before_no_pull_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(tmp_path)
    calls: list[list[str]] = []

    def fake_run(
        command: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> str:
        del environment, timeout_seconds
        calls.append(list(command))
        if command[-2:] == ["config", "--images"]:
            return f"{settings.sova_image}\n{settings.caddy_image}\n"
        if "--format={{json .RepoDigests}}" in command:
            return json.dumps([command[-1]])
        return ""

    monkeypatch.setattr(preflight, "_run", fake_run)
    preflight.launch_compose(settings, "C:/absolute/docker.exe", environ={})

    pull_index = next(index for index, call in enumerate(calls) if "pull" in call)
    inspect_indexes = [
        index for index, call in enumerate(calls) if "--format={{json .RepoDigests}}" in call
    ]
    up_index = next(index for index, call in enumerate(calls) if "up" in call)
    assert pull_index < min(inspect_indexes) < max(inspect_indexes) < up_index
    assert calls[pull_index][-3:] == ["pull", "--policy", "always"]
    assert calls[up_index][-5:] == ["up", "--detach", "--wait", "--pull", "never"]


def test_image_build_checks_base_digest_context_and_runtime_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    deploy = root / "deploy" / "community"
    dist = root / "dist"
    deploy.mkdir(parents=True)
    dist.mkdir()
    dockerfile = deploy / "Dockerfile"
    dockerignore = deploy / "Dockerfile.dockerignore"
    dockerfile.write_text("fixture", encoding="utf-8")
    dockerignore.write_text("**\n!dist\n!dist/*.whl\n", encoding="utf-8")
    wheel = dist / "sova_oss-0.1.0a0-py3-none-any.whl"
    wheel.write_bytes(b"synthetic wheel")
    monkeypatch.setattr(preflight, "_ROOT", root)
    monkeypatch.setattr(preflight, "_DEPLOY_ROOT", deploy)
    monkeypatch.setattr(preflight, "_DOCKERFILE", dockerfile)
    monkeypatch.setattr(preflight, "_DOCKERIGNORE", dockerignore)
    calls: list[list[str]] = []

    def fake_run(
        command: Sequence[str],
        *,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> str:
        del environment, timeout_seconds
        calls.append(list(command))
        if "--format={{json .Config}}" in command:
            return json.dumps(
                {
                    "User": "65532:65532",
                    "WorkingDir": "/var/lib/sova",
                    "Entrypoint": ["sova"],
                    "Labels": {
                        "org.sova.runtime.data": "/var/lib/sova",
                        "org.sova.runtime.operator": "/run/sova/operator",
                    },
                }
            )
        return ""

    monkeypatch.setattr(preflight, "_run", fake_run)
    report = preflight.build_sova_image(
        base_image=f"python:3.11-slim@{_DIGEST_A}",
        wheel=wheel,
        local_tag="ghcr.io/sova/runtime:0.1.0a0",
        docker="C:/absolute/docker.exe",
    )
    assert report["digestRequiredBeforeLaunch"] is True
    assert calls[0][-1] == str(root)
    assert f"SOVA_PYTHON_IMAGE=python:3.11-slim@{_DIGEST_A}" in calls[0]
    assert "SOVA_WHEEL=dist/sova_oss-0.1.0a0-py3-none-any.whl" in calls[0]


def test_deployment_boundary_documents_canonical_preflight_and_external_gates() -> None:
    boundary = Path("deploy/community/README.md").read_text(encoding="utf-8")
    for command in ("preflight.py build", "preflight.py check", "preflight.py up"):
        assert command in boundary
    for gate in ("identity", "moderation", "backups", "DDoS", "incident-response"):
        assert gate in boundary
    assert "SOVA_OPERATOR_DIR" in boundary
    assert "50331648" in boundary
    assert "sova-community_registry-operator" in boundary
    assert "Docker daemon administrator can read" in boundary
