# SPDX-License-Identifier: Apache-2.0
"""Build, validate, and launch the digest-pinned community blueprint."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from typing import NoReturn

_ROOT = Path(__file__).resolve().parents[2]
_DEPLOY_ROOT = Path(__file__).resolve().parent
_COMPOSE_FILE = _DEPLOY_ROOT / "compose.yaml"
_COMPOSE_PROJECT = "sova-community"
_DOCKERFILE = _DEPLOY_ROOT / "Dockerfile"
_DOCKERIGNORE = _DEPLOY_ROOT / "Dockerfile.dockerignore"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_DOMAIN_COMPONENT = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*"
_REPOSITORY = re.compile(
    rf"(?=.{{1,255}}\Z)(?:{_DOMAIN}(?::[1-9][0-9]{{0,4}})?/)?"
    rf"{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*\Z"
)
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}\Z")
_PUBLIC_DOMAIN = re.compile(rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})+\Z")
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_PORT = 65535
_MAX_DOMAIN_LENGTH = 253
_MIN_TOKEN_BYTES = 24
_MAX_TOKEN_BYTES = 4096
_PRINTABLE_ASCII_FIRST = 0x21
_PRINTABLE_ASCII_LAST = 0x7E
_MAX_METHODOLOGY_BYTES = 1024 * 1024
_MAX_DIAGNOSTIC_CHARACTERS = 2000


class PreflightError(RuntimeError):
    """A fail-closed deployment validation error."""


def _fail(message: str) -> NoReturn:
    raise PreflightError(message)


@dataclass(frozen=True)
class DeploymentSettings:
    """Validated values passed to Compose without secret contents."""

    sova_image: str
    caddy_image: str
    trusted_evidence_key_id: str
    domain: str
    operator_directory: Path


@dataclass(frozen=True)
class DeploymentOptions:
    """Unvalidated CLI values, with environment fallback for missing fields."""

    sova_image: str | None = None
    caddy_image: str | None = None
    trusted_evidence_key_id: str | None = None
    domain: str | None = None
    operator_directory: str | None = None


def validate_immutable_image(value: str, *, label: str) -> str:
    """Require one exact lowercase repository[:tag]@sha256 image reference."""
    if value.count("@") != 1:
        _fail(f"{label} must be repository[:tag]@sha256:<64 lowercase hex>")
    name, digest = value.split("@", maxsplit=1)
    last_slash = name.rfind("/")
    tag_separator = name.rfind(":")
    if tag_separator > last_slash:
        repository = name[:tag_separator]
        tag = name[tag_separator + 1 :]
        if _TAG.fullmatch(tag) is None:
            _fail(f"{label} contains an invalid image tag")
    else:
        repository = name
    if _REPOSITORY.fullmatch(repository) is None or _DIGEST.fullmatch(digest) is None:
        _fail(f"{label} must be repository[:tag]@sha256:<64 lowercase hex>")
    first_component = repository.split("/", maxsplit=1)[0]
    if ":" in first_component:
        port = int(first_component.rsplit(":", maxsplit=1)[1])
        if port > _MAX_PORT:
            _fail(f"{label} contains an invalid registry port")
    return value


def validate_local_tag(value: str) -> str:
    """Validate an explicit mutable tag used only as a pre-push build name."""
    if "@" in value:
        _fail("local build tag must not contain a digest")
    last_slash = value.rfind("/")
    tag_separator = value.rfind(":")
    if tag_separator <= last_slash:
        _fail("local build tag must include an explicit :tag")
    repository = value[:tag_separator]
    tag = value[tag_separator + 1 :]
    if _REPOSITORY.fullmatch(repository) is None or _TAG.fullmatch(tag) is None:
        _fail("local build tag is not a valid repository:tag reference")
    return value


def validate_public_domain(value: str) -> str:
    """Reject URLs, ports, wildcards, and single-label development hosts."""
    if len(value) > _MAX_DOMAIN_LENGTH or _PUBLIC_DOMAIN.fullmatch(value) is None:
        _fail("SOVA_COMMUNITY_DOMAIN must be a lowercase public DNS name")
    return value


def _validate_token_file(token_file: Path) -> None:
    token = token_file.read_bytes()
    if not _MIN_TOKEN_BYTES <= len(token) <= _MAX_TOKEN_BYTES:
        _fail("operator service.token has an invalid bounded length")
    if any(byte < _PRINTABLE_ASCII_FIRST or byte > _PRINTABLE_ASCII_LAST for byte in token):
        _fail("operator service.token must contain printable ASCII without whitespace")
    if os.name != "nt" and stat.S_IMODE(token_file.stat().st_mode) & 0o077:
        _fail("operator service.token permissions must not grant group/other access")


def _validate_methodology_file(methodology_file: Path) -> None:
    methodology = methodology_file.read_bytes()
    if not methodology or len(methodology) > _MAX_METHODOLOGY_BYTES:
        _fail("operator methodology.md must be non-empty and at most 1 MiB")
    try:
        methodology_text = methodology.decode("utf-8")
    except UnicodeDecodeError:
        _fail("operator methodology.md must be UTF-8")
    if not methodology_text.strip():
        _fail("operator methodology.md must contain non-whitespace text")


def validate_operator_directory(value: Path) -> Path:
    """Validate the external, non-symlinked token and methodology directory."""
    if not value.is_absolute():
        _fail("SOVA_OPERATOR_DIR must be an absolute path outside the repository")
    try:
        operator_directory = value.resolve(strict=True)
    except OSError:
        _fail("SOVA_OPERATOR_DIR does not exist")
    if value.is_symlink() or not operator_directory.is_dir():
        _fail("SOVA_OPERATOR_DIR must be a real directory, not a symlink")
    try:
        operator_directory.relative_to(_ROOT)
    except ValueError:
        pass
    else:
        _fail("SOVA_OPERATOR_DIR must remain outside the source repository")

    token_file = operator_directory / "service.token"
    methodology_file = operator_directory / "methodology.md"
    for path, label in (
        (token_file, "service.token"),
        (methodology_file, "methodology.md"),
    ):
        if path.is_symlink() or not path.is_file():
            _fail(f"operator {label} must be a real regular file")

    _validate_token_file(token_file)
    _validate_methodology_file(methodology_file)
    return operator_directory


def load_deployment_settings(
    options: DeploymentOptions,
    *,
    environ: Mapping[str, str] | None = None,
) -> DeploymentSettings:
    """Load CLI/environment values and validate every deployment input."""
    source = os.environ if environ is None else environ

    def required(cli_value: str | None, variable: str) -> str:
        selected = cli_value if cli_value is not None else source.get(variable)
        if selected is None or not selected.strip():
            _fail(f"{variable} is required")
        if selected != selected.strip():
            _fail(f"{variable} must not contain surrounding whitespace")
        return selected

    sova = validate_immutable_image(
        required(options.sova_image, "SOVA_IMAGE"),
        label="SOVA_IMAGE",
    )
    caddy = validate_immutable_image(
        required(options.caddy_image, "CADDY_IMAGE"),
        label="CADDY_IMAGE",
    )
    key_id = required(options.trusted_evidence_key_id, "SOVA_TRUSTED_EVIDENCE_KEY_ID")
    if _DIGEST.fullmatch(key_id) is None:
        _fail("SOVA_TRUSTED_EVIDENCE_KEY_ID must be sha256:<64 lowercase hex>")
    public_domain = validate_public_domain(required(options.domain, "SOVA_COMMUNITY_DOMAIN"))
    operator = validate_operator_directory(
        Path(required(options.operator_directory, "SOVA_OPERATOR_DIR"))
    )
    return DeploymentSettings(sova, caddy, key_id, public_domain, operator)


def resolve_docker_executable(value: str) -> str:
    """Resolve Docker to an explicit executable path before subprocess use."""
    path = Path(value)
    if path.is_absolute():
        if not path.is_file():
            _fail(f"Docker executable does not exist: {path}")
        return str(path.resolve())
    resolved = shutil.which(value)
    if resolved is None:
        _fail(f"Docker executable was not found on PATH: {value}")
    return str(Path(resolved).resolve())


def _run(
    command: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: int = 60,
) -> str:
    try:
        completed = subprocess.run(  # noqa: S603
            list(command),
            cwd=_DEPLOY_ROOT,
            env=None if environment is None else dict(environment),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail(f"command could not complete: {command[0]}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        if len(detail) > _MAX_DIAGNOSTIC_CHARACTERS:
            detail = detail[-_MAX_DIAGNOSTIC_CHARACTERS:]
        _fail(f"command failed ({command[0]}): {detail or 'no diagnostic'}")
    return completed.stdout


def compose_environment(
    settings: DeploymentSettings,
    environ: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return Compose inputs without ever loading the service token value."""
    result = dict(os.environ)
    if environ is not None:
        result.update(environ)
    result.update(
        {
            "SOVA_IMAGE": settings.sova_image,
            "CADDY_IMAGE": settings.caddy_image,
            "SOVA_TRUSTED_EVIDENCE_KEY_ID": settings.trusted_evidence_key_id,
            "SOVA_COMMUNITY_DOMAIN": settings.domain,
            "SOVA_OPERATOR_DIR": str(settings.operator_directory),
        }
    )
    return result


def validate_compose(
    settings: DeploymentSettings,
    docker: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Validate Compose syntax and its fully interpolated image set."""
    environment = compose_environment(settings, environ)
    base = [
        docker,
        "compose",
        "--project-name",
        _COMPOSE_PROJECT,
        "--file",
        str(_COMPOSE_FILE),
    ]
    _run([*base, "config", "--quiet"], environment=environment)
    image_output = _run([*base, "config", "--images"], environment=environment)
    resolved_images = {line.strip() for line in image_output.splitlines() if line.strip()}
    expected_images = {settings.sova_image, settings.caddy_image}
    if resolved_images != expected_images:
        _fail("resolved Compose image set differs from the two preflight-validated references")
    for image in resolved_images:
        validate_immutable_image(image, label="resolved Compose image")


def _verify_pulled_digest_reference(image: str, docker: str) -> None:
    output = _run(
        [docker, "image", "inspect", "--format={{json .RepoDigests}}", image],
        timeout_seconds=60,
    )
    try:
        repo_digests = json.loads(output)
    except json.JSONDecodeError:
        _fail("Docker returned malformed RepoDigests metadata")
    expected_digest = image.split("@", maxsplit=1)[1]
    if not isinstance(repo_digests, list) or not any(
        isinstance(item, str) and item.endswith("@" + expected_digest) for item in repo_digests
    ):
        _fail(f"pulled image does not expose the required digest: {image}")


def launch_compose(
    settings: DeploymentSettings,
    docker: str,
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    """Pull exact digests, verify local metadata, then launch without repulling."""
    validate_compose(settings, docker, environ=environ)
    environment = compose_environment(settings, environ)
    base = [
        docker,
        "compose",
        "--project-name",
        _COMPOSE_PROJECT,
        "--file",
        str(_COMPOSE_FILE),
    ]
    _run([*base, "pull", "--policy", "always"], environment=environment, timeout_seconds=600)
    _verify_pulled_digest_reference(settings.sova_image, docker)
    _verify_pulled_digest_reference(settings.caddy_image, docker)
    _run(
        [*base, "up", "--detach", "--wait", "--pull", "never"],
        environment=environment,
        timeout_seconds=600,
    )


def build_sova_image(
    *,
    base_image: str,
    wheel: Path,
    local_tag: str,
    docker: str,
) -> dict[str, object]:
    """Build the shipped runtime recipe and verify its non-root contract."""
    validated_base = validate_immutable_image(base_image, label="SOVA_PYTHON_IMAGE")
    validated_tag = validate_local_tag(local_tag)
    if wheel.is_symlink():
        _fail("SOVA wheel must be a regular file, not a symlink")
    try:
        resolved_wheel = wheel.resolve(strict=True)
    except OSError:
        _fail("SOVA wheel does not exist")
    if not resolved_wheel.is_file() or resolved_wheel.suffix != ".whl":
        _fail("SOVA wheel must be a regular .whl file")
    try:
        relative_wheel = resolved_wheel.relative_to(_ROOT)
    except ValueError:
        _fail("SOVA wheel must remain inside the build context")
    if relative_wheel.parent != Path("dist") or not relative_wheel.name.startswith("sova_oss-"):
        _fail("SOVA wheel must be a dist/sova_oss-*.whl release artifact")
    if not _DOCKERFILE.is_file() or not _DOCKERIGNORE.is_file():
        _fail("the shipped Dockerfile or deny-by-default ignore file is missing")

    _run(
        [
            docker,
            "build",
            "--file",
            str(_DOCKERFILE),
            "--build-arg",
            f"SOVA_PYTHON_IMAGE={validated_base}",
            "--build-arg",
            f"SOVA_WHEEL={relative_wheel.as_posix()}",
            "--tag",
            validated_tag,
            str(_ROOT),
        ],
        timeout_seconds=1200,
    )
    config_output = _run(
        [docker, "image", "inspect", "--format={{json .Config}}", validated_tag],
        timeout_seconds=60,
    )
    try:
        config = json.loads(config_output)
    except json.JSONDecodeError:
        _fail("Docker returned malformed runtime image configuration")
    expected = {
        "User": "65532:65532",
        "WorkingDir": "/var/lib/sova",
        "Entrypoint": ["sova"],
    }
    if not isinstance(config, dict) or any(
        config.get(key) != value for key, value in expected.items()
    ):
        _fail("built image violates the SOVA non-root runtime contract")
    labels = config.get("Labels")
    expected_labels = {
        "org.sova.runtime.data": "/var/lib/sova",
        "org.sova.runtime.operator": "/run/sova/operator",
    }
    if not isinstance(labels, dict) or any(
        labels.get(key) != value for key, value in expected_labels.items()
    ):
        _fail("built image is missing the SOVA runtime-data contract label")
    return {
        "artifactType": "sova.community-image-build-verification",
        "schemaVersion": "0.1.0",
        "baseImage": validated_base,
        "localTag": validated_tag,
        "runtimeUser": "65532:65532",
        "runtimeData": "/var/lib/sova",
        "digestRequiredBeforeLaunch": True,
    }


def _add_deployment_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--sova-image")
    parser.add_argument("--caddy-image")
    parser.add_argument("--trusted-evidence-key-id")
    parser.add_argument("--domain")
    parser.add_argument("--operator-dir")
    parser.add_argument("--docker", default="docker")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail-closed SOVA community image and Compose preflight",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build and inspect the shipped SOVA image recipe")
    build.add_argument("--base-image", required=True)
    build.add_argument("--wheel", type=Path, required=True)
    build.add_argument("--local-tag", required=True)
    build.add_argument("--docker", default="docker")
    check = commands.add_parser("check", help="validate inputs and resolved Compose configuration")
    _add_deployment_arguments(check)
    up = commands.add_parser("up", help="validate, pull exact digests, and launch the stack")
    _add_deployment_arguments(up)
    return parser


def _deployment_report(settings: DeploymentSettings, *, launched: bool) -> dict[str, object]:
    return {
        "artifactType": "sova.community-deployment-preflight",
        "schemaVersion": "0.1.0",
        "status": "pass",
        "launched": launched,
        "immutableImages": {
            "sova": settings.sova_image,
            "caddy": settings.caddy_image,
        },
        "trustedEvidenceKeyId": settings.trusted_evidence_key_id,
        "domain": settings.domain,
        "composeProject": _COMPOSE_PROJECT,
        "operatorDirectory": str(settings.operator_directory),
        "secretContentsReadIntoReport": False,
        "operatorInputsCopiedByBoundedInitializer": True,
        "registryOperatorMountReadOnly": True,
        "runtimeDataOwner": "65532:65532",
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Run one build, validation, or launch operation."""
    args = build_parser().parse_args(argv)
    try:
        docker = resolve_docker_executable(str(args.docker))
        if args.command == "build":
            report = build_sova_image(
                base_image=str(args.base_image),
                wheel=args.wheel,
                local_tag=str(args.local_tag),
                docker=docker,
            )
        else:
            settings = load_deployment_settings(
                DeploymentOptions(
                    sova_image=args.sova_image,
                    caddy_image=args.caddy_image,
                    trusted_evidence_key_id=args.trusted_evidence_key_id,
                    domain=args.domain,
                    operator_directory=args.operator_dir,
                )
            )
            if args.command == "up":
                launch_compose(settings, docker)
                report = _deployment_report(settings, launched=True)
            else:
                validate_compose(settings, docker)
                report = _deployment_report(settings, launched=False)
    except PreflightError as error:
        sys.stderr.write(f"COMMUNITY_PREFLIGHT=FAILED: {error}\n")
        return 2
    sys.stdout.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
