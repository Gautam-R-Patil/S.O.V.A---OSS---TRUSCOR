# SPDX-License-Identifier: Apache-2.0
"""Lifecycle owner for one bounded CUA Driver service generation."""

from __future__ import annotations

import os
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from sova.mcp.protocol import StdioServerSpec

_SAFE_ENV_KEYS = (
    "APPDATA",
    "COMSPEC",
    "HOME",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "WINDIR",
)
_STARTUP_TIMEOUT_SECONDS = 30.0
_MCP_ARGV_LENGTH = 5


def _environment(spec: StdioServerSpec) -> dict[str, str]:
    environment = {key: os.environ[key] for key in _SAFE_ENV_KEYS if key in os.environ}
    environment.update(dict(spec.environment))
    return environment


@dataclass(slots=True)
class CuaDriverService:
    """Own a private CUA service and close the exact generation deterministically."""

    spec: StdioServerSpec
    process: subprocess.Popen[bytes]
    socket_name: str
    _closed: bool = False

    @classmethod
    def start(cls, spec: StdioServerSpec) -> Self:
        if (
            spec.name != "cua-driver"
            or len(spec.argv) != _MCP_ARGV_LENGTH
            or spec.argv[1:3] != ("mcp", "--socket")
            or spec.argv[4] != "--no-overlay"
        ):
            raise FormatError("SOVA-CUA-SERVICE-SPEC", "CUA MCP launch spec is malformed")
        executable = spec.argv[0]
        socket_name = spec.argv[3]
        policy = spec.environment.get("CUA_DRIVER_SESSION_POLICY_FILE")
        if not isinstance(policy, str):
            raise FormatError("SOVA-CUA-SERVICE-SPEC", "CUA bounded policy is absent")
        argv = (
            executable,
            "serve",
            "--socket",
            socket_name,
            "--no-overlay",
            "--no-permissions-gate",
            "--permission-mode",
            "bounded",
            "--session-policy",
            policy,
            "--approve-session-policy",
        )
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0
        try:
            process = subprocess.Popen(  # noqa: S603 - exact reviewed executable and argv
                argv,
                cwd=spec.cwd,
                env=_environment(spec),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=creationflags,
            )
        except OSError as error:
            raise FormatError("SOVA-CUA-SERVICE-START", "CUA service could not start") from error
        service = cls(spec, process, socket_name)
        try:
            service._wait_ready()
        except Exception:
            service.close()
            raise
        return service

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            return_code = self.process.poll()
            if return_code is not None:
                detail = ""
                if self.process.stderr is not None:
                    detail = self.process.stderr.read(4096).decode("utf-8", errors="replace")
                raise FormatError(
                    "SOVA-CUA-SERVICE-EXIT",
                    "CUA service exited before becoming ready",
                    details={"returnCode": return_code, "stderr": detail},
                )
            probe = subprocess.run(  # noqa: S603 - exact reviewed executable and argv
                (self.spec.argv[0], "status", "--socket", self.socket_name, "--json"),
                cwd=self.spec.cwd,
                env=_environment(self.spec),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                timeout=5,
                check=False,
            )
            if probe.returncode == 0:
                return
            time.sleep(0.1)
        raise FormatError("SOVA-CUA-SERVICE-TIMEOUT", "CUA service readiness timed out")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.process.poll() is None:
            with suppress(OSError, subprocess.TimeoutExpired):
                subprocess.run(  # noqa: S603 - exact reviewed executable and argv
                    (self.spec.argv[0], "stop", "--socket", self.socket_name),
                    cwd=self.spec.cwd,
                    env=_environment(self.spec),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    timeout=5,
                    check=False,
                )
                self.process.wait(timeout=5)
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.process.stderr is not None:
            self.process.stderr.close()


__all__ = ["CuaDriverService"]
