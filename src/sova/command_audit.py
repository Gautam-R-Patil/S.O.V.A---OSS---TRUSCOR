# SPDX-License-Identifier: Apache-2.0
"""Command registration and test-coverage audit primitives."""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any, cast

from sova.cli import build_parser

CLI_PATH = Path(__file__).resolve().with_name("cli.py")


class AuditError(RuntimeError):
    """Machine-classifiable CLI coverage audit failure."""

    @classmethod
    def missing_handler(cls, command: str) -> AuditError:
        return cls(f"CLI leaf has no callable handler: {command}")

    @classmethod
    def missing_files(cls) -> AuditError:
        return cls("coverage JSON has no files object")

    @classmethod
    def missing_cli_lines(cls) -> AuditError:
        return cls("coverage JSON has no executed lines for src/sova/cli.py")


def command_handlers() -> dict[str, str]:
    """Return every leaf command path and registered handler name."""
    result: dict[str, str] = {}

    def visit(parser: argparse.ArgumentParser, prefix: tuple[str, ...]) -> None:
        children: dict[str, argparse.ArgumentParser] = {}
        for action in parser._actions:
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict) and all(
                isinstance(value, argparse.ArgumentParser) for value in choices.values()
            ):
                children.update(cast("dict[str, argparse.ArgumentParser]", choices))
        if children:
            for name, child in sorted(children.items()):
                visit(child, (*prefix, name))
            return
        handler = parser.get_default("handler")
        if not callable(handler):
            raise AuditError.missing_handler(" ".join(prefix))
        result[" ".join(prefix)] = str(handler.__name__)

    visit(build_parser(), ())
    return result


def function_body_lines(path: Path) -> dict[str, set[int]]:
    """Collect executable statement lines for module-level functions."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result: dict[str, set[int]] = {}
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        lines = {
            child.lineno
            for statement in node.body
            for child in ast.walk(statement)
            if isinstance(child, ast.stmt)
        }
        result[node.name] = lines
    return result


def _cli_coverage(document: dict[str, Any]) -> set[int]:
    files = document.get("files")
    if not isinstance(files, dict):
        raise AuditError.missing_files()
    for name, value in files.items():
        normalized = str(name).replace("\\", "/")
        if not normalized.endswith("src/sova/cli.py") or not isinstance(value, dict):
            continue
        executed = value.get("executed_lines")
        if not isinstance(executed, list):
            break
        return {int(line) for line in executed}
    raise AuditError.missing_cli_lines()


def audit(coverage_path: Path) -> dict[str, Any]:
    """Audit handler registration and at least one executed body line per handler."""
    document = cast("dict[str, Any]", json.loads(coverage_path.read_text(encoding="utf-8")))
    executed = _cli_coverage(document)
    bodies = function_body_lines(CLI_PATH)
    handlers = command_handlers()
    unexecuted = sorted(
        command
        for command, handler in handlers.items()
        if not (bodies.get(handler, set()) & executed)
    )
    return {
        "artifactType": "sova.cli-coverage-audit",
        "schemaVersion": "0.1.0",
        "status": "pass" if not unexecuted else "fail",
        "commandCount": len(handlers),
        "unexecutedCommands": unexecuted,
        "commands": handlers,
    }


__all__ = ["AuditError", "audit", "command_handlers", "function_body_lines"]
