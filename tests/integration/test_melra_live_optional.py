# SPDX-License-Identifier: Apache-2.0
"""Opt-in live conformance for the pinned public MELRA executor."""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from sova.executors import (
    ActionRequest,
    CancellationToken,
    ExecutionContext,
    OutcomeStatus,
)
from sova.mcp import MelraDirectories, MelraExecutorAdapter, StdioMCPClient, melra_stdio_spec
from sova.runtime import BrowserProfileVault, SessionBroker, SessionIdentity


class _FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/set-session":
            body = b"<!doctype html><h1>SOVA MELRA SESSION SET</h1>"
            self.send_response(200)
            self.send_header(
                "Set-Cookie",
                "SOVA_AUTH=PERSISTED; Path=/; Max-Age=3600; SameSite=Strict",
            )
        elif self.path == "/read-session":
            cookie = self.headers.get("Cookie", "ABSENT")
            body = f"<!doctype html><h1>SOVA MELRA COOKIE {cookie}</h1>".encode()
            self.send_response(200)
        else:
            body = (
                b"<!doctype html><title>SOVA MELRA fixture</title>"
                b"<main><h1>SOVA MELRA LIVE</h1><button>Inspect</button></main>"
            )
            self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _authorization() -> dict[str, str]:
    return {
        "decision": "allowed",
        "scopeDigest": "sha256:" + "1" * 64,
        "decidedBy": "sova.authorization-kernel/0.1",
    }


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_MELRA") != "1",
    reason="set SOVA_RUN_MELRA=1 with the audited MELRA source paths",
)
def test_pinned_melra_executes_browser_terminal_and_computer_probe(tmp_path: Path) -> None:
    node = Path(os.environ["SOVA_MELRA_NODE"])
    cli = Path(os.environ["SOVA_MELRA_CLI"])
    browser_value = os.environ.get("SOVA_MELRA_BROWSER")
    browser = None if browser_value is None else Path(browser_value)
    policy = tmp_path / "melra-policy.json"
    policy.write_text(
        json.dumps(
            {
                "version": "sova-live-conformance",
                "workspaceRoot": str(tmp_path.resolve()),
                "allowedCommands": ["node"],
                "allowedDomains": ["127.0.0.1"],
                "allowLocalhost": True,
                "mutations": "confirm",
                "approvalTtlMs": 300_000,
                "maxFileBytes": 1_000_000,
            }
        ),
        encoding="utf-8",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        identity = SessionIdentity(
            "melra-live-user",
            origin,
            ("sova-secret:fixture/pre-provisioned",),
            shared_state_allowed=True,
        )
        lease = SessionBroker((identity,)).lease(
            identity.id,
            agent_id="live-conformance",
            scope=("browser.navigate",),
            shared=True,
        )
        profile_vault = BrowserProfileVault(tmp_path / ".sova" / "browser-profiles")
        profile_vault.provision(
            lease.profile_handle,
            identity_id=identity.id,
            target=identity.target,
        )
        profile = profile_vault.path_for_executor(lease.profile_handle)
        spec = melra_stdio_spec(
            node_executable=node,
            cli_entrypoint=cli,
            workspace=tmp_path,
            directories=MelraDirectories(
                state=tmp_path / ".sova" / "melra",
                policy=policy,
                browser_profile=profile,
            ),
            browser_executable=browser,
        )
        context = ExecutionContext(tmp_path, _authorization())
        with StdioMCPClient(spec) as client:
            adapter = MelraExecutorAdapter(client)
            capability = adapter.execute(
                ActionRequest("capabilities", "computer.capabilities", {}, 30),
                context,
                CancellationToken(),
            )
            assert capability.status == OutcomeStatus.SUCCEEDED
            assert capability.output["providerOutput"]["platform"] == "win32"

            terminal = adapter.execute(
                ActionRequest(
                    "terminal",
                    "terminal.run",
                    {
                        "command": "node",
                        "args": ["-e", "process.stdout.write('SOVA-MELRA-LIVE')"],
                    },
                    30,
                ),
                context,
                CancellationToken(),
            )
            assert terminal.status == OutcomeStatus.SUCCEEDED
            assert terminal.output["providerApprovalDelegated"] is True
            assert terminal.output["providerOutput"]["stdout"] == "SOVA-MELRA-LIVE"

            if browser is not None:
                navigated = adapter.execute(
                    ActionRequest(
                        "browser", "browser.navigate", {"url": origin + "/set-session"}, 30
                    ),
                    context,
                    CancellationToken(),
                )
                assert navigated.status == OutcomeStatus.SUCCEEDED
                assert navigated.output["providerOutput"]["url"].startswith(origin)
                assert "SOVA MELRA SESSION SET" in navigated.output["providerOutput"]["text"]
                reused = adapter.execute(
                    ActionRequest(
                        "browser", "browser.navigate", {"url": origin + "/read-session"}, 30
                    ),
                    context,
                    CancellationToken(),
                )
                assert reused.status == OutcomeStatus.SUCCEEDED
                assert "SOVA_AUTH=PERSISTED" in reused.output["providerOutput"]["text"]
                trace_safe = profile_vault.inspect(lease.profile_handle)
                assert str(profile) not in json.dumps(trace_safe)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
