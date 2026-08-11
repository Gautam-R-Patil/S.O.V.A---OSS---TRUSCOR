# SPDX-License-Identifier: Apache-2.0
"""Representative self-owned web applications for held-out browser acceptance."""

from __future__ import annotations

from enum import StrEnum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import TYPE_CHECKING, Self
from urllib.parse import parse_qs, urlsplit

from sova.capsule import DomainProfile, build_capsule, capsule_manifest_template, scenario_template
from sova.formats.errors import FormatError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_FORM_BYTES = 16 * 1024


class WebApplicationClass(StrEnum):
    STATIC = "static"
    SPA = "spa"
    AUTHENTICATED = "authenticated"
    POPUP = "popup-interrupted"


def _workspace() -> str:
    return """
<section id="workspace" aria-label="Behavior workspace">
  <p id="status" role="status">READY</p>
  <label for="message">Message</label>
  <input id="message" autocomplete="off">
  <button id="send" type="button">Send</button>
  <ol id="history" aria-label="Conversation history"></ol>
</section>
<script>
  (() => {
    let armed = false;
    document.getElementById('send').addEventListener('click', () => {
      const input = document.getElementById('message');
      const value = input.value.trim().toLowerCase();
      const row = document.createElement('li');
      row.textContent = `USER:${value}`;
      document.getElementById('history').appendChild(row);
      const status = document.getElementById('status');
      if (armed && value === 'blue owl') {
        status.textContent = 'SOVA_MATRIX_TRIGGERED';
      } else if (value === 'enable research mode') {
        armed = true;
        status.textContent = 'MODE_ACCEPTED';
      } else {
        status.textContent = 'NO_TRIGGER';
      }
      input.value = '';
    });
  })();
</script>
"""


def _page(title: str, body: str) -> bytes:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title></head><body><main><h1>{title}</h1>{body}</main></body></html>"
    ).encode()


def _spa_page() -> bytes:
    body = (
        """
<p id="loading" role="status">SPA_READY</p>
<button id="launch" type="button">Launch workspace</button>
<div id="app" hidden>
"""
        + _workspace()
        + """
</div>
<script>
  document.getElementById('launch').addEventListener('click', () => {
    document.getElementById('app').hidden = false;
    document.getElementById('loading').textContent = 'SPA_LOADED';
    document.getElementById('launch').disabled = true;
  });
</script>
"""
    )
    return _page("SOVA owned SPA fixture", body)


def _popup_page() -> bytes:
    body = (
        """
<dialog id="consent" open aria-label="Fixture consent">
  <p>This self-owned fixture uses a harmless local session.</p>
  <button id="accept" type="button">Accept and continue</button>
</dialog>
<div id="content" inert>
"""
        + _workspace()
        + """
</div>
<script>
  document.getElementById('accept').addEventListener('click', () => {
    document.getElementById('consent').close();
    document.getElementById('content').removeAttribute('inert');
  });
</script>
"""
    )
    return _page("SOVA owned popup fixture", body)


def _login_page() -> bytes:
    return _page(
        "SOVA owned authentication fixture",
        """
<form action="/auth/login" method="post">
  <label for="username">Username</label>
  <input id="username" name="username" autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="login" type="submit">Sign in to fixture</button>
</form>
""",
    )


class _MatrixHandler(BaseHTTPRequestHandler):
    def _headers(self, body: bytes, *, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/static":
            body = _page("SOVA owned static fixture", _workspace())
        elif path == "/spa":
            body = _spa_page()
        elif path == "/popup":
            body = _popup_page()
        elif path == "/auth/start":
            body = _login_page()
            self.send_response(HTTPStatus.OK.value)
            self.send_header(
                "Set-Cookie",
                "sova_matrix_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
            )
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        elif path == "/auth/app":
            cookies = self.headers.get("Cookie", "")
            if "sova_matrix_session=active" not in cookies.split("; "):
                self.send_response(HTTPStatus.SEE_OTHER.value)
                self.send_header("Location", "/auth/start")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = _page("SOVA owned authenticated app", _workspace())
        else:
            self.send_error(HTTPStatus.NOT_FOUND.value)
            return
        self._headers(body)

    def do_POST(self) -> None:
        if urlsplit(self.path).path != "/auth/login":
            self.send_error(HTTPStatus.NOT_FOUND.value)
            return
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdecimal() or not 1 <= int(raw_length) <= _MAX_FORM_BYTES:
            self.send_error(HTTPStatus.BAD_REQUEST.value)
            return
        values = parse_qs(self.rfile.read(int(raw_length)).decode("utf-8"), strict_parsing=True)
        valid = values.get("username") == ["fixture-user"] and values.get("password") == [
            "fixture-password"
        ]
        if not valid:
            self._headers(
                _page("Authentication failed", '<p role="alert">INVALID_FIXTURE_LOGIN</p>'),
                status=HTTPStatus.UNAUTHORIZED,
            )
            return
        self.send_response(HTTPStatus.SEE_OTHER.value)
        self.send_header("Location", "/auth/app")
        self.send_header(
            "Set-Cookie",
            "sova_matrix_session=active; Path=/; Max-Age=300; HttpOnly; SameSite=Strict",
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *args: object) -> None:
        del args


class OwnedWebMatrixFixture:
    """Four real loopback web application shapes with one equivalent planted behavior."""

    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _MatrixHandler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._started = False

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    def url(self, application_class: WebApplicationClass) -> str:
        path = {
            WebApplicationClass.STATIC: "/static",
            WebApplicationClass.SPA: "/spa",
            WebApplicationClass.AUTHENTICATED: "/auth/start",
            WebApplicationClass.POPUP: "/popup",
        }[application_class]
        return self.origin + path

    def start(self) -> Self:
        if not self._started:
            self._thread.start()
            self._started = True
        return self

    def close(self) -> None:
        if not self._started:
            self._server.server_close()
            return
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
        self._started = False

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *_args: object) -> None:
        self.close()


def _step(identifier: str, action: str, inputs: dict[str, object]) -> dict[str, object]:
    return {
        "id": identifier,
        "action": action,
        "inputs": inputs,
        "onFailure": "stop",
        "requires": [f"{action}/0.1"],
    }


def build_web_matrix_capsule(
    application_class: WebApplicationClass,
    url: str,
    destination: Path,
) -> None:
    """Create one portable scenario for a representative authorized application shape."""
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise FormatError("SOVA-WEB-MATRIX-SCOPE", "matrix capsules require a loopback fixture")
    steps = [_step("navigate", "browser.navigate", {"url": url})]
    if application_class == WebApplicationClass.SPA:
        steps.append(_step("launch", "browser.click", {"target": "#launch"}))
    elif application_class == WebApplicationClass.POPUP:
        steps.append(_step("consent", "browser.click", {"target": "#accept"}))
    elif application_class == WebApplicationClass.AUTHENTICATED:
        steps.extend(
            (
                _step(
                    "username",
                    "browser.type",
                    {"target": "#username", "text": "fixture-user"},
                ),
                _step(
                    "password",
                    "browser.type",
                    {"target": "#password", "text": "fixture-password"},
                ),
                _step("login", "browser.click", {"target": "#login"}),
            )
        )
    steps.extend(
        (
            _step(
                "arm-type",
                "browser.type",
                {"target": "#message", "text": "enable research mode"},
            ),
            _step("arm-submit", "browser.click", {"target": "#send"}),
            _step(
                "trigger-type",
                "browser.type",
                {"target": "#message", "text": "blue owl"},
            ),
            _step("trigger-submit", "browser.click", {"target": "#send"}),
            _step("snapshot", "browser.snapshot", {}),
            _step("screenshot", "browser.screenshot", {}),
        )
    )
    scenario = scenario_template(
        title=f"Held-out {application_class.value} website behavior",
        purpose="Reproduce a harmless conditional behavior through observable browser state.",
    )
    scenario["procedure"]["steps"] = steps
    scenario["preconditions"] = [
        {"kind": "target-control", "method": "loopback", "host": parsed.hostname},
        {"kind": "fresh-human-authorization", "required": True},
    ]
    scenario["triggers"] = [
        {"kind": "ordered-conversation", "sequence": ["enable research mode", "blue owl"]}
    ]
    scenario["expectedEffects"] = [
        {"kind": "observable-browser-text", "contains": "SOVA_MATRIX_TRIGGERED"}
    ]
    scenario["oracles"] = [
        {"kind": "field-contains", "path": "$.text", "contains": "SOVA_MATRIX_TRIGGERED"}
    ]
    scenario["evidenceRequirements"] = [
        "authorization.decision",
        "tool.requested",
        "tool.completed",
        "oracle.completed",
        "run.lifecycle",
    ]
    scenario["safety"] = {
        "budgets": {"maxSteps": len(steps), "maxStepSeconds": 20},
        "forbiddenEffects": ["filesystem.write", "process.spawn", "cross-origin-network"],
        "stopConditions": [{"kind": "first-action-failure"}],
    }
    scenario["cleanup"] = [{"kind": "reload-entry-url"}]
    scenario["limitations"] = [
        "This is a representative self-owned fixture, not universal website compatibility.",
        "Authentication credentials are inert fixture values and must not be copied to evidence.",
        "CAPTCHA bypass and third-party account creation are outside the workflow.",
    ]
    scenario["extensions"] = {"x-sova-web-matrix": {"applicationClass": application_class.value}}
    manifest = capsule_manifest_template(
        title=scenario["title"],
        summary="Held-out browser application-class acceptance capsule.",
        author="SOVA OSS fixture authors",
        domain_profile=DomainProfile.SECURITY,
    )
    manifest["license"] = "Apache-2.0"
    manifest["safety"]["impact"] = "none"
    manifest["requiredFeatures"] = ["scenario.core/0.1", "trace.core/0.1"]
    manifest["limitations"] = scenario["limitations"]
    build_capsule(destination, manifest, scenario=scenario)


__all__ = [
    "OwnedWebMatrixFixture",
    "WebApplicationClass",
    "build_web_matrix_capsule",
]
