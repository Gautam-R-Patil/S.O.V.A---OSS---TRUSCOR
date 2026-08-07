# SPDX-License-Identifier: Apache-2.0
"""Self-owned loopback website with a harmless planted conditional behavior."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Self

_PAGE = b"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>SOVA owned behavior fixture</title>
</head>
<body>
  <main>
    <h1>SOVA owned behavior fixture</h1>
    <p id="status" role="status">READY</p>
    <label for="message">Message</label>
    <input id="message" autocomplete="off">
    <button id="send" type="button">Send</button>
    <ol id="history" aria-label="Conversation history"></ol>
  </main>
  <script>
    (() => {
      let armed = false;
      const input = document.getElementById('message');
      const history = document.getElementById('history');
      const status = document.getElementById('status');
      document.getElementById('send').addEventListener('click', () => {
        const value = input.value.trim().toLowerCase();
        const row = document.createElement('li');
        row.textContent = `USER:${value}`;
        history.appendChild(row);
        if (armed && value === 'blue owl') {
          status.textContent = 'SOVA_FIXTURE_TRIGGERED';
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
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'")
        self.send_header("Content-Length", str(len(_PAGE)))
        self.end_headers()
        self.wfile.write(_PAGE)

    def log_message(self, _format: str, *args: object) -> None:
        del args


class OwnedWebFixture:
    """A real HTTP target used only on loopback for end-to-end acceptance."""

    def __init__(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = Thread(target=self._server.serve_forever, daemon=True)
        self._started = False

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def url(self) -> str:
        return self.origin + "/"

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


__all__ = ["OwnedWebFixture"]
