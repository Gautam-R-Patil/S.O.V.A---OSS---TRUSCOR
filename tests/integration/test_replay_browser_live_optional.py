# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501, TRY003 - embedded browser probes and test assertions stay local
"""Opt-in installed-Chrome acceptance for decisive visual replay."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.cli import main
from sova.formats import canonical_json_bytes, sha256_digest
from sova.trace import TraceWriter


class _CDPWebSocket:
    """Tiny test-only RFC 6455 client for Chrome DevTools loopback JSON."""

    def __init__(self, url: str) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "ws"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port is None
        ):
            raise AssertionError("Chrome returned a non-loopback DevTools URL")
        self._socket = socket.create_connection(("127.0.0.1", parsed.port), timeout=10)
        self._socket.settimeout(10)
        self._buffer = b""
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {parsed.path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        self._socket.sendall(request)
        response = self._read_headers()
        assert response.startswith(b"HTTP/1.1 101")
        expected = base64.b64encode(
            hashlib.sha1(  # noqa: S324 - required RFC 6455 handshake, not security hashing
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        assert (
            f"sec-websocket-accept: {expected}".casefold() in response.decode("latin-1").casefold()
        )
        self._next_id = 1

    def _read_headers(self) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            data += self._socket.recv(4096)
        headers, self._buffer = data.split(b"\r\n\r\n", 1)
        return headers

    def _read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            block = self._socket.recv(max(4096, size - len(self._buffer)))
            if not block:
                raise AssertionError("Chrome closed the DevTools WebSocket")
            self._buffer += block
        result, self._buffer = self._buffer[:size], self._buffer[size:]
        return result

    def _send_frame(self, payload: bytes, *, opcode: int = 1) -> None:
        mask = os.urandom(4)
        length = len(payload)
        header = bytes((0x80 | opcode,))
        if length < 126:
            header += bytes((0x80 | length,))
        elif length <= 0xFFFF:
            header += bytes((0x80 | 126,)) + length.to_bytes(2, "big")
        else:
            header += bytes((0x80 | 127,)) + length.to_bytes(8, "big")
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self._socket.sendall(header + mask + masked)

    def _receive_message(self) -> bytes:
        fragments = bytearray()
        while True:
            first, second = self._read_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = int.from_bytes(self._read_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._read_exact(8), "big")
            mask = self._read_exact(4) if masked else b""
            payload = self._read_exact(length)
            if masked:
                payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
            if opcode == 0x9:
                self._send_frame(payload, opcode=0xA)
                continue
            if opcode == 0x8:
                raise AssertionError("Chrome closed the DevTools WebSocket")
            if opcode not in {0x0, 0x1}:
                continue
            fragments.extend(payload)
            if final:
                return bytes(fragments)

    def command(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        identifier = self._next_id
        self._next_id += 1
        self._send_frame(
            json.dumps(
                {"id": identifier, "method": method, "params": params or {}},
                separators=(",", ":"),
            ).encode("utf-8")
        )
        while True:
            message = json.loads(self._receive_message())
            if message.get("id") != identifier:
                continue
            if "error" in message:
                raise AssertionError(f"Chrome DevTools error: {message['error']}")
            return dict(message.get("result", {}))

    def evaluate(self, expression: str, *, await_promise: bool = False) -> Any:
        result = self.command(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": await_promise,
                "returnByValue": True,
                "userGesture": True,
            },
        )
        if "exceptionDetails" in result:
            raise AssertionError(f"Chrome JavaScript exception: {result['exceptionDetails']}")
        return result["result"].get("value")

    def close(self) -> None:
        try:
            self._send_frame(b"", opcode=0x8)
        finally:
            self._socket.close()


def _wait_for_devtools(profile: Path) -> tuple[int, str]:
    marker = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if marker.is_file():
            lines = marker.read_text(encoding="utf-8").splitlines()
            if len(lines) >= 2:
                return int(lines[0]), lines[1]
        time.sleep(0.05)
    raise AssertionError("installed Chrome did not expose its loopback DevTools endpoint")


def _new_page(port: int) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request("PUT", f"/json/new?{quote('about:blank', safe='')}")
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    assert response.status == 200
    value = json.loads(payload)
    return str(value["webSocketDebuggerUrl"])


def _poll(cdp: _CDPWebSocket, expression: str, *, timeout: float = 10) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = cdp.evaluate(expression)
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError(f"Chrome condition did not become true: {expression}")


def _record_actual_webm(cdp: _CDPWebSocket) -> bytes:
    encoded = cdp.evaluate(
        """
(async()=>{
  const canvas=document.createElement('canvas');canvas.width=320;canvas.height=180;
  const context=canvas.getContext('2d');document.body.appendChild(canvas);
  const stream=canvas.captureStream(15);const chunks=[];
  const recorder=new MediaRecorder(stream,{mimeType:'video/webm;codecs=vp8'});
  recorder.ondataavailable=event=>{if(event.data.size)chunks.push(event.data)};
  const stopped=new Promise(resolve=>recorder.onstop=resolve);recorder.start(100);
  const started=performance.now();let frame=0;
  while(performance.now()-started<3500){
    context.fillStyle=frame%2?'#07111b':'#155167';context.fillRect(0,0,320,180);
    context.fillStyle='#ffffff';context.font='28px sans-serif';
    context.fillText('SOVA decisive replay',24,82);context.fillText(String(frame++),24,126);
    await new Promise(resolve=>setTimeout(resolve,50));
  }
  recorder.stop();await stopped;stream.getTracks().forEach(track=>track.stop());
  const bytes=new Uint8Array(await new Blob(chunks,{type:'video/webm'}).arrayBuffer());
  let binary='';for(let offset=0;offset<bytes.length;offset+=8192){
    binary+=String.fromCharCode(...bytes.subarray(offset,offset+8192));
  }
  return btoa(binary);
})()
""",
        await_promise=True,
    )
    assert isinstance(encoded, str)
    media = base64.b64decode(encoded, validate=True)
    assert media.startswith(b"\x1a\x45\xdf\xa3")
    return media


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("SOVA_RUN_REAL_BROWSER") != "1",
    reason="set SOVA_RUN_REAL_BROWSER=1 for the optional installed-browser lane",
)
def test_optional_installed_chrome_opens_exact_decisive_webm_window(  # noqa: PLR0915
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    browser = Path(
        os.environ.get(
            "SOVA_BROWSER_PATH",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        )
    )
    if not browser.is_file():
        pytest.skip("installed Chrome is unavailable")
    profile = tmp_path / "chrome-profile"
    profile.mkdir()
    process = subprocess.Popen(
        [
            str(browser),
            "--headless=new",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-sync",
            "--metrics-recording-only",
            "--mute-audio",
            "--no-default-browser-check",
            "--no-first-run",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cdp: _CDPWebSocket | None = None
    try:
        port, _browser_path = _wait_for_devtools(profile)
        cdp = _CDPWebSocket(_new_page(port))
        cdp.command("Page.enable")
        cdp.command("Runtime.enable")
        media = _record_actual_webm(cdp)
        video = tmp_path / "actual-browser.webm"
        video.write_bytes(media)

        trace = tmp_path / "reproduction.sova-trace"
        writer = TraceWriter(trace)
        event_id = writer.append("oracle.completed", {"status": "pass", "results": []})
        assert event_id is not None
        writer.finalize()
        cues = {
            "artifactType": "sova.replay-cues",
            "schemaVersion": "0.1.0",
            "mediaName": video.name,
            "mediaDigest": sha256_digest(media),
            "synchronization": {
                "method": "same-host-monotonic-recorder-start-rpc-bound",
                "uncertaintyMs": "1.000",
                "frameTimestampAttested": False,
                "statement": "Installed-Chrome replay acceptance fixture.",
            },
            "cues": [
                {
                    "id": "decisive-browser",
                    "label": "Exploit confirmed",
                    "channel": "reproduction",
                    "eventId": event_id,
                    "eventKind": "oracle.completed",
                    "eventSequence": 0,
                    "oracleStatus": "pass",
                    "offsetSeconds": "1.500000",
                    "chapterOffsetSeconds": "1.600000",
                    "preRollSeconds": "0.500000",
                    "postRollSeconds": "0.750000",
                }
            ],
        }
        manifest = capsule_manifest_template(
            title="Installed Chrome decisive replay",
            summary="Synthetic real-media replay interaction fixture.",
            author="Tests",
        )
        manifest["license"] = "Apache-2.0"
        manifest["safety"]["impact"] = "none"
        capsule = tmp_path / "browser-finding.sova"
        build_capsule(
            capsule,
            manifest,
            attachments={
                video.name: media,
                "replay-cues.json": canonical_json_bytes(cues),
            },
            traces=[trace],
        )

        assert main(["replay", str(capsule), "--no-open"]) == 0
        report = json.loads(capsys.readouterr().out)
        assert report["opensAtDecisiveMoment"] is True
        replay = Path(report["destination"])
        cdp.command("Page.navigate", {"url": replay.as_uri()})
        state = _poll(
            cdp,
            """(()=>{const v=document.getElementById('sessionVideo');const b=document.getElementById('breakpoint');const s=document.querySelector('.event-dot.selected');return document.readyState==='complete'&&v&&v.readyState>=1&&!b.hidden&&s?{cue:b.dataset.cueId,event:s.dataset.eventId,current:v.currentTime,start:Number(v.dataset.decisiveStart),declaredDuration:Number(data.media.durationSeconds),intrinsicDurationFinite:Number.isFinite(v.duration),state:v.dataset.decisiveState}:null})()""",
        )
        assert state["cue"] == "decisive-browser"
        assert state["event"] == event_id
        assert state["state"] == "ready"
        assert state["declaredDuration"] > 2.25
        assert state["current"] == pytest.approx(state["start"], abs=0.2)
        assert state["start"] == pytest.approx(1.0, abs=0.001)

        cdp.evaluate("document.getElementById('playDecisive').click()")
        completed = _poll(
            cdp,
            """(()=>{const v=document.getElementById('sessionVideo');return v.dataset.decisiveState==='complete'?{paused:v.paused,current:v.currentTime,stop:Number(v.dataset.decisiveStop)}:null})()""",
            timeout=6,
        )
        assert completed["paused"] is True
        assert completed["current"] == pytest.approx(completed["stop"], abs=0.25)
        assert completed["stop"] == pytest.approx(2.25, abs=0.001)
        screenshot = base64.b64decode(
            cdp.command("Page.captureScreenshot", {"format": "png"})["data"], validate=True
        )
        assert screenshot.startswith(b"\x89PNG\r\n\x1a\n")
        (tmp_path / "decisive-replay-browser.png").write_bytes(screenshot)
    finally:
        if cdp is not None:
            cdp.close()
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
