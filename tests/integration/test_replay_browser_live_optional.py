# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501, TRY003 - embedded browser probes and test assertions stay local
"""Opt-in installed-Chrome acceptance for decisive visual replay."""

from __future__ import annotations

import base64
import http.client
import importlib
import json
import os
import subprocess
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

from sova.capsule import build_capsule, capsule_manifest_template
from sova.cli import main
from sova.formats import canonical_json_bytes, sha256_digest
from sova.trace import TraceWriter


class _CDPWebSocket:
    """Maintained WebSocket transport for Chrome DevTools loopback JSON."""

    def __init__(self, url: str) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "ws"
            or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.port is None
        ):
            raise AssertionError("Chrome returned a non-loopback DevTools URL")
        websocket = cast("Any", importlib.import_module("websocket"))
        try:
            self._socket = websocket.create_connection(
                url,
                timeout=10,
                origin=f"http://127.0.0.1:{parsed.port}",
                enable_multithread=False,
            )
        except Exception as error:
            raise AssertionError("Chrome rejected its loopback DevTools WebSocket") from error
        self._next_id = 1
        self._session_id: str | None = None

    def bind_session(self, session_id: str) -> None:
        """Route subsequent commands through one flattened page session."""
        assert session_id
        self._session_id = session_id

    def command(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        identifier = self._next_id
        self._next_id += 1
        envelope: dict[str, Any] = {
            "id": identifier,
            "method": method,
            "params": params or {},
        }
        if self._session_id is not None:
            envelope["sessionId"] = self._session_id
        self._socket.send(json.dumps(envelope, separators=(",", ":")))
        while True:
            payload = self._socket.recv()
            if not payload:
                raise AssertionError("Chrome closed the DevTools WebSocket")
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8")
            message = json.loads(payload)
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
        with suppress(Exception):
            self._socket.close()


def _wait_for_devtools(profile: Path) -> tuple[int, str]:
    marker = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if marker.is_file():
            try:
                lines = marker.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                # Chrome creates this marker before releasing its startup
                # write handle on Windows.  Retry within the existing bound.
                time.sleep(0.05)
                continue
            if len(lines) >= 2:
                try:
                    return int(lines[0]), lines[1]
                except ValueError:
                    pass
        time.sleep(0.05)
    raise AssertionError("installed Chrome did not expose its loopback DevTools endpoint")


def _new_page(port: int) -> str:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request("GET", "/json/list")
    response = connection.getresponse()
    payload = response.read()
    connection.close()
    assert response.status == 200
    value = json.loads(payload)
    assert isinstance(value, list)
    pages = [item for item in value if isinstance(item, dict) and item.get("type") == "page"]
    assert len(pages) == 1
    return str(pages[0]["webSocketDebuggerUrl"])


def _connect_page(port: int, browser_path: str) -> _CDPWebSocket:
    """Attach a flattened page session through Chrome's browser endpoint."""
    last_error: BaseException | None = None
    for _attempt in range(3):
        client: _CDPWebSocket | None = None
        try:
            client = _CDPWebSocket(f"ws://127.0.0.1:{port}{browser_path}")
            client.command("Browser.getVersion")
            target = client.command("Target.createTarget", {"url": "about:blank"})
            attached = client.command(
                "Target.attachToTarget",
                {"targetId": target["targetId"], "flatten": True},
            )
            client.bind_session(str(attached["sessionId"]))
            client.command("Page.enable")
            client.command("Runtime.enable")
        except Exception as error:  # noqa: BLE001 - retry Chrome startup/transport races
            last_error = error
            if client is not None:
                with suppress(Exception):
                    client.close()
            time.sleep(0.1)
        else:
            return client
    raise AssertionError("Chrome did not keep a fresh DevTools page connected") from last_error


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
            "--disable-gpu",
            "--disable-gpu-compositing",
            "--disable-gpu-sandbox",
            "--disable-sync",
            "--metrics-recording-only",
            "--mute-audio",
            "--no-default-browser-check",
            "--no-first-run",
            "--remote-allow-origins=*",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            "--use-angle=swiftshader",
            "--use-gl=angle",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    cdp: _CDPWebSocket | None = None
    try:
        port, browser_path = _wait_for_devtools(profile)
        cdp = _connect_page(port, browser_path)
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
