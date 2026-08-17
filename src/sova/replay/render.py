# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - embedded HTML/JavaScript remains directly auditable
"""Inert, self-contained visual replay rendering."""

from __future__ import annotations

import base64
import html
import json
from typing import TYPE_CHECKING, Any

from sova.formats import sha256_digest
from sova.formats.errors import FormatError
from sova.replay.model import ReplayMode
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path

_MAX_RENDER_EVENTS = 50_000
_MAX_MEDIA_BYTES = 128 * 1024 * 1024
_MIN_MP4_SIGNATURE_BYTES = 12


def _reviewed_media(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    if path.is_symlink():
        raise FormatError("SOVA-REPLAY-MEDIA-PATH", "replay media must not be a link")
    resolved = path.resolve()
    if not resolved.is_file():
        raise FormatError("SOVA-REPLAY-MEDIA-PATH", "replay media must be a regular file")
    media_type = {".webm": "video/webm", ".mp4": "video/mp4"}.get(resolved.suffix.casefold())
    if media_type is None:
        raise FormatError("SOVA-REPLAY-MEDIA-TYPE", "replay media must be WebM or MP4")
    size = resolved.stat().st_size
    if size <= 0 or size > _MAX_MEDIA_BYTES:
        raise FormatError(
            "SOVA-REPLAY-MEDIA-LIMIT",
            "replay media is empty or exceeds the 128 MiB local renderer budget",
        )
    with resolved.open("rb") as handle:
        data = handle.read(_MAX_MEDIA_BYTES + 1)
    if len(data) != size or len(data) > _MAX_MEDIA_BYTES:
        raise FormatError(
            "SOVA-REPLAY-MEDIA-LIMIT",
            "replay media changed during bounded rendering",
        )
    if media_type == "video/webm" and not data.startswith(b"\x1a\x45\xdf\xa3"):
        raise FormatError("SOVA-REPLAY-MEDIA-TYPE", "WebM media has no EBML signature")
    if media_type == "video/mp4" and (len(data) < _MIN_MP4_SIGNATURE_BYTES or data[4:8] != b"ftyp"):
        raise FormatError("SOVA-REPLAY-MEDIA-TYPE", "MP4 media has no ISO base signature")
    return {
        "name": resolved.name,
        "mediaType": media_type,
        "digest": sha256_digest(data),
        "dataUrl": f"data:{media_type};base64,{base64.b64encode(data).decode('ascii')}",
        "synchronization": "session-level-recording-not-event-time-attested",
    }


def _safe_json(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def replay_document(payload: dict[str, Any]) -> str:
    """Return the dependency-free replay application for already verified data.

    Recorded values are embedded as escaped JSON and are inserted into the DOM
    only through ``textContent`` or safe element properties. Nothing from a
    trace is interpreted as HTML or executable code.
    """
    title = html.escape(str(payload["source"]))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src 'self' data:; media-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<meta name="referrer" content="no-referrer"><title>SOVA Replay — {title}</title><style>
:root{{--ink:#eaf2f8;--muted:#89a1b5;--panel:#0b1724;--line:#1d3448;--cyan:#5ce1e6;--amber:#ffc66d;--red:#ff7b86;--green:#66dda5;--bg:#050b12;color-scheme:dark;background:var(--bg);color:var(--ink);font:14px/1.45 Inter,ui-sans-serif,system-ui,sans-serif}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at 20% -10%,#12314a 0,transparent 36rem),var(--bg)}}button,input,select{{font:inherit}}button,select,input[type=search]{{color:var(--ink);background:#0d2030;border:1px solid #29485f;border-radius:8px}}button{{padding:.55rem .8rem;cursor:pointer}}button:hover,button:focus-visible{{border-color:var(--cyan);outline:none}}button.active{{background:#155167;border-color:var(--cyan)}}
header{{position:sticky;top:0;z-index:9;display:flex;justify-content:space-between;gap:1rem;align-items:center;padding:1rem 1.4rem;background:rgba(5,11,18,.92);border-bottom:1px solid var(--line);backdrop-filter:blur(14px)}}.brand{{display:flex;gap:.75rem;align-items:center}}.mark{{display:grid;place-items:center;width:38px;height:38px;border:1px solid var(--cyan);border-radius:50%;color:var(--cyan);font-weight:800}}h1{{font-size:1rem;letter-spacing:.16em;margin:0}}.sub{{color:var(--muted);font-size:.78rem}}.status{{display:flex;gap:.55rem;align-items:center}}.dot{{width:8px;height:8px;border-radius:50%;background:var(--amber);box-shadow:0 0 12px currentColor}}.dot.sealed{{background:var(--green)}}
main{{max-width:1500px;margin:auto;padding:1.2rem}}.warning{{padding:.7rem 1rem;border:1px solid #5c4927;background:#211a0e;color:var(--amber);border-radius:10px}}.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:.75rem;margin:1rem 0}}.metric{{background:linear-gradient(145deg,#0d1b29,#09131e);border:1px solid var(--line);border-radius:12px;padding:.8rem 1rem}}.metric b{{display:block;font-size:1.15rem}}.metric span{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.09em}}
.visual{{margin:1rem 0;padding:1rem;background:var(--panel);border:1px solid var(--line);border-radius:12px}}.visual-head{{display:flex;justify-content:space-between;gap:1rem;align-items:center;margin-bottom:.7rem}}.visual video{{display:block;width:100%;max-height:66vh;background:#000;border-radius:9px}}.visual-note{{color:var(--amber);font-size:.78rem}}
.controls{{display:grid;grid-template-columns:auto auto minmax(180px,1fr) auto minmax(180px,320px);gap:.65rem;align-items:center;padding:1rem;background:var(--panel);border:1px solid var(--line);border-radius:12px}}#scrub{{width:100%;accent-color:var(--cyan)}}select{{padding:.5rem}}input[type=search]{{padding:.55rem .7rem;width:100%}}.filters{{display:flex;gap:.45rem;flex-wrap:wrap;margin:.8rem 0}}.filters button{{padding:.35rem .65rem;font-size:.78rem}}
.workspace{{display:grid;grid-template-columns:minmax(0,2.1fr) minmax(300px,.9fr);gap:1rem}}.tracks,.detail{{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}.tracks-head,.detail-head{{display:flex;justify-content:space-between;align-items:center;padding:.75rem 1rem;border-bottom:1px solid var(--line)}}.tracks-body{{max-height:62vh;overflow:auto}}.lane{{display:grid;grid-template-columns:150px minmax(600px,1fr);min-height:50px;border-bottom:1px solid #122638}}.lane-label{{position:sticky;left:0;z-index:2;display:flex;align-items:center;padding:.6rem .8rem;color:var(--muted);background:#091522;border-right:1px solid var(--line);overflow-wrap:anywhere}}.rail{{position:relative;margin:.55rem .8rem;background:linear-gradient(90deg,#102236,#173149);height:30px;border-radius:7px;min-width:560px}}.event-dot{{position:absolute;top:7px;translate:-50% 0;width:15px;height:15px;padding:0;border:2px solid #07111b;border-radius:50%;background:var(--cyan);box-shadow:0 0 0 1px #4a899b}}.event-dot.selected{{background:white;box-shadow:0 0 0 3px var(--cyan)}}.event-dot.redacted{{background:var(--amber)}}.event-dot.error{{background:var(--red)}}
.detail-body{{padding:1rem;max-height:62vh;overflow:auto}}.kicker{{color:var(--cyan);font-size:.75rem;letter-spacing:.12em;text-transform:uppercase}}h2{{font-size:1.15rem;margin:.35rem 0}}.meta{{color:var(--muted);overflow-wrap:anywhere}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#07111b;border:1px solid #172d40;padding:.85rem;border-radius:9px;max-height:280px;overflow:auto}}.links{{display:flex;gap:.4rem;flex-wrap:wrap}}.links button{{font-size:.72rem;padding:.28rem .5rem}}.comparison{{margin-top:1rem;padding-top:1rem;border-top:1px solid var(--line)}}.empty{{padding:2rem;color:var(--muted)}}
@media(max-width:900px){{.controls{{grid-template-columns:auto auto 1fr}}.controls input[type=search]{{grid-column:1/-1}}.workspace{{grid-template-columns:1fr}}.lane{{grid-template-columns:105px minmax(480px,1fr)}}header{{position:static}}}}
@media(prefers-reduced-motion:reduce){{*{{scroll-behavior:auto!important;transition:none!important}}}}
</style></head><body>
<header><div class="brand"><div class="mark" aria-hidden="true">S</div><div><h1>SOVA REPLAY</h1><div class="sub">observable evidence navigator</div></div></div><div class="status"><span class="dot" id="statusDot"></span><span id="statusText">loading</span></div></header>
<main><p class="warning">Inert playback only. Recorded actions, payloads, links, and tools are never executed by this page.</p>
<section class="metrics" aria-label="Trace summary"><div class="metric"><b id="eventCount">0</b><span>events</span></div><div class="metric"><b id="laneCount">0</b><span>sensor lanes</span></div><div class="metric"><b id="actorCount">0</b><span>actors</span></div><div class="metric"><b id="redactionCount">0</b><span>redactions</span></div><div class="metric"><b id="duration">0</b><span>observed span</span></div></section>
<section class="visual" id="visual" hidden><div class="visual-head"><div><b>Recorded browser session</b><div class="sub" id="mediaMeta"></div></div><span class="visual-note">Session-level visual evidence; event-time synchronization is not attested.</span></div><video id="sessionVideo" controls preload="metadata"></video></section>
<section class="controls" aria-label="Playback controls"><button id="play" type="button">▶ Play</button><select id="speed" aria-label="Playback speed"><option value="0.5">0.5x</option><option value="1" selected>1x</option><option value="2">2x</option><option value="4">4x</option><option value="8">8x</option></select><input id="scrub" type="range" min="0" value="0" aria-label="Event position"><output id="position">0 / 0</output><input id="search" type="search" maxlength="128" placeholder="Filter kind, actor, phase, target…" aria-label="Search events"></section>
<div class="filters" id="filters" aria-label="Sensor family filters"></div>
<section class="workspace"><div class="tracks"><div class="tracks-head"><b>Sensor lanes</b><span class="sub" id="sourceMeta"></span></div><div class="tracks-body" id="lanes"></div></div>
<aside class="detail"><div class="detail-head"><b>Evidence detail</b><span class="sub" id="sequence"></span></div><div class="detail-body" id="detail"><p class="empty">Select an event.</p></div></aside></section>
</main><script type="application/json" id="sova-data">{_safe_json(payload)}</script><script>
'use strict';
const data=JSON.parse(document.getElementById('sova-data').textContent);let events=[...data.events],comparison=[...data.comparisonEvents],visible=[],selectedFamily='all',selectedIndex=0,timer=null;
const byId=new Map();const scrub=document.getElementById('scrub');const play=document.getElementById('play');const search=document.getElementById('search');
function text(node,value){{document.getElementById(node).textContent=String(value)}}
function family(e){{return e.kind.split('.')[0]}}
function time(e){{return Number(e.monotonicNs)||e.sequence}}
function range(source){{if(!source.length)return [0,1];let lo=Infinity,hi=-Infinity;source.forEach(e=>{{const value=time(e);lo=Math.min(lo,value);hi=Math.max(hi,value)}});return [lo,hi===lo?lo+1:hi]}}
function pct(e,source){{const [lo,hi]=range(source);return Math.max(0,Math.min(100,(time(e)-lo)*100/(hi-lo)))}}
function duration(){{const [lo,hi]=range(events);const ns=hi-lo;return ns>1e9?(ns/1e9).toFixed(2)+' s':ns>1e6?(ns/1e6).toFixed(2)+' ms':ns+' ns'}}
function matches(e){{const q=search.value.trim().toLowerCase();return (selectedFamily==='all'||family(e)===selectedFamily)&&(!q||[e.kind,e.phase,e.actor.name,e.actor.id,e.target.name,e.target.id].some(v=>String(v).toLowerCase().includes(q)))}}
function families(){{return ['all',...new Set(events.map(family))]}}
function selectEvent(event){{const index=visible.findIndex(e=>e.id===event.id);if(index>=0){{selectedIndex=index;scrub.value=String(index);draw()}}}}
function linkButton(id){{const b=document.createElement('button');b.type='button';b.textContent=id;b.onclick=()=>{{const e=byId.get(id);if(e){{selectedFamily='all';search.value='';drawFilters();apply();selectEvent(e)}}}};return b}}
function detailBlock(event,label){{const wrap=document.createElement('section');const kick=document.createElement('div');kick.className='kicker';kick.textContent=label;const h=document.createElement('h2');h.textContent=event.kind;const meta=document.createElement('p');meta.className='meta';meta.textContent=`${{event.wallTime}} · ${{event.actor.name}} → ${{event.target.name}} · ${{event.phase}}`;const pre=document.createElement('pre');pre.textContent=JSON.stringify(event.payload,null,2);wrap.append(kick,h,meta,pre);const relations=[...(event.parents||[]),...(event.links||[]).map(x=>x.eventId).filter(Boolean)];if(relations.length){{const title=document.createElement('p');title.className='kicker';title.textContent='Recorded causal / correlation links';const links=document.createElement('div');links.className='links';relations.forEach(id=>links.appendChild(linkButton(id)));wrap.append(title,links)}}return wrap}}
function nearest(event){{if(!comparison.length)return null;const [alo,ahi]=range(events),[blo,bhi]=range(comparison),fraction=(time(event)-alo)/(ahi-alo);const target=blo+fraction*(bhi-blo);return comparison.reduce((best,item)=>Math.abs(time(item)-target)<Math.abs(time(best)-target)?item:best)}}
function drawDetail(event){{const box=document.getElementById('detail');box.replaceChildren();if(!event){{const p=document.createElement('p');p.className='empty';p.textContent='No event matches the active filters.';box.appendChild(p);return}}box.appendChild(detailBlock(event,'Original evidence'));const other=nearest(event);if(other){{const section=detailBlock(other,'Synchronized comparison');section.className='comparison';box.appendChild(section)}}}}
function drawLanes(){{const box=document.getElementById('lanes');box.replaceChildren();const groups=new Map();visible.forEach(e=>{{const key=family(e);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(e)}});for(const [name,items] of groups){{const lane=document.createElement('div');lane.className='lane';const label=document.createElement('div');label.className='lane-label';label.textContent=`${{name}} · ${{items.length}}`;const rail=document.createElement('div');rail.className='rail';items.forEach(e=>{{const b=document.createElement('button');b.type='button';b.className='event-dot'+((e.redactions||[]).length?' redacted':'')+(e.kind.startsWith('error.')?' error':'');b.style.left=pct(e,events)+'%';b.title=`${{e.sequence}} ${{e.kind}}`;b.setAttribute('aria-label',b.title);b.dataset.eventId=e.id;b.onclick=()=>selectEvent(e);rail.appendChild(b)}});lane.append(label,rail);box.appendChild(lane)}}text('laneCount',groups.size)}}
function updateSelection(){{document.querySelectorAll('.event-dot.selected').forEach(n=>n.classList.remove('selected'));const e=visible[selectedIndex];if(e){{const node=document.querySelector(`[data-event-id="${{CSS.escape(e.id)}}"]`);if(node)node.classList.add('selected')}}}}
function draw(){{if(selectedIndex>=visible.length)selectedIndex=Math.max(0,visible.length-1);const e=visible[selectedIndex];scrub.max=String(Math.max(0,visible.length-1));scrub.value=String(selectedIndex);text('position',visible.length?`${{selectedIndex+1}} / ${{visible.length}}`:'0 / 0');text('sequence',e?`sequence ${{e.sequence}}`:'');drawDetail(e);updateSelection()}}
function apply(){{visible=events.filter(matches);selectedIndex=0;drawLanes();draw()}}
function drawFilters(){{const box=document.getElementById('filters');box.replaceChildren();families().forEach(name=>{{const b=document.createElement('button');b.type='button';b.textContent=name;b.className=name===selectedFamily?'active':'';b.onclick=()=>{{selectedFamily=name;drawFilters();apply()}};box.appendChild(b)}})}}
function summary(){{events.forEach(e=>byId.set(e.id,e));text('eventCount',events.length);text('actorCount',new Set(events.map(e=>e.actor.id)).size);text('redactionCount',events.reduce((n,e)=>n+(e.redactions||[]).length,0));text('duration',duration());text('sourceMeta',`${{data.source}}${{data.comparison?' ↔ '+data.comparison:''}}`);const sealed=data.completion==='sealed';document.getElementById('statusDot').classList.toggle('sealed',sealed);text('statusText',sealed?'integrity-checked sealed trace':data.liveEndpoint?'live unsealed tail':'integrity-checked playback')}}
function loadMedia(){{if(!data.media)return;const panel=document.getElementById('visual');const video=document.getElementById('sessionVideo');panel.hidden=false;video.src=data.media.dataUrl;text('mediaMeta',`${{data.media.name}} · ${{data.media.digest}}`)}}
function stop(){{if(timer)clearInterval(timer);timer=null;play.textContent='▶ Play'}}
function start(){{stop();play.textContent='❚❚ Pause';const speed=Number(document.getElementById('speed').value);timer=setInterval(()=>{{if(selectedIndex>=visible.length-1){{stop();return}}selectedIndex+=1;draw()}},Math.max(45,650/speed))}}
play.onclick=()=>timer?stop():start();scrub.oninput=()=>{{stop();selectedIndex=Number(scrub.value);draw()}};search.oninput=apply;document.getElementById('speed').onchange=()=>{{if(timer)start()}};
function addLive(raw){{if(!raw||byId.has(raw.id))return;events.push(raw);events.sort((a,b)=>a.sequence-b.sequence);summary();drawFilters();apply()}}
if(data.liveEndpoint){{const stream=new EventSource(data.liveEndpoint);stream.addEventListener('trace-event',e=>{{try{{addLive(JSON.parse(e.data))}}catch(_error){{text('statusText','invalid live event refused')}}}});stream.addEventListener('sealed',()=>{{data.completion='sealed';summary();stream.close()}});stream.onerror=()=>{{if(data.completion!=='sealed')text('statusText','live tail reconnecting')}}}}
summary();loadMedia();drawFilters();apply();
</script></body></html>"""


def render_timeline_html(
    source: Path,
    destination: Path,
    *,
    comparison: Path | None = None,
    counterfactual: str | None = None,
    media: Path | None = None,
) -> None:
    """Write a rich offline replay application that never executes trace payloads."""
    source_paths = {source.resolve()}
    if comparison is not None:
        source_paths.add(comparison.resolve())
    if destination.resolve() in source_paths:
        raise FormatError(
            "SOVA-REPLAY-IMMUTABLE-SOURCE",
            "visual playback requires a destination separate from every source trace",
        )
    primary = TraceReader(source)
    primary.verify()
    events = primary.events()
    secondary_events: list[dict[str, Any]] = []
    if comparison is not None:
        secondary = TraceReader(comparison)
        secondary.verify()
        secondary_events = secondary.events()
    if len(events) + len(secondary_events) > _MAX_RENDER_EVENTS:
        raise FormatError(
            "SOVA-REPLAY-RENDER-LIMIT",
            "visual replay exceeds the bounded 50,000-event local renderer",
        )
    payload = {
        "mode": ReplayMode.PLAYBACK.value,
        "source": source.name,
        "comparison": None if comparison is None else comparison.name,
        "counterfactual": counterfactual,
        "events": events,
        "comparisonEvents": secondary_events,
        "completion": "sealed",
        "liveEndpoint": None,
        "warning": "Inert playback only. No recorded action is executed.",
        "media": _reviewed_media(media),
    }
    destination.write_text(replay_document(payload), encoding="utf-8", newline="\n")


__all__ = ["render_timeline_html", "replay_document"]
