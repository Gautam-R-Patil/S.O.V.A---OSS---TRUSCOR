# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - embedded HTML/JavaScript remains directly auditable
"""Inert, self-contained visual replay rendering."""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING, Any

from sova.formats.errors import FormatError
from sova.replay.model import ReplayMode
from sova.trace import TraceReader

if TYPE_CHECKING:
    from pathlib import Path


def _safe_json(value: Any) -> str:
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def render_timeline_html(
    source: Path,
    destination: Path,
    *,
    comparison: Path | None = None,
    counterfactual: str | None = None,
) -> None:
    """Write a scrubbable offline HTML timeline that never executes trace payloads."""
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
    secondary_events: list[dict[str, Any]] = []
    if comparison is not None:
        secondary = TraceReader(comparison)
        secondary.verify()
        secondary_events = secondary.events()
    payload = {
        "mode": ReplayMode.PLAYBACK.value,
        "source": source.name,
        "comparison": None if comparison is None else comparison.name,
        "counterfactual": counterfactual,
        "events": primary.events(),
        "comparisonEvents": secondary_events,
        "warning": "Inert playback only. No recorded action is executed.",
    }
    title = html.escape(source.name)
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>SOVA replay - {title}</title><style>
:root{{color-scheme:dark;background:#07111f;color:#e9f1f8;font:15px/1.5 system-ui,sans-serif}}
body{{max-width:1120px;margin:auto;padding:28px}} h1{{font-size:1.5rem}} .warning{{color:#ffc66d}}
.controls{{display:grid;grid-template-columns:1fr auto;gap:12px;align-items:center}}
input[type=range]{{width:100%}} .filters{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
button{{background:#102942;color:#e9f1f8;border:1px solid #285073;border-radius:7px;padding:7px 11px}}
button.active{{background:#195a78}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1c2d;padding:16px;border-radius:9px}}
.meta{{color:#94afc5}} .bar{{height:4px;background:#17334d;margin:20px 0}} .event{{border-left:4px solid #4dd0e1;padding-left:14px;min-width:0}}
.panes{{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:22px}} .label{{font-size:.75rem;letter-spacing:.12em;text-transform:uppercase;color:#72d7e3}}
</style></head><body><h1>SOVA trace playback</h1><p class="warning">Inert playback only - this page never re-executes recorded actions.</p>
<p class="meta" id="meta"></p><div class="controls"><input id="scrub" type="range" min="0" value="0"><output id="position"></output></div>
<div class="filters" id="filters"></div><div class="bar"></div><div class="panes">
<section class="event"><p class="label">Original</p><h2 id="primaryKind"></h2><p class="meta" id="primaryIdentity"></p><pre id="primaryPayload"></pre></section>
<section class="event"><p class="label">Replay / comparison</p><h2 id="comparisonKind"></h2><p class="meta" id="comparisonIdentity"></p><pre id="comparisonPayload"></pre></section>
</div>
<script type="application/json" id="sova-data">{_safe_json(payload)}</script><script>
'use strict';const data=JSON.parse(document.getElementById('sova-data').textContent);let primaryEvents=data.events,comparisonEvents=data.comparisonEvents;let selected='all';
const scrub=document.getElementById('scrub'),pos=document.getElementById('position');
function families(){{return ['all',...new Set(data.events.map(e=>e.kind.split('.')[0]))]}}
function filterEvents(source){{return selected==='all'?source:source.filter(e=>e.kind.startsWith(selected+'.'))}}
function configure(){{primaryEvents=filterEvents(data.events);comparisonEvents=filterEvents(data.comparisonEvents);scrub.max=Math.max(0,primaryEvents.length-1,comparisonEvents.length-1);scrub.value=0}}
function drawFilters(){{const box=document.getElementById('filters');for(const name of families()){{const b=document.createElement('button');b.type='button';b.textContent=name;b.className=name===selected?'active':'';b.onclick=()=>{{selected=name;configure();box.replaceChildren();drawFilters();draw()}};box.appendChild(b)}}}}
function drawPanel(prefix,event,empty){{const kind=document.getElementById(prefix+'Kind'),identity=document.getElementById(prefix+'Identity'),out=document.getElementById(prefix+'Payload');if(!event){{kind.textContent=empty;identity.textContent='';out.textContent='';return}}kind.textContent=event.kind;identity.textContent=`${{event.sequence}} / ${{event.wallTime}} / ${{event.actor.name}} -> ${{event.target.name}}`;out.textContent=JSON.stringify(event.payload,null,2)}}
function draw(){{const i=Number(scrub.value);drawPanel('primary',primaryEvents[i],'No matching original event');drawPanel('comparison',comparisonEvents[i],data.comparison?'No matching comparison event':'No comparison trace selected');pos.textContent=`${{Math.min(i+1,Math.max(primaryEvents.length,comparisonEvents.length))}} / ${{Math.max(primaryEvents.length,comparisonEvents.length)}}`}}
configure();scrub.oninput=draw;document.getElementById('meta').textContent=`Mode: ${{data.mode}} / Source: ${{data.source}}${{data.comparison?' / Comparison: '+data.comparison:''}}${{data.counterfactual?' / Counterfactual: '+data.counterfactual:''}}`;drawFilters();draw();
</script></body></html>"""
    destination.write_text(document, encoding="utf-8", newline="\n")


__all__ = ["render_timeline_html"]
