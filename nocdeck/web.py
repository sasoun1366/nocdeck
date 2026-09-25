"""The dashboard: one page that answers "what is broken right now?".

Server-rendered HTML, hand-written SVG, and a little JavaScript that swaps the grid
every `refresh_seconds`. No framework, no CDN, no build step — the page is a string
that a `http.server` hands out, which means the whole dashboard works on a machine
with nothing installed, and works the same on a TV in the NOC as in a browser tab.

Pages:

* `/` — the fleet: tiles, filters, one card per device with a sparkline
* `/device/<id>` — one device: metrics, every port, every sensor, its history
* `/events` — what changed, newest first
* `/wall` — the same fleet, huge, no chrome: for a screen on the wall
* `/api/...` — the same data as JSON, for whatever comes next
"""

from __future__ import annotations

import html
import json
import pathlib
import threading
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from . import mibs
from .model import (CLASS_THRESHOLDS, STATUS_COLOUR, STATUS_ORDER, Device, Event, Interface,
                    Reading, human_bps, human_bytes, human_seconds, now_utc, parse_iso)

CSS = """
:root{color-scheme:dark;--bg:#0b1017;--panel:#141d29;--panel2:#1a2534;--line:#22303f;
      --text:#e8eef5;--dim:#8ba0b6;--up:#3ddc84;--warn:#ffb648;--down:#ff5f56;
      --unknown:#7a8b9c;--accent:#4aa8ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
     font:15px/1.55 -apple-system,"Segoe UI",Roboto,"Noto Naskh Arabic",Tahoma,sans-serif}
a{color:var(--accent);text-decoration:none}
header{position:sticky;top:0;z-index:6;background:linear-gradient(#0e1621,#0e1621ee);
       border-bottom:1px solid var(--line);padding:12px 18px;display:flex;gap:16px;
       align-items:center;flex-wrap:wrap}
header h1{font-size:17px;margin:0;font-weight:650;letter-spacing:.2px}
header .clock{color:var(--dim);font-size:13px;margin-inline-start:auto}
.wrap{max-width:1500px;margin:0 auto;padding:18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;
       margin-bottom:16px}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.tile b{display:block;font-size:26px;font-weight:650;line-height:1.15}
.tile span{color:var(--dim);font-size:12.5px}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.filters a,.filters button{border:1px solid var(--line);background:var(--panel);color:var(--text);
       border-radius:999px;padding:6px 13px;font-size:13px;cursor:pointer}
.filters a.on{background:#1d3category;border-color:#2f5d86;background:#182a3d}
input[type=search]{background:var(--panel);border:1px solid var(--line);border-radius:999px;
       color:var(--text);padding:7px 14px;font-size:13.5px;min-width:220px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--unknown);
      border-radius:12px;padding:13px 15px;display:flex;flex-direction:column;gap:9px;
      transition:border-color .15s,transform .15s}
.card:hover{transform:translateY(-1px)}
.card.up{border-left-color:var(--up)} .card.down{border-left-color:var(--down)}
.card.degraded{border-left-color:var(--warn)} .card.unknown{border-left-color:var(--unknown)}
.card .top{display:flex;align-items:baseline;gap:8px}
.card .top b{font-size:15.5px}
.card .host{color:var(--dim);font-size:12.5px}
.card .pill{margin-inline-start:auto;font-size:11.5px;border-radius:999px;padding:2px 9px;
      background:#1b2735;color:var(--dim)}
.card .pill.up{background:#12331f;color:var(--up)} .card .pill.down{background:#3a1a1a;color:var(--down)}
.card .pill.degraded{background:#3a2c12;color:var(--warn)}
.kv{display:flex;gap:14px;flex-wrap:wrap;color:var(--dim);font-size:12.5px}
.kv b{color:var(--text);font-weight:600}
.spark{height:34px}
.tags{display:flex;gap:6px;flex-wrap:wrap}
.tag{font-size:11.5px;color:var(--dim);background:#16202c;border-radius:6px;padding:1px 7px}
.table{width:100%;border-collapse:collapse;font-size:13.5px}
.table th{text-align:left;color:var(--dim);font-weight:500;border-bottom:1px solid var(--line);
          padding:7px 8px;position:sticky;top:0;background:var(--bg)}
.table td{border-bottom:1px solid #16202b;padding:7px 8px}
.table tr:hover td{background:#131c28}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;
       padding:15px 17px;margin-bottom:16px}
.panel h2{font-size:14px;margin:0 0 12px;color:var(--dim);font-weight:600;
          text-transform:uppercase;letter-spacing:.08em}
.bar{height:7px;background:#16202b;border-radius:999px;overflow:hidden;min-width:70px}
.bar i{display:block;height:100%;background:var(--up)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.big{font-size:24px;font-weight:600}
.dim{color:var(--dim)}
.sev-critical{color:var(--down)} .sev-warning{color:var(--warn)} .sev-info{color:var(--up)}
footer{color:var(--dim);font-size:12.5px;text-align:center;padding:26px 10px 40px}
.wallgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:10px}
.wallcard{border-radius:12px;padding:14px;background:var(--panel);border:1px solid var(--line)}
.wallcard.up{background:#0f2a1c;border-color:#1d5236}
.wallcard.down{background:#2c1414;border-color:#632424}
.wallcard.degraded{background:#2b2210;border-color:#63501f}
.wallcard b{display:block;font-size:16px}
.wallcard .s{font-size:12.5px;color:var(--dim)}
button.act{background:#182a3d;border:1px solid #2f5d86;color:var(--text);border-radius:8px;
           padding:6px 12px;font-size:13px;cursor:pointer}
"""

JS = """
(function(){
  var seconds = %(refresh)d;
  function swap(url, target){
    fetch(url, {headers:{"Accept":"text/html"}})
      .then(function(r){return r.text()})
      .then(function(html){var node=document.querySelector(target); if(node){node.innerHTML=html;}})
      .catch(function(){});
  }
  function tick(){
    swap("/_cards" + location.search, "#cards");
    swap("/_summary" + location.search, "#tiles");
    swap("/_events" + location.search, "#events");
    var now = new Date();
    var el = document.getElementById("clock");
    if(el){el.textContent = now.toISOString().substr(11,8) + " UTC";}
  }
  setInterval(tick, seconds*1000);
  document.addEventListener("click", function(event){
    var button = event.target.closest("[data-poll]");
    if(!button){return}
    button.disabled = true; button.textContent = "…";
    fetch("/api/poll/" + button.getAttribute("data-poll"), {method:"POST"})
      .then(function(){return fetch("/_cards" + location.search)})
      .then(function(r){return r.text()})
      .then(function(html){var node=document.querySelector("#cards"); if(node){node.innerHTML=html;}})
      .catch(function(){})
      .finally(function(){button.disabled=false; button.textContent="بازخوانی"};
    );
  });
})();
"""


# ------------------------------------------------------------------ small pieces


def esc(text) -> str:
    return html.escape(str(text if text is not None else ""), quote=True)


def sparkline(points: Sequence[Tuple[float, Optional[float]]], width: int = 300, height: int = 34,
              colour: str = "#4aa8ff", warn: Optional[float] = None,
              crit: Optional[float] = None) -> str:
    """An inline SVG graph. No library, no canvas, no request — just a polyline.

    Missing samples (a device that was down) break the line instead of being drawn
    as zero, because a flat line at the bottom is a lie about what happened.
    """
    values = [(when, value) for when, value in points if isinstance(value, (int, float))]
    if len(values) < 2:
        return ('<svg class="spark" viewBox="0 0 %d %d" preserveAspectRatio="none">'
                '<text x="4" y="%d" fill="#5c7186" font-size="11">no history yet</text></svg>'
                % (width, height, height // 2 + 4))
    lows = min(value for _when, value in values)
    highs = max(value for _when, value in values)
    span = (highs - lows) or 1.0
    start = values[0][0]
    length = (values[-1][0] - start) or 1.0
    scale = max(highs, crit or 0, warn or 0, 1.0)

    chunks: List[List[str]] = [[]]
    for when, value in values:
        x = 2 + (when - start) / length * (width - 4)
        y = height - 3 - (value / scale) * (height - 8)
        chunks[-1].append("%.1f,%.1f" % (x, y))
    paths = []
    for chunk in chunks:
        if len(chunk) == 1:
            continue
        d = " ".join(chunk)
        paths.append('<polyline fill="none" stroke="%s" stroke-width="1.6" '
                     'stroke-linejoin="round" points="%s"/>' % (colour, d))
    lines = []
    if warn and warn <= scale:
        y = height - 3 - (warn / scale) * (height - 8)
        lines.append('<line x1="0" y1="%.1f" x2="%d" y2="%.1f" stroke="#ffb64855" '
                     'stroke-width="1" stroke-dasharray="3 3"/>' % (y, width, y))
    if crit and crit <= scale:
        y = height - 3 - (crit / scale) * (height - 8)
        lines.append('<line x1="0" y1="%.1f" x2="%d" y2="%.1f" stroke="#ff5f5655" '
                     'stroke-width="1" stroke-dasharray="3 3"/>' % (y, width, y))
    return ('<svg class="spark" viewBox="0 0 %d %d" preserveAspectRatio="none">%s%s</svg>'
            % (width, height, "".join(lines), "".join(paths)))


def gauge(value: Optional[float], warn: float, crit: float, unit: str = "",
          direction: str = "high") -> str:
    """The number, and a bar that turns amber then red — in the right direction.

    A battery at 100 % is a full bar in green; a battery at 5 % is a bar that is
    nearly empty, in red. The same function, told which way is bad.
    """
    if value is None:
        return '<span class="dim">—</span>'
    if direction == "low":
        # the scale runs downward: the red line is the *low* one
        worst = max(abs(crit), abs(warn), 1e-9)
        percent = max(0.0, min(100.0, (value / worst) * 100.0 if value > 0 else 0.0))
        colour = "#3ddc84"
        if value <= crit:
            colour = "#ff5f56"
        elif value <= warn:
            colour = "#ffb648"
    else:
        percent = max(0.0, min(100.0, (value / crit) * 100.0 if crit else value))
        colour = "#3ddc84"
        if value >= crit:
            colour = "#ff5f56"
        elif value >= warn:
            colour = "#ffb648"
    return ('<span class="mono">%s%s</span>'
            '<div class="bar"><i style="width:%.0f%%;background:%s"></i></div>'
            % (("%.1f" % value).rstrip("0").rstrip("."), unit, percent, colour))


def status_pill(status: str, text: str = "") -> str:
    return '<span class="pill %s">%s</span>' % (esc(status), esc(text or status))


def when_text(stamp: str) -> str:
    when = parse_iso(stamp)
    if not when:
        return "—"
    delta = (now_utc() - when).total_seconds()
    if delta < 90:
        return "%d s ago" % int(delta)
    if delta < 5400:
        return "%d min ago" % int(delta / 60)
    if delta < 172800:
        return "%d h ago" % int(delta / 3600)
    return when.strftime("%Y-%m-%d %H:%M")


def page(title: str, body: str, config, refresh: bool = True, nav: bool = True) -> str:
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>%(title)s</title>
<style>%(css)s</style></head><body>
<header>
  <h1>🛰 %(brand)s</h1>
  %(nav)s
  <span class="clock" id="clock">%(now)s</span>
</header>
<div class="wrap">
%(body)s
</div>
<footer>nocdeck · <a href="https://github.com/sasoun1366/nocdeck">github.com/sasoun1366/nocdeck</a>
 · <a href="/events">events</a> · <a href="/wall">wall</a> · <a href="/api/summary">api</a></footer>
<noscript><meta http-equiv="refresh" content="%(refresh)d"></noscript>
<script>%(js)s</script>
</body></html>
""" % {"title": esc(title), "css": CSS, "body": body, "brand": esc(config.title),
       "nav": ('<a href="/">fleet</a> · <a href="/events">events</a> · '
               '<a href="/wall">wall</a>') if nav else "",
       "now": now_utc().strftime("%H:%M:%S") + " UTC",
       "refresh": config.refresh_seconds if refresh else 3600,
       "js": JS % {"refresh": config.refresh_seconds} if refresh else ""}


# ----------------------------------------------------------------------- the app


class Dashboard:
    """Renders the pages, and owns nothing but a reference to the store."""

    def __init__(self, store, config, poller=None):
        self.store = store
        self.config = config
        self.poller = poller
        self.started = time.time()

    # ------------------------------------------------------------------ helpers
    def names(self) -> Dict[str, str]:
        return {device.key(): device.name for device in self.store.devices()}

    def devices(self, query: str = "", group: str = "", kind: str = "",
                status: str = "") -> List[Device]:
        found = self.store.devices(group=group, kind=kind)
        if query:
            found = [device for device in found if device.match(query)]
        if status:
            latest = self.store.last_samples([device.key() for device in found])
            found = [device for device in found
                     if (latest.get(device.key()).status if latest.get(device.key()) else "unknown")
                     == status]
        return found

    def snapshot(self, query: str = "", group: str = "", kind: str = "", status: str = ""
                 ) -> List[Dict[str, object]]:
        """Everything a card needs, in one query per table — the hot path."""
        devices = self.devices(query, group, kind, status)
        latest = self.store.last_samples([device.key() for device in devices])
        rows: List[Dict[str, object]] = []
        for device in devices:
            reading = latest.get(device.key()) or Reading(device_id=device.key())
            history = self.store.history(device.key(), "latency_ms" if device.snmp_only else "cpu",
                                         hours=24, limit=240)
            rows.append({
                "device": device, "reading": reading, "history": history,
                "uptime": self.store.uptime(device.key(), hours=24),
                "colour": STATUS_COLOUR.get(reading.status, "#7a8b9c"),
            })
        rows.sort(key=lambda row: (STATUS_ORDER.get(row["reading"].status, 2),
                                   row["device"].name.lower()))
        return rows

    # --------------------------------------------------------------------- tiles
    def tiles_html(self, query: str = "", group: str = "", kind: str = "") -> str:
        fleet = self.store.fleet(hours=24)
        devices = self.devices(query, group, kind)
        latest = self.store.last_samples([device.key() for device in devices])
        counts = {"up": 0, "degraded": 0, "down": 0, "unknown": 0}
        for row in latest.values():
            counts[row.status] = counts.get(row.status, 0) + 1
        missing = max(0, len(devices) - len(latest))
        counts["unknown"] += missing
        events = [event for event in self.store.events(hours=24, limit=500)
                  if event.severity in ("critical", "warning")]
        tiles = [
            ("devices", len(devices), "in this view"),
            ("up", counts["up"], "healthy"),
            ("degraded", counts["degraded"], "over a warning line"),
            ("down", counts["down"], "not answering"),
            ("unknown", counts["unknown"], "never polled"),
            ("events 24h", len(events), "warnings + critical"),
            ("avg latency", ("%.0f ms" % fleet["latency"]) if fleet["latency"] else "—",
             "across the fleet"),
            ("samples", fleet["samples"], "stored readings, 24 h"),
        ]
        out = ['<div class="tiles" id="tiles">']
        for label, value, note in tiles:
            colour = ""
            if label in STATUS_COLOUR:
                colour = ' style="color:%s"' % STATUS_COLOUR[label]
            out.append('<div class="tile"><b%s>%s</b><span>%s · %s</span></div>'
                       % (colour, esc(value), esc(label), esc(note)))
        out.append("</div>")
        return "".join(out)

    # --------------------------------------------------------------------- cards
    def cards_html(self, query: str = "", group: str = "", kind: str = "",
                   status: str = "") -> str:
        rows = self.snapshot(query, group, kind, status)
        if not rows:
            return ('<div class="panel"><b>هیچ دستگاهی اینجا نیست.</b>'
                    '<p class="dim">Add one: <span class="mono">nocdeck scan 192.168.1.0/24</span>, '
                    'then <span class="mono">nocdeck add --scan</span>. Or start the demo: '
                    '<span class="mono">nocdeck demo</span>.</p></div>')
        out = ['<div class="grid" id="cards">']
        for row in rows:
            out.append(self.card_html(row))
        out.append("</div>")
        return "".join(out)

    def card_html(self, row: Dict[str, object]) -> str:
        device: Device = row["device"]           # type: ignore[assignment]
        reading: Reading = row["reading"]        # type: ignore[assignment]
        status = reading.status
        limits = device.limits()
        metrics = []
        for key, label in (("cpu", "CPU"), ("memory", "RAM"), ("temperature", "Temp"),
                           ("disk", "Disk"), ("battery", "Battery")):
            value = reading.metric(key)
            if value is None:
                continue
            pair = limits.limits(key) or (100, 100)
            unit = {"temperature": "°C"}.get(key, "%")
            metrics.append('<span>%s %s</span>' % (esc(label),
                                                   gauge(value, pair[0], pair[1], unit,
                                                         limits.direction(key))))
        down_ports = [port for port in self.store.interfaces(device.key())
                      if port.oper == "down" and port.admin == "up"]
        bits = [
            '<div class="top"><b><a href="/device/%s">%s</a></b>'
            '<span class="host mono">%s</span>%s</div>'
            % (esc(device.key()), esc(device.name), esc(device.address or device.host),
               status_pill(status)),
            '<div class="tags">%s%s%s</div>' % (
                '<span class="tag">%s</span>' % esc(device.kind),
                '<span class="tag">%s</span>' % esc(device.vendor) if device.vendor else "",
                "".join('<span class="tag">%s</span>' % esc(tag) for tag in device.tags[:3])),
            '<div class="kv">%s</div>' % "".join(metrics) if metrics else
            '<div class="kv dim">no health counters answered — SNMP may be off or read-only</div>',
            sparkline(row["history"], colour=str(row["colour"])),
            '<div class="kv"><span>%s</span><span>%.1f%% up (24h)</span>%s%s</div>'
            % ("%.0f ms" % reading.latency_ms if reading.latency_ms is not None else "no latency",
               float(row["uptime"]["percent"]),                      # type: ignore[index]
               '<span>%s</span>' % esc(human_seconds(reading.uptime_seconds()))
               if reading.uptime_seconds() else "",
               '<span>%d port(s) down</span>' % len(down_ports) if down_ports else ""),
            '<div class="kv"><span>%s</span><button class="act" data-poll="%s">بازخوانی</button></div>'
            % (esc("seen " + when_text(reading.at) if reading.at else "never polled"),
               esc(device.key())),
        ]
        return '<div class="card %s">%s</div>' % (esc(status), "".join(bits))

    # -------------------------------------------------------------------- events
    def events_html(self, hours: float = 48, severity: str = "", device_id: str = "",
                    limit: int = 60) -> str:
        events = self.store.events(hours=hours, severity=severity, device_id=device_id,
                                   limit=limit)
        if not events:
            return '<div class="panel dim">هیچ رویدادی در این بازه نیست. / no events in this window.</div>'
        names = self.names()
        rows = []
        for event in events:
            rows.append(
                '<tr><td class="mono dim">%s</td><td class="sev-%s">%s</td>'
                '<td><a href="/device/%s">%s</a></td><td>%s</td><td class="dim">%s</td></tr>'
                % (esc(parse_iso(event.at).strftime("%m-%d %H:%M") if parse_iso(event.at) else "?"),
                   esc(event.severity), esc(event.kind), esc(event.device_id),
                   esc(names.get(event.device_id, event.device_id)), esc(event.message),
                   esc(event.subject)))
        return ('<div class="panel" id="events"><h2>رویدادها / events</h2>'
                '<table class="table"><thead><tr><th>when (UTC)</th><th>severity</th>'
                '<th>device</th><th>what</th><th>subject</th></tr></thead><tbody>%s</tbody>'
                '</table></div>' % "".join(rows))

    # --------------------------------------------------------------------- fleet
    def index(self, query: str = "", group: str = "", kind: str = "", status: str = "",
              hours: float = 48) -> str:
        chips = []
        for label, value in (("all", ""), ("up", "up"), ("degraded", "degraded"),
                             ("down", "down"), ("unknown", "unknown")):
            url = "?%s" % urllib.parse.urlencode({k: v for k, v in
                                                  (("q", query), ("group", group), ("kind", kind),
                                                   ("status", value)) if v})
            chips.append('<a href="%s" class="%s">%s</a>'
                         % (esc(url), "on" if status == value else "", esc(label)))
        groups = sorted({device.group for device in self.store.devices() if device.group})
        for name in groups:
            url = "?%s" % urllib.parse.urlencode({k: v for k, v in
                                                  (("q", query), ("group", name),
                                                   ("kind", kind), ("status", status)) if v})
            chips.append('<a href="%s" class="%s">#%s</a>'
                         % (esc(url), "on" if group == name else "", esc(name)))
        kinds = sorted({device.kind for device in self.store.devices() if device.kind})
        for name in kinds:
            url = "?%s" % urllib.parse.urlencode({k: v for k, v in
                                                  (("q", query), ("group", group),
                                                   ("kind", name), ("status", status)) if v})
            chips.append('<a href="%s" class="%s">%s</a>'
                         % (esc(url), "on" if kind == name else "", esc(name)))
        body = [
            self.tiles_html(query, group, kind),
            '<form class="filters" method="get" action="/">',
            '<input type="search" name="q" placeholder="search name, ip, vendor…" value="%s">'
            % esc(query),
            '<button type="submit">جست‌وجو / search</button>',
            "".join(chips),
            "</form>",
            self.cards_html(query, group, kind, status),
            self.events_html(hours=hours, limit=25),
        ]
        return page("nocdeck — fleet", "".join(body), self.config)

    def detail(self, device_id: str, hours: float = 24) -> Optional[str]:
        device = self.store.get_device(device_id)
        if not device:
            return None
        reading = self.store.last_sample(device_id) or Reading(device_id=device_id)
        limits = device.limits()
        interfaces = self.store.interfaces(device_id)
        history = self.store.history(device_id, "cpu", hours=hours, limit=800)
        latency = self.store.history(device_id, "latency_ms", hours=hours, limit=800)
        memory = self.store.history(device_id, "memory", hours=hours, limit=800)
        temperature = self.store.history(device_id, "temperature", hours=hours, limit=800)
        uptime = self.store.uptime(device_id, hours=hours)
        sensors = reading.facts.get("sensors_list") or []
        filesystems = reading.facts.get("filesystems") or []
        facts = reading.facts

        top = ['<div class="panel">',
               '<div class="top"><span class="big">%s</span> %s</div>'
               % (esc(device.name), status_pill(reading.status)),
               '<div class="kv"><span class="mono">%s</span><span>%s</span><span>%s</span>'
               '<span>%s</span></div>'
               % (esc(device.address or device.host), esc(device.kind),
                  esc(device.vendor or "vendor unknown"), esc("seen " + when_text(reading.at))),
               '<div class="kv"><span>uptime <b>%s</b></span><span>latency <b>%s</b></span>'
               '<span>loss <b>%s</b></span><span>availability <b>%.1f%%</b></span></div>'
               % (esc(reading.uptime_text() or "—"),
                  "%.0f ms" % reading.latency_ms if reading.latency_ms is not None else "—",
                  "%.0f%%" % reading.loss if reading.loss is not None else "—",
                  float(uptime["percent"])),
               '<div class="kv">%s</div>' % "".join(
                   '<span class="tag">%s</span>' % esc(str(value)[:120])
                   for value in [facts.get("descr", ""), facts.get("object_id", ""),
                                 facts.get("location", ""), facts.get("contact", ""),
                                 ("%s ports" % facts.get("interfaces")) if facts.get("interfaces") else "",
                                 ("PoE %s W" % facts.get("poe_watts")) if facts.get("poe_watts") else "",
                                 ("%s processes" % facts.get("processes")) if facts.get("processes") else ""]
                   if value),
               '<div class="kv"><button class="act" data-poll="%s">بازخوانی / poll now</button></div>'
               % esc(device.key()),
               "</div>"]

        metrics_html = []
        for key in mibs.CANONICAL:
            value = reading.metric(key)
            if value is None:
                continue
            label = (reading.facts.get("labels") or {}).get(key) or key
            pair = limits.limits(key) or (100, 100)
            unit = {"temperature": "°C", "voltage": "V", "power": "W", "fan": "rpm",
                    "optical": "dBm", "runtime": "min", "uptime": "s"}.get(key, "%")
            metrics_html.append(
                '<tr><td>%s</td><td class="mono">%s</td><td style="width:120px">%s</td></tr>'
                % (esc(label), esc(("%.2f" % value).rstrip("0").rstrip(".") + unit),
                   gauge(value, pair[0], pair[1], direction=limits.direction(key))))
        if metrics_html:
            top.append('<div class="panel"><h2>سلامت / health</h2><table class="table">%s</table></div>'
                       % "".join(metrics_html))

        graphs = []
        for label, points, colour, pair in (
                ("CPU %", history, "#4aa8ff", limits.limits("cpu")),
                ("RAM %", memory, "#a78bfa", limits.limits("memory")),
                ("latency ms", latency, "#3ddc84", limits.limits("latency_ms")),
                ("temperature °C", temperature, "#ffb648", limits.limits("temperature"))):
            if points:
                graphs.append('<div class="panel"><h2>%s</h2>%s</div>'
                              % (esc(label),
                                 sparkline(points, width=600, height=90, colour=colour,
                                           warn=pair[0] if pair else None,
                                           crit=pair[1] if pair else None)))
        if graphs:
            top.append("".join(graphs))

        if interfaces:
            rows = []
            for port in interfaces:
                colour = "#3ddc84" if port.up() else ("#ff5f56" if port.admin == "up"
                                                      else "#5c7186")
                rows.append(
                    '<tr><td class="mono">%s</td><td>%s</td><td>%s</td>'
                    '<td style="color:%s">%s</td><td class="mono">%s</td>'
                    '<td class="mono">↓ %s</td><td style="width:90px">%s</td>'
                    '<td class="mono">↑ %s</td><td style="width:90px">%s</td>'
                    '<td class="mono">%s</td></tr>'
                    % (esc(port.name), esc(port.label()), esc(port.type or "—"), colour,
                       esc(port.oper or "?"),
                       ("%g M" % port.speed_mbps) if port.speed_mbps else "—",
                       esc(human_bps(port.in_bps)), gauge(port.in_util, 70, 90),
                       esc(human_bps(port.out_bps)), gauge(port.out_util, 70, 90),
                       esc("%d/%d err" % (port.in_errors, port.out_errors))))
            top.append('<div class="panel"><h2>پورت‌ها / interfaces — %d</h2>'
                       '<table class="table"><thead><tr><th>port</th><th>name</th><th>type</th>'
                       '<th>state</th><th>speed</th><th>in</th><th></th><th>out</th><th></th>'
                       '<th>errors</th></tr></thead><tbody>%s</tbody></table></div>'
                       % (len(interfaces), "".join(rows)))

        if sensors:
            rows = []
            for sensor in sensors:
                rows.append('<tr><td>%s</td><td>%s</td><td class="mono">%s %s</td>'
                            '<td class="dim">%s</td></tr>'
                            % (esc(sensor.get("name", "")), esc(sensor.get("metric", "")),
                               esc(sensor.get("value")), esc(sensor.get("unit", "")),
                               esc(sensor.get("status", ""))))
            top.append('<div class="panel"><h2>سنسورها / sensors — %d</h2>'
                       '<table class="table">%s</table></div>' % (len(sensors), "".join(rows)))

        if filesystems:
            rows = []
            for row in filesystems:
                rows.append('<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td>'
                            '<td style="width:140px">%s</td></tr>'
                            % (esc(row.get("name", "")),
                               esc(human_bytes(row.get("used") or 0)),
                               esc(human_bytes(row.get("total") or 0)),
                               gauge(row.get("percent"), limits.disk,
                                     limits.disk + limits.critical_bump)))
            top.append('<div class="panel"><h2>دیسک‌ها / storage</h2>'
                       '<table class="table">%s</table></div>' % "".join(rows))

        top.append(self.events_html(hours=168, device_id=device_id, limit=40))
        if device.notes:
            top.append('<div class="panel"><h2>notes</h2><pre class="mono">%s</pre></div>'
                       % esc(device.notes))
        return page("%s — nocdeck" % device.name, "".join(top), self.config)

    def wall(self) -> str:
        rows = self.snapshot()
        cards = []
        for row in rows:
            device: Device = row["device"]           # type: ignore[assignment]
            reading: Reading = row["reading"]        # type: ignore[assignment]
            metrics = " · ".join(
                "%s %s" % (key.upper() if key != "temperature" else "temp",
                           (("%.1f" % reading.metric(key)).rstrip("0").rstrip(".")))
                for key in ("cpu", "temperature", "memory")
                if reading.metric(key) is not None)
            cards.append('<div class="wallcard %s"><b>%s</b><div class="s">%s</div>'
                         '<div class="s mono">%s</div><div class="s">%s</div></div>'
                         % (esc(reading.status), esc(device.name),
                            esc(device.address or device.host), esc(metrics),
                            esc("%.0f ms" % reading.latency_ms if reading.latency_ms is not None
                                else reading.status)))
        return page("nocdeck — wall", '<div class="wallgrid">%s</div>' % "".join(cards),
                    self.config, nav=False)

    # ----------------------------------------------------------------------- api
    def api_summary(self) -> Dict[str, object]:
        fleet = self.store.fleet(hours=24)
        latest = self.store.last_samples()
        counts: Dict[str, int] = {}
        for reading in latest.values():
            counts[reading.status] = counts.get(reading.status, 0) + 1
        return {"fleet": fleet, "by_status": counts, "now": now_utc().isoformat(timespec="seconds"),
                "poller": self.poller.status() if self.poller else None}

    def api_devices(self, query: str = "", group: str = "", kind: str = "") -> List[Dict[str, object]]:
        out = []
        for row in self.snapshot(query, group, kind):
            device: Device = row["device"]           # type: ignore[assignment]
            reading: Reading = row["reading"]        # type: ignore[assignment]
            out.append({"id": device.key(), "name": device.name, "host": device.host,
                        "address": device.address, "kind": device.kind, "group": device.group,
                        "vendor": device.vendor, "status": reading.status,
                        "latency_ms": reading.latency_ms, "metrics": reading.metrics,
                        "at": reading.at, "uptime_percent": row["uptime"],
                        "ports_down": len([p for p in self.store.interfaces(device.key())
                                           if p.oper == "down" and p.admin == "up"])})
        return out

    def api_device(self, device_id: str) -> Optional[Dict[str, object]]:
        device = self.store.get_device(device_id)
        if not device:
            return None
        reading = self.store.last_sample(device_id)
        return {"device": device.as_dict(),
                "reading": reading.as_dict() if reading else None,
                "interfaces": [row.as_dict() for row in self.store.interfaces(device_id)],
                "uptime": self.store.uptime(device_id, hours=24)}

    def api_events(self, hours: float = 48, limit: int = 200) -> List[Dict[str, object]]:
        return [event.as_dict() for event in self.store.events(hours=hours, limit=limit)]


# ---------------------------------------------------------------------- server


def make_handler(dashboard: Dashboard, poll_hook: Optional[Callable[[str], object]] = None):
    """The HTTP handler, with the dashboard closed over it."""

    config = dashboard.config

    class Handler(BaseHTTPRequestHandler):
        server_version = "nocdeck/0.1"
        protocol_version = "HTTP/1.1"

        # ------------------------------------------------------------ plumbing
        def log_message(self, fmt, *args):
            if config.public_summary:
                return
            print("  %s %s" % (self.address_string(), fmt % args))

        def _send(self, body: bytes, kind: str = "text/html; charset=utf-8", code: int = 200,
                  cache: str = "no-store"):
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _html(self, text: str, code: int = 200):
            if isinstance(text, str):
                text = text.encode("utf-8")
            self._send(text, code=code)

        def _json(self, payload, code: int = 200):
            self._send(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"),
                       "application/json; charset=utf-8", code)

        def _query(self) -> Dict[str, str]:
            parsed = urllib.parse.urlparse(self.path)
            return {key: value[0] for key, value in
                    urllib.parse.parse_qs(parsed.query).items()}

        # --------------------------------------------------------------- routes
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = self._query()
            search = query.get("q", "")
            group = query.get("group", "")
            kind = query.get("kind", "")
            status = query.get("status", "")
            hours = float(query.get("hours", 48) or 48)
            try:
                if path == "/healthz":
                    return self._send(b"ok", "text/plain")
                if path == "/_cards":
                    return self._html(dashboard.cards_html(search, group, kind, status))
                if path == "/_summary":
                    return self._html(dashboard.tiles_html(search, group, kind))
                if path == "/_events":
                    return self._html(dashboard.events_html(hours=hours, limit=25))
                if path == "/api/summary":
                    return self._json(dashboard.api_summary())
                if path == "/api/devices":
                    return self._json(dashboard.api_devices(search, group, kind))
                if path == "/api/events":
                    return self._json(dashboard.api_events(hours=hours))
                if path.startswith("/api/device/"):
                    payload = dashboard.api_device(path.rsplit("/", 1)[-1])
                    return self._json(payload or {"error": "no such device"},
                                      200 if payload else 404)
                if path.startswith("/device/"):
                    body = dashboard.detail(path.rsplit("/", 1)[-1], hours=hours)
                    if body is None:
                        return self._html("<h1>404</h1><p>no such device</p>", 404)
                    return self._html(body)
                if path == "/events":
                    body = page("nocdeck — events",
                                dashboard.events_html(hours=hours, limit=300), config)
                    return self._html(body)
                if path == "/wall":
                    return self._html(dashboard.wall())
                if path == "/":
                    return self._html(dashboard.index(search, group, kind, status, hours))
                return self._html("<h1>404</h1>", 404)
            except Exception as exc:                                # noqa: BLE001
                self._html("<h1>500</h1><pre>%s</pre>" % esc(exc), 500)

        def do_POST(self):
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            if path.startswith("/api/poll/"):
                device_id = path.rsplit("/", 1)[-1]
                if poll_hook is None:
                    return self._json({"ok": False, "error": "no poller attached"}, 503)
                outcome = poll_hook(device_id)
                if outcome is None:
                    return self._json({"ok": False, "error": "no such device"}, 404)
                return self._json({"ok": True, "device": device_id,
                                   "status": outcome.reading.status,
                                   "events": [event.as_dict() for event in outcome.events]})
            if path == "/api/poll":
                return self._json({"ok": False, "error": "which device?"}, 400)
            return self._json({"ok": False, "error": "unknown endpoint"}, 404)

    return Handler


def serve(store, config, poller=None, background: bool = False) -> Tuple[ThreadingHTTPServer,
                                                                        threading.Thread]:
    """Start the dashboard. Returns the server and its thread, already running."""
    dashboard = Dashboard(store, config, poller)
    hook = (lambda device_id: poller.poll_now(device_id)) if poller else None
    server = ThreadingHTTPServer((config.bind, config.port), make_handler(dashboard, hook))
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="nocdeck-web", daemon=True)
    thread.start()
    return server, thread
