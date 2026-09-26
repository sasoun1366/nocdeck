"""The command line — every door into the tool, in one file.

`nocdeck scan` finds gear, `nocdeck add` keeps it, `nocdeck watch` polls it,
`nocdeck serve` opens the dashboard, `nocdeck desktop` opens the same dashboard as
a window, and `nocdeck demo` does all of it with imaginary switches so the thing
can be seen before it is trusted. Each command prints what it did and exits
non-zero when the answer is "no", which is what makes it usable from a script.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence

from . import __version__
from . import alerts as AL
from . import discover as DI
from . import mibs, simulate
from .config import Config, config_path, db_path, home
from .model import (AlertTarget, Device, Event, STATUS_COLOUR, STATUS_ORDER, human_bps,
                    human_bytes, human_seconds, iso, now_utc, parse_iso, slug)
from .poller import Poller
from .store import Store

WIDTH = 96
BLOCKS = "▁▂▃▄▅▆▇█"


class Out:
    """Printing, in one place, so `--json` and `--quiet` are a decision made once."""

    def __init__(self, quiet: bool = False, as_json: bool = False):
        self.quiet = quiet
        self.json = as_json

    def banner(self, text: str) -> None:
        if self.quiet or self.json:
            return
        print("nocdeck %s — %s" % (__version__, text))
        print("─" * WIDTH)

    def step(self, text: str, note: str = "") -> None:
        if self.quiet or self.json:
            return
        left = "· %s" % text
        if note:
            pad = max(1, WIDTH - len(left) - len(note) - 2)
            print("%s %s%s" % (left, "·" * min(pad, 20) + " ", note))
        else:
            print(left)

    def say(self, text: str = "") -> None:
        if not self.quiet and not self.json:
            print(text)

    def warn(self, text: str) -> None:
        print("  ! %s" % text, file=sys.stderr)

    def fail(self, text: str) -> int:
        print("  ✗ %s" % text, file=sys.stderr)
        return 1

    def data(self, payload) -> None:
        if self.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def make_console_safe() -> None:
    """Let this tool draw its boxes on a console that never learnt Unicode.

    A Windows console is cp1252 or cp850 by default, and printing a `─` to one of those
    raises UnicodeEncodeError — so `nocdeck list > file.txt` would end in a traceback
    for the crime of drawing a separator. Ask for UTF-8 when the output really is a
    console (Windows 10 and later can render it), and on everything else — a pipe, a
    redirected file, a CI log — keep the encoding and never raise: an undrawable
    character becomes `?` and the command still does its job.
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is None:                              # a windowed build has no streams
            continue
        try:
            encoding = (getattr(stream, "encoding", "") or "").lower()
            if encoding and "utf" not in encoding and stream.isatty():
                stream.reconfigure(encoding="utf-8")
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def blocks(values: Sequence[float], width: int = 34) -> str:
    """A sparkline for the terminal, because a table of numbers hides the shape."""
    numbers = [value for value in values if isinstance(value, (int, float))]
    if len(numbers) < 2:
        return ""
    step = max(1, len(numbers) // width)
    sampled = numbers[::step][-width:]
    low, high = min(sampled), max(sampled)
    span = (high - low) or 1.0
    return "".join(BLOCKS[min(7, int((value - low) / span * 7))] for value in sampled)


def colour_status(status: str) -> str:
    return {"up": "up", "down": "DOWN", "degraded": "degraded", "unknown": "unknown"}.get(
        status, status)


# ------------------------------------------------------------------ open things


def open_store(args) -> Store:
    return Store(getattr(args, "db", "") or db_path())


def load_config(args) -> Config:
    config = Config.load()
    for name, attribute in (("port", "port"), ("bind", "bind"), ("interval", "interval")):
        value = getattr(args, name, None)
        if value:
            setattr(config, attribute, value)
    return config


def make_poller(store: Store, config: Config, out: Out) -> Poller:
    def on_events(events: List[Event]) -> None:
        report = AL.dispatch(store, config, events, dashboard_url(config))
        for sent in report["sent"]:
            out.step("alert sent", "%s · %s" % (sent["target"], sent["detail"]))
        for problem in report["errors"]:
            out.warn("alert failed: %s" % problem)
    return Poller(store, config, on_events=on_events)


def dashboard_url(config: Config) -> str:
    host = config.bind if config.bind not in ("0.0.0.0", "::") else "localhost"
    return "http://%s:%d" % (host, config.port)


# ------------------------------------------------------------------- commands


def cmd_scan(args) -> int:
    out = Out(args.quiet, args.json)
    config = load_config(args)
    communities = args.communities or config.communities
    out.banner("scanning for devices")
    out.step("range", " ".join(args.targets))
    out.step("communities", ", ".join(communities))

    def progress(done: int, total: int) -> None:
        if not args.quiet and not args.json:
            sys.stdout.write("\r· swept %d/%d addresses" % (done, total))
            sys.stdout.flush()

    found = DI.sweep(args.targets, communities=communities, workers=args.workers,
                     timeout=config.scan_timeout, snmp_timeout=config.snmp_timeout,
                     icmp=args.icmp, on_progress=progress)
    if not args.quiet and not args.json:
        print()
    out.step("found", "%d address(es) answered" % len(found))
    for candidate in found:
        out.say("   %-15s %-10s %-9s %-9s %s"
                % (candidate.host, candidate.kind, candidate.vendor or "?",
                   candidate.community or candidate.alive_by,
                   (candidate.name or candidate.descr)[:46]))

    if not args.json:
        store = open_store(args)
        store.set_meta("last_scan", json.dumps([row.as_dict() for row in found],
                                               ensure_ascii=False))
    if args.accept:
        return accept_scan(args, found)
    if found:
        out.say("")
        out.say("  keep them with:   nocdeck add --scan --group <group>")
    return 0


def accept_scan(args, found: Optional[List[DI.Candidate]] = None) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    if found is None:
        blob = store.meta("last_scan", "")
        if not blob:
            return out.fail("no scan has been run yet — `nocdeck scan 10.0.0.0/24` first")
        found = [DI.Candidate(**row) for row in json.loads(blob)]
    kept = 0
    for candidate in found:
        if candidate.alive_by != "snmp" and not args.include_silent:
            continue
        device = candidate.to_device(group=args.group or "", interval=args.interval)
        if args.community:
            device.community = args.community
        if store.get_device(device.key()):
            continue
        store.save_device(device)
        kept += 1
        out.step("added", "%s (%s)" % (device.name, device.host))
    out.step("inventory", "%d device(s) now" % len(store.devices()))
    return 0


def cmd_add(args) -> int:
    out = Out(args.quiet, args.json)
    if args.scan:
        return accept_scan(args)
    if not args.host:
        return out.fail("give a host: nocdeck add 10.0.0.5 --name core-sw")
    store = open_store(args)
    config = load_config(args)
    device = Device(
        name=args.name or args.host, host=args.host, kind=args.kind, group=args.group or "",
        location=args.location or "", community=args.community or "public",
        version=args.version, port=args.snmp_port, interval=args.interval,
        snmp=not args.no_snmp, ping=not args.no_ping, snmp_only=args.snmp_only,
        tcp_ports=[int(p) for p in (args.tcp or "").split(",") if p.strip().isdigit()],
        http_url=args.http or "", tags=[tag.strip() for tag in (args.tags or "").split(",")
                                        if tag.strip()],
        notes=args.notes or "")
    if args.name:
        device.id = slug(args.name)
    if store.get_device(device.key()) and not args.force:
        return out.fail("%s is already in the inventory (--force to overwrite)"
                        % device.key())
    store.save_device(device)
    out.step("added", "%s → %s (%s, %s)" % (device.name, device.host, device.kind,
                                            device.community))
    # first look, so the person sees something immediately
    poller = Poller(store, config)
    outcome = poller.poll(device, force=True)
    reading = outcome.reading
    out.step("first poll", "%s · %s" % (reading.status,
                                        reading.message or "no complaint"))
    for key, value in sorted(reading.metrics.items()):
        out.say("     %-14s %s" % (key, value))
    out.data({"device": device.as_dict(), "reading": reading.as_dict()})
    return 0


def cmd_list(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    devices = store.devices(group=args.group or "", kind=args.kind or "")
    if args.search:
        devices = [device for device in devices if device.match(args.search)]
    latest = store.last_samples([device.key() for device in devices])
    rows = []
    out.banner("%d device(s)" % len(devices))
    out.say("   %-22s %-15s %-9s %-9s %-7s %-11s %s"
            % ("name", "address", "kind", "status", "latency", "cpu / temp", "seen"))
    for device in sorted(devices, key=lambda row: (STATUS_ORDER.get(
            (latest.get(row.key()).status if latest.get(row.key()) else "unknown"), 2),
            row.name.lower())):
        reading = latest.get(device.key())
        status = reading.status if reading else "unknown"
        metrics = ""
        if reading:
            parts = []
            if reading.metric("cpu") is not None:
                parts.append("cpu %.0f%%" % reading.metric("cpu"))
            if reading.metric("temperature") is not None:
                parts.append("%.0f°C" % reading.metric("temperature"))
            metrics = " ".join(parts)
        out.say("   %-22s %-15s %-9s %-9s %-7s %-11s %s"
                % (device.name[:22], (device.address or device.host)[:15], device.kind[:9],
                   colour_status(status),
                   ("%.0f ms" % reading.latency_ms) if reading and reading.latency_ms is not None else "—",
                   metrics, (reading.at[11:19] if reading and reading.at else "never")))
        rows.append({"id": device.key(), "name": device.name, "host": device.host,
                     "status": status, "kind": device.kind,
                     "metrics": reading.metrics if reading else {}})
    out.data(rows)
    return 0


def cmd_show(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    device = store.get_device(args.device)
    if device is None:
        devices = [row for row in store.devices() if row.match(args.device)]
        if len(devices) == 1:
            device = devices[0]
        else:
            return out.fail("no device matches %r" % args.device)
    reading = store.last_sample(device.key())
    history = store.history(device.key(), "cpu", hours=args.hours)
    latency = store.history(device.key(), "latency_ms", hours=args.hours)
    interfaces = store.interfaces(device.key())
    events = store.events(hours=args.hours, device_id=device.key(), limit=15)

    out.banner("%s (%s)" % (device.name, device.key()))
    out.say("  address      %s" % (device.address or device.host))
    out.say("  kind         %s · %s" % (device.kind, device.vendor or "vendor unknown"))
    out.say("  group        %s" % (device.group or "—"))
    if reading:
        out.say("  status       %s  (seen %s)" % (reading.status, reading.at))
        out.say("  uptime       %s" % (reading.uptime_text() or "—"))
        out.say("  latency      %s" % (("%.1f ms" % reading.latency_ms)
                                       if reading.latency_ms is not None else "—"))
        if history:
            out.say("  cpu (%.0fh)   %s  %s"
                    % (args.hours, blocks([value for _t, value in history]),
                       "min %.0f max %.0f" % (min(v for _t, v in history if v is not None),
                                              max(v for _t, v in history if v is not None))
                       if any(v is not None for _t, v in history) else ""))
        if latency:
            out.say("  latency      %s" % blocks([value for _t, value in latency]))
        for key, value in sorted(reading.metrics.items()):
            if key in ("cpu", "uptime"):
                continue
            out.say("  %-12s %s" % (key, value))
        facts = {key: value for key, value in reading.facts.items()
                 if key not in ("sensors_list", "filesystems", "labels") and value}
        for key in sorted(facts):
            out.say("  %-12s %s" % (key, str(facts[key])[:80]))
    if interfaces:
        out.say("")
        out.say("  ports (%d)" % len(interfaces))
        out.say("   %-10s %-14s %-6s %-8s %-14s %-14s %s"
                % ("port", "name", "state", "speed", "in", "out", "errors"))
        for port in sorted(interfaces, key=lambda row: row.index)[:60]:
            out.say("   %-10s %-14s %-6s %-8s %-14s %-14s %d/%d"
                    % (port.name[:10], port.label()[:14], port.oper or "?",
                       ("%gM" % port.speed_mbps) if port.speed_mbps else "—",
                       human_bps(port.in_bps), human_bps(port.out_bps),
                       port.in_errors, port.out_errors))
    if events:
        out.say("")
        out.say("  recent events")
        for event in events:
            out.say("   %s  %-16s %s" % (event.at[5:16], event.kind, event.message[:110]))
    out.data({"device": device.as_dict(), "reading": reading.as_dict() if reading else None,
              "interfaces": [row.as_dict() for row in interfaces],
              "events": [event.as_dict() for event in events]})
    return 0


def cmd_remove(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    if not args.yes:
        out.warn("this deletes the device and its history — add --yes")
    if not args.yes:
        return 1
    removed = store.delete_device(args.device)
    out.step("removed" if removed else "not found", args.device)
    return 0 if removed else 1


def cmd_poll(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    config = load_config(args)
    poller = make_poller(store, config, out)
    if args.device:
        device = store.get_device(args.device)
        if device is None:
            matches = [row for row in store.devices() if row.match(args.device)]
            device = matches[0] if matches else None
        if device is None:
            return out.fail("no device matches %r" % args.device)
        devices = [device]
    else:
        devices = store.devices(enabled_only=True, group=args.group or "", kind=args.kind or "")
    out.banner("polling %d device(s)" % len(devices))
    started = time.time()
    outcomes = []
    for device in devices:
        outcome = poller.poll(device, force=True)
        outcomes.append(outcome)
        reading = outcome.reading
        note = "%s · %s" % (reading.status, reading.message or "ok")
        if reading.latency_ms is not None:
            note += " · %.0f ms" % reading.latency_ms
        out.step(device.name[:28], note)
        for event in outcome.events:
            out.say("     ↳ %s" % event.message)
        for key in ("cpu", "memory", "temperature", "disk", "battery"):
            value = reading.metric(key)
            if value is not None:
                out.say("       %-12s %.1f" % (key, value))
    counts: Dict[str, int] = {}
    for outcome in outcomes:
        counts[outcome.reading.status] = counts.get(outcome.reading.status, 0) + 1
    out.step("done in %.1fs" % (time.time() - started),
             " · ".join("%s %d" % (key, value) for key, value in sorted(counts.items())))
    out.data([outcome.as_dict() for outcome in outcomes])
    return 0


def cmd_watch(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    config = load_config(args)
    poller = make_poller(store, config, out)
    out.banner("watching %d device(s) every %ds — ctrl-c to stop"
               % (len(store.devices(enabled_only=True)), config.interval))
    cycles = 0
    try:
        while args.cycles == 0 or cycles < args.cycles:
            outcomes = poller.run_once(force=cycles == 0)
            cycles += 1
            line = "cycle %d · %d polled · %d events · %d errors" % (
                cycles, len(outcomes), sum(len(o.events) for o in outcomes),
                len([o for o in outcomes if o.error]))
            out.step(line)
            for outcome in outcomes:
                for event in outcome.events:
                    out.say("   %s  %s" % (event.kind, event.message))
            if args.cycles and cycles >= args.cycles:
                break
            time.sleep(max(1.0, min(poller.wait_seconds(), 30.0)))
    except KeyboardInterrupt:
        out.say("\nstopped.")
    out.data(poller.status())
    return 0


def cmd_serve(args) -> int:
    from . import web

    out = Out(args.quiet, args.json)
    store = open_store(args)
    config = load_config(args)
    poller = make_poller(store, config, out)
    server, _thread = web.serve(store, config, poller)
    out.banner("dashboard on %s" % dashboard_url(config))
    out.step("devices", "%d in the inventory" % len(store.devices()))
    out.step("polling", "every %d s in the background" % config.interval)
    out.say("\n  ctrl-c to stop.\n")
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        poller.stop()
        server.shutdown()
        server.server_close()
    return 0


def cmd_demo(args) -> int:
    """The whole thing, on imaginary gear: build, poll, serve."""
    from . import web

    out = Out(args.quiet, args.json)
    store = open_store(args)
    config = load_config(args)
    nodes, simulator = simulate.build_simulator(store, config, size=args.size, seed=args.seed)
    poller = Poller(store, config, client_factory=simulator.client_for,
                    prober=simulator.prober, tcp_prober=simulator.tcp_prober,
                    http_prober=simulator.http_prober)
    out.banner("demo — %d imaginary devices" % len(nodes))
    out.step("building history", "a few passes so the graphs have a shape")
    started = time.time()
    for pass_number in range(args.warmup):
        simulator.advance(60.0, elapsed=pass_number * 45.0)
        poller.run_once(force=True)
    out.step("warmed up", "%d samples · %.1fs" % (len(store.devices()) * args.warmup,
                                                  time.time() - started))

    def cycle(_outcomes) -> None:
        simulator.advance(config.interval, elapsed=time.time() - started)

    import threading

    def loop() -> None:
        """The heartbeat. One bad cycle must not end the demo — a dashboard that
        disappears is worse than one that skipped a poll."""
        while not poller._stop.is_set():                    # noqa: SLF001 — the demo owns it
            try:
                cycle([])
                outcomes = poller.run_once(force=True)
                for outcome in outcomes:
                    if outcome.error:
                        out.warn("%s: %s" % (outcome.device.name, outcome.error))
            except Exception as exc:                        # noqa: BLE001
                import traceback

                out.warn("demo cycle failed: %s" % exc)
                traceback.print_exc()
            time.sleep(max(2.0, min(config.interval, 20)))

    thread = threading.Thread(target=loop, daemon=True, name="demo-loop")
    thread.start()

    server, _server_thread = web.serve(store, config, poller)
    out.step("dashboard", dashboard_url(config))
    out.say("\n  This is imaginary equipment. Point the tool at real gear with")
    out.say("  `nocdeck scan <range>` once you have seen what it does.\n")
    out.say("  ctrl-c to stop.\n")
    if args.json:
        out.data({"devices": [row.as_dict() for row in store.devices()]})
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        poller.stop()
        server.shutdown()
        server.server_close()
    return 0


def cmd_desktop(args) -> int:
    """The same dashboard, as a window, over the same database."""
    from . import desktop as DESK

    out = Out(args.quiet, args.json)
    if not DESK.available():
        return out.fail("the desktop window needs PyQt6 — pip install PyQt6 "
                        "(reason from Qt: %s)" % (DESK.why_not() or "not installed"))
    tab = (getattr(args, "tab", "") or "").lower()
    if tab and tab not in DESK.TABS:
        out.warn("no tab called %r — the frame will show the fleet tab" % tab)
        tab = ""
    out.banner("desktop window")
    if args.shot:
        out.step("rendering one frame", args.shot)
    else:
        out.step("opening", "the window closes with ctrl-w")
    code = DESK.main(["--db", str(getattr(args, "db", "") or db_path())]
                     + (["--demo"] if args.demo else [])
                     + (["--shot", args.shot] if args.shot else [])
                     + (["--tab", tab] if tab else [])
                     + (["--size", str(args.size)] if args.size else [])
                     + ["--warmup", str(args.warmup)] + ["--seed", str(args.seed)])
    if args.shot:
        out.step("wrote", args.shot)
    return code


def cmd_events(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    events = store.events(hours=args.hours, device_id=args.device or "",
                          severity=args.severity or "", limit=args.limit)
    out.banner("%d event(s) in the last %.0fh" % (len(events), args.hours))
    for event in events:
        device = store.get_device(event.device_id)
        out.say("  %s  %-8s %-16s %s"
                % (event.at[5:16], event.severity, (device.name if device else event.device_id)[:16],
                   event.message[:110]))
    out.data([event.as_dict() for event in events])
    return 0


def cmd_summary(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    fleet = store.fleet(hours=args.hours)
    latest = store.last_samples()
    counts: Dict[str, int] = {}
    for reading in latest.values():
        counts[reading.status] = counts.get(reading.status, 0) + 1
    out.banner("fleet, last %.0f hours" % args.hours)
    out.say("  devices       %d (%d enabled)" % (fleet["devices"], fleet["enabled"]))
    out.say("  samples       %d" % fleet["samples"])
    out.say("  latency       %s" % ("%.1f ms" % fleet["latency"] if fleet["latency"] else "—"))
    out.say("  now           %s" % " · ".join("%s %d" % (key, value)
                                              for key, value in sorted(counts.items())))
    if args.table:
        out.say("")
        cmd_list(argparse.Namespace(quiet=args.quiet, json=False, db=args.db, group="",
                                    kind="", search=""))
    out.data({"fleet": fleet, "now": counts})
    return 0


def cmd_alert(args) -> int:
    out = Out(args.quiet, args.json)
    config = Config.load()
    if args.action == "list":
        out.banner("%d alert target(s)" % len(config.alert_targets))
        for line in AL.summarise_targets(config):
            out.say("  " + line)
        out.data([target.as_dict() for target in config.alert_targets])
        return 0
    if args.action == "test":
        wanted = [target for target in config.alert_targets
                  if not args.name or args.name == target.name or args.name == target.kind]
        if not wanted:
            return out.fail("no target matches %r" % (args.name or "any"))
        failures = 0
        for target in wanted:
            try:
                detail = AL.test_target(target, dashboard_url(config))
                out.step("sent", "%s → %s" % (target.name or target.kind, detail))
            except AL.AlertError as exc:
                failures += 1
                out.warn("%s: %s" % (target.name or target.kind, exc))
        return 1 if failures else 0
    if args.action == "remove":
        before = len(config.alert_targets)
        config.alert_targets = [target for target in config.alert_targets
                                if not (args.name in (target.name, target.kind))]
        config.save()
        out.step("removed", "%d → %d target(s)" % (before, len(config.alert_targets)))
        return 0
    # add
    if args.kind == "telegram":
        target = AlertTarget(kind="telegram", name=args.name or "telegram",
                             token=args.token or os.environ.get("NOCDECK_TELEGRAM_TOKEN", ""),
                             chat_id=args.chat or "")
        if not target.token or not target.chat_id:
            return out.fail("telegram needs --token and --chat")
    elif args.kind == "email":
        target = AlertTarget(kind="email", name=args.name or "email", server=args.server or "",
                             port=args.smtp_port, username=args.username or "",
                             password=args.password or "", sender=args.sender or "",
                             to=[part.strip() for part in (args.to or "").split(",") if part.strip()])
        if not target.server or not target.to:
            return out.fail("email needs --server and --to")
    elif args.kind == "webhook":
        target = AlertTarget(kind="webhook", name=args.name or "webhook", url=args.url or "",
                             method=args.method)
        if not target.url:
            return out.fail("webhook needs --url")
    else:
        return out.fail("kind must be telegram, email or webhook")
    target.min_severity = args.min_severity
    target.quiet_hours = args.quiet_hours or ""
    config.alert_targets = [row for row in config.alert_targets if row.name != target.name]
    config.alert_targets.append(target)
    path = config.save()
    out.step("saved", "%s → %s" % (target.name, path))
    if not args.no_test:
        try:
            detail = AL.test_target(target, dashboard_url(config))
            out.step("test message", detail)
        except AL.AlertError as exc:
            out.warn("the test failed: %s" % exc)
    return 0


def cmd_doctor(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    config = load_config(args)
    problems: List[str] = []
    out.banner("doctor")
    for line in config.summarise():
        out.say("  " + line)
    devices = store.devices()
    out.say("  inventory       %d device(s), %d enabled"
            % (len(devices), len([d for d in devices if d.enabled])))
    out.say("  database        %s (%.1f MB)"
            % (db_path(), store.size() / 1e6))
    latest = store.last_samples()
    if not latest and devices:
        problems.append("no device has ever been polled — run `nocdeck poll`")
    out.say("  polled          %d/%d device(s)" % (len(latest), len(devices)))
    fresh = [device for device in devices if device.snmp]
    if fresh and not any(device.community for device in fresh):
        problems.append("devices have no SNMP community set")
    v3 = [device for device in devices if device.version == "3"]
    if v3:
        out.say("  snmpv3          %d device(s) — detected, not polled" % len(v3))
    out.say("  snmp            " + ("v1 + v2c implemented; v3 reported only"))
    if not config.alert_targets:
        out.say("  alerts          none — the dashboard will know, nobody will be told")
    else:
        out.say("  alerts          %d target(s)" % len(config.alert_targets))
    if shutil_which() is None and any(device.ping and not device.snmp_only for device in devices):
        out.say("  ping            no system ping found; TCP fallback will be used")
    if problems:
        out.say("")
        for problem in problems:
            out.warn(problem)
        return 1
    out.say("")
    out.say("  all good — `nocdeck serve` opens the dashboard.")
    out.data({"config": config.to_dict(), "devices": len(devices), "problems": problems})
    return 0


def shutil_which() -> Optional[str]:
    import shutil

    return shutil.which("ping")


def cmd_export(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    payload = {"version": 1, "exported_at": iso(),
               "devices": [device.as_dict() for device in store.devices()]}
    if args.out:
        path = pathlib.Path(args.out)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        out.step("wrote", "%s (%d devices)" % (path, len(payload["devices"])))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def cmd_import(args) -> int:
    out = Out(args.quiet, args.json)
    store = open_store(args)
    path = pathlib.Path(args.file)
    if not path.exists():
        return out.fail("no such file: %s" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        return out.fail("that is not JSON: %s" % exc)
    rows = data.get("devices") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        return out.fail("expected a list of devices, or {\"devices\": [...]}")
    added, updated = store.merge_devices([Device.from_dict(row) for row in rows])
    out.step("imported", "%d added, %d updated" % (added, updated))
    return 0


def cmd_version(args) -> int:
    out = Out(getattr(args, "quiet", False), getattr(args, "json", False))
    if out.json:
        out.data({"version": __version__, "python": sys.version.split()[0],
                  "home": str(home()), "database": str(db_path())})
    else:
        print("nocdeck %s" % __version__)
        print("python  %s" % sys.version.split()[0])
        print("home    %s" % home())
        print("db      %s" % db_path())
        print("desks   %d vendors · %d standard tables · SNMP v1/v2c" %
              (len({row.vendor for row in mibs.VENDOR_METRICS if row.vendor}),
               len(mibs.standard_table_roots())))
    return 0


# ---------------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nocdeck",
        description="A network monitoring dashboard for anything with an IP address: "
                    "SNMP, ping, ports and certificates, with history, alerting and "
                    "no dependencies.")
    parser.add_argument("--version", action="version", version="nocdeck %s" % __version__)
    subs = parser.add_subparsers(dest="command")

    def shared(sub, offline=False):
        sub.add_argument("--json", action="store_true", help="machine-readable output")
        sub.add_argument("--quiet", action="store_true", help="only the result")
        sub.add_argument("--db", default="", help="database file (default: ~/.nocdeck/nocdeck.db)")
        sub.add_argument("--port", type=int, default=0)
        sub.add_argument("--bind", default="")
        sub.add_argument("--interval", type=int, default=0)

    p = subs.add_parser("scan", help="sweep a range and ask what is there")
    shared(p)
    p.add_argument("targets", nargs="+", help="10.0.0.0/24, 10.0.0.10-40, or one address")
    p.add_argument("--communities", default="", help="comma-separated (default: config)")
    p.add_argument("--accept", action="store_true", help="add everything that answered SNMP")
    p.add_argument("--include-silent", action="store_true",
                   help="with --accept: also add hosts that maybe have no SNMP")
    p.add_argument("--group", default="", help="group for --accept")
    p.add_argument("--workers", type=int, default=64)
    p.add_argument("--icmp", action="store_true", help="also try ICMP (needs privileges)")
    p.set_defaults(func=cmd_scan)

    p = subs.add_parser("add", help="add a device to the inventory")
    shared(p)
    p.add_argument("host", nargs="?", help="address or hostname")
    p.add_argument("--name", default="", help="a name a human will recognise")
    p.add_argument("--kind", default="generic",
                   choices=["generic", "switch", "router", "firewall", "server", "ap", "ups",
                            "printer", "storage", "camera"])
    p.add_argument("--group", default="")
    p.add_argument("--location", default="")
    p.add_argument("--community", default="")
    p.add_argument("--version", default="2c", choices=["1", "2c", "3"])
    p.add_argument("--snmp-port", type=int, default=161)
    p.add_argument("--no-snmp", action="store_true", help="ping it only")
    p.add_argument("--no-ping", action="store_true")
    p.add_argument("--snmp-only", action="store_true", help="do not ping it either")
    p.add_argument("--tcp", default="", help="ports to watch, e.g. 443,22")
    p.add_argument("--http", default="", help="URL to watch")
    p.add_argument("--tags", default="")
    p.add_argument("--notes", default="")
    p.add_argument("--scan", action="store_true", help="add everything the last scan found")
    p.add_argument("--include-silent", action="store_true")
    p.add_argument("--force", action="store_true", help="overwrite an existing device")
    p.set_defaults(func=cmd_add)

    p = subs.add_parser("list", help="the inventory, with the last reading")
    shared(p)
    p.add_argument("--group", default="")
    p.add_argument("--kind", default="")
    p.add_argument("--search", default="")
    p.set_defaults(func=cmd_list)

    p = subs.add_parser("show", help="one device in detail")
    shared(p)
    p.add_argument("device", help="id, name, address — anything that matches")
    p.add_argument("--hours", type=float, default=24)
    p.set_defaults(func=cmd_show)

    p = subs.add_parser("remove", help="forget a device and its history")
    shared(p)
    p.add_argument("device")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_remove)

    p = subs.add_parser("poll", help="read the devices now")
    shared(p)
    p.add_argument("device", nargs="?", help="one device (default: all that are due)")
    p.add_argument("--group", default="")
    p.add_argument("--kind", default="")
    p.set_defaults(func=cmd_poll)

    p = subs.add_parser("watch", help="poll on a loop, in the foreground")
    shared(p)
    p.add_argument("--cycles", type=int, default=0, help="0 = until ctrl-c")
    p.set_defaults(func=cmd_watch)

    p = subs.add_parser("serve", help="the web dashboard")
    shared(p)
    p.set_defaults(func=cmd_serve)

    p = subs.add_parser("demo", help="imaginary devices, real pipeline, live dashboard")
    shared(p)
    p.add_argument("--size", type=int, default=0, help="how many devices")
    p.add_argument("--warmup", type=int, default=8, help="history passes before serving")
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_demo)

    p = subs.add_parser("desktop", help="the dashboard as a window (needs PyQt6)")
    shared(p)
    p.add_argument("--demo", action="store_true", help="imaginary gear, no network")
    p.add_argument("--shot", default="", help="render one frame to a PNG and exit")
    p.add_argument("--tab", default="", help="which tab the frame shows")
    p.add_argument("--size", type=int, default=0, help="how many imaginary devices")
    p.add_argument("--warmup", type=int, default=6)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(func=cmd_desktop)

    p = subs.add_parser("events", help="what changed")
    shared(p)
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--device", default="")
    p.add_argument("--severity", default="", choices=["", "info", "warning", "critical"])
    p.add_argument("--limit", type=int, default=100)
    p.set_defaults(func=cmd_events)

    p = subs.add_parser("summary", help="the fleet in one screen")
    shared(p)
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--table", action="store_true", help="and the device table")
    p.set_defaults(func=cmd_summary)

    p = subs.add_parser("alert", help="where alerts go: telegram, email, webhook")
    shared(p)
    p.add_argument("action", choices=["add", "list", "test", "remove"])
    p.add_argument("kind", nargs="?", default="", choices=["", "telegram", "email", "webhook"])
    p.add_argument("name", nargs="?", default="")
    p.add_argument("--token", default="")
    p.add_argument("--chat", default="")
    p.add_argument("--server", default="")
    p.add_argument("--smtp-port", type=int, default=587)
    p.add_argument("--username", default="")
    p.add_argument("--password", default="")
    p.add_argument("--sender", default="")
    p.add_argument("--to", default="")
    p.add_argument("--url", default="")
    p.add_argument("--method", default="POST")
    p.add_argument("--min-severity", default="warning", choices=["info", "warning", "critical"])
    p.add_argument("--quiet-hours", default="", help="e.g. 23:00-07:00, local time")
    p.add_argument("--no-test", action="store_true")
    p.set_defaults(func=cmd_alert)

    p = subs.add_parser("doctor", help="what is missing, in plain language")
    shared(p)
    p.set_defaults(func=cmd_doctor)

    p = subs.add_parser("export", help="the inventory as JSON")
    shared(p)
    p.add_argument("--out", default="")
    p.set_defaults(func=cmd_export)

    p = subs.add_parser("import", help="read an inventory back")
    shared(p)
    p.add_argument("file")
    p.set_defaults(func=cmd_import)

    p = subs.add_parser("version", help="what this is")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    make_console_safe()
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    for name, default in (("json", False), ("quiet", False), ("db", ""), ("port", 0),
                          ("bind", ""), ("interval", 0)):
        if not hasattr(args, name):
            setattr(args, name, default)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print()
        return 130
    except BrokenPipeError:
        return 0
