"""The memory: SQLite, one file, no server.

A monitoring tool that forgets is a monitoring tool you cannot trust, so this is
the part that has to be right. Three tables carry the history:

* `devices` — the inventory, one JSON document per device (so adding a field never
  needs a migration), plus the columns that get queried (name, host, kind, group)
* `samples` — one row per poll: status, latency, loss, and the handful of metrics a
  graph is drawn from, with the rest kept in JSON beside them
* `events` — the transitions, which are what a human reads
* `interfaces` — the latest snapshot of every port (history for ports would be
  gigabytes; the rates are the interesting part and they are in `samples`)

Plus `rollups`, hourly averages, so a month-wide graph is seven hundred rows and
not four million.

SQLite is in the standard library, survives a power cut (WAL), and is the same file
on Windows, Linux and macOS — which matters, because this tool is meant to be
copied onto a server that has nothing installed.
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import Device, Event, Interface, Reading, iso, now_utc, parse_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    host         TEXT NOT NULL,
    address      TEXT DEFAULT '',
    kind         TEXT DEFAULT 'generic',
    grp          TEXT DEFAULT '',
    vendor       TEXT DEFAULT '',
    enabled      INTEGER DEFAULT 1,
    interval     INTEGER DEFAULT 60,
    json         TEXT NOT NULL,
    added_at     TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS devices_grp ON devices(grp);
CREATE INDEX IF NOT EXISTS devices_kind ON devices(kind);

CREATE TABLE IF NOT EXISTS samples (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL,
    at         TEXT NOT NULL,
    ts         REAL NOT NULL,          -- epoch seconds: every query sorts and windows on this
    status     TEXT NOT NULL,
    latency_ms REAL,
    loss       REAL,
    cpu        REAL,
    memory     REAL,
    temperature REAL,
    disk       REAL,
    uptime     REAL,
    metrics    TEXT DEFAULT '{}',
    message    TEXT DEFAULT '',
    seconds    REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS samples_device_ts ON samples(device_id, ts DESC);
CREATE INDEX IF NOT EXISTS samples_ts ON samples(ts DESC);

CREATE TABLE IF NOT EXISTS interfaces (
    device_id  TEXT NOT NULL,
    idx        INTEGER NOT NULL,
    name       TEXT DEFAULT '',
    alias      TEXT DEFAULT '',
    type       TEXT DEFAULT '',
    speed_mbps REAL DEFAULT 0,
    admin      TEXT DEFAULT '',
    oper       TEXT DEFAULT '',
    in_octets  INTEGER DEFAULT 0,
    out_octets INTEGER DEFAULT 0,
    in_bps     REAL DEFAULT 0,
    out_bps    REAL DEFAULT 0,
    in_util    REAL DEFAULT 0,
    out_util   REAL DEFAULT 0,
    in_errors  INTEGER DEFAULT 0,
    out_errors INTEGER DEFAULT 0,
    in_discards INTEGER DEFAULT 0,
    out_discards INTEGER DEFAULT 0,
    phys       TEXT DEFAULT '',
    last_change INTEGER DEFAULT 0,
    mtu        INTEGER DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (device_id, idx)
);

CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         TEXT NOT NULL,
    ts         REAL NOT NULL,
    device_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    subject    TEXT DEFAULT '',
    message    TEXT DEFAULT '',
    value      REAL,
    notified   INTEGER DEFAULT 0,
    detail     TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS events_device ON events(device_id, ts DESC);

CREATE TABLE IF NOT EXISTS rollups (
    device_id  TEXT NOT NULL,
    hour       REAL NOT NULL,          -- epoch seconds, floored to the hour
    metric     TEXT NOT NULL,
    low        REAL,
    avg        REAL,
    high       REAL,
    samples    INTEGER DEFAULT 0,
    PRIMARY KEY (device_id, hour, metric)
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

#: The metrics kept as columns, because every graph and every query uses them.
HOT_METRICS = ("cpu", "memory", "temperature", "disk", "uptime")

DEFAULT_SAMPLE_DAYS = 14
DEFAULT_EVENT_DAYS = 120
DEFAULT_ROLLUP_DAYS = 400


class Store:
    """One connection, one lock, and a schema that is created on first use.

    `sqlite3` objects cannot be shared across threads by default, and the poller is
    a thread pool; a single connection with a lock is slower on paper and completely
    correct on a bad day, which is the trade this tool wants.
    """

    def __init__(self, path: "str | pathlib.Path"):
        self.path = pathlib.Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30.0)
        self.db.row_factory = sqlite3.Row
        with self._lock:
            self.db.executescript(SCHEMA)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.commit()

    # ------------------------------------------------------------------ plumbing
    def close(self) -> None:
        with self._lock:
            self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    @contextmanager
    def _write(self):
        with self._lock:
            try:
                yield self.db
            finally:
                self.db.commit()

    def _rows(self, sql: str, args: Sequence = ()) -> List[sqlite3.Row]:
        with self._lock:
            return list(self.db.execute(sql, args).fetchall())

    def _one(self, sql: str, args: Sequence = ()):
        rows = self._rows(sql, args)
        return rows[0] if rows else None

    # ------------------------------------------------------------------- devices
    def save_device(self, device: Device) -> Device:
        if not device.id:
            device.id = device.key()
        stamp = iso()
        payload = device.to_json()
        existing = self.get_device(device.id)
        with self._write() as db:
            db.execute(
                """INSERT INTO devices (id, name, host, address, kind, grp, vendor, enabled,
                                        interval, json, added_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name, host=excluded.host, address=excluded.address,
                     kind=excluded.kind, grp=excluded.grp, vendor=excluded.vendor,
                     enabled=excluded.enabled, interval=excluded.interval,
                     json=excluded.json, updated_at=excluded.updated_at""",
                (device.id, device.name, device.host, device.address, device.kind,
                 device.group, device.vendor, 1 if device.enabled else 0, device.interval,
                 payload, existing.first_seen if existing and existing.first_seen else stamp,
                 stamp))
        return device

    def get_device(self, device_id: str) -> Optional[Device]:
        row = self._one("SELECT json FROM devices WHERE id=?", (device_id,))
        return Device.from_dict(json.loads(row["json"])) if row else None

    def devices(self, enabled_only: bool = False, group: str = "",
                kind: str = "") -> List[Device]:
        sql = "SELECT json FROM devices"
        where, args = [], []
        if enabled_only:
            where.append("enabled=1")
        if group:
            where.append("grp=?"); args.append(group)
        if kind:
            where.append("kind=?"); args.append(kind)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY name COLLATE NOCASE"
        return [Device.from_dict(json.loads(row["json"])) for row in self._rows(sql, args)]

    def delete_device(self, device_id: str) -> bool:
        with self._write() as db:
            found = db.execute("SELECT 1 FROM devices WHERE id=?", (device_id,)).fetchone()
            for table in ("devices", "samples", "interfaces", "events", "rollups"):
                column = "device_id" if table != "devices" else "id"
                db.execute("DELETE FROM %s WHERE %s=?" % (table, column), (device_id,))
        return bool(found)

    def merge_devices(self, incoming: Iterable[Device]) -> Tuple[int, int]:
        """Import: keep what exists, add what does not. Returns (added, updated)."""
        added = updated = 0
        for device in incoming:
            if not device.id:
                device.id = device.key()
            if self.get_device(device.id):
                updated += 1
            else:
                added += 1
            self.save_device(device)
        return added, updated

    # ------------------------------------------------------------------- samples
    def add_sample(self, reading: Reading) -> None:
        when = parse_iso(reading.at) or now_utc()
        metrics = {k: round(float(v), 3) for k, v in reading.metrics.items()
                   if isinstance(v, (int, float))}
        with self._write() as db:
            db.execute(
                """INSERT INTO samples (device_id, at, ts, status, latency_ms, loss, cpu,
                                       memory, temperature, disk, uptime, metrics, message,
                                       seconds)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (reading.device_id, iso(when), when.timestamp(), reading.status,
                 reading.latency_ms, reading.loss, metrics.get("cpu"), metrics.get("memory"),
                 metrics.get("temperature"), metrics.get("disk"), metrics.get("uptime"),
                 json.dumps(metrics, ensure_ascii=False), reading.message,
                 round(reading.seconds, 3)))
            db.execute("UPDATE devices SET address=?, vendor=?, updated_at=? WHERE id=?",
                       (reading.facts.get("address", ""), reading.facts.get("vendor", ""),
                        iso(when), reading.device_id))
        self._rollup(reading.device_id, when, metrics)

    def last_sample(self, device_id: str) -> Optional[Reading]:
        # Ordered by row id, not by timestamp: two polls inside the same second are a
        # real thing (a hand-triggered poll next to the scheduled one) and `ts` alone
        # would pick one of them at random.
        row = self._one("SELECT * FROM samples WHERE device_id=? ORDER BY id DESC LIMIT 1",
                        (device_id,))
        return self._reading(row) if row else None

    def last_samples(self, device_ids: Optional[Sequence[str]] = None) -> Dict[str, Reading]:
        """The newest row per device, one query — the dashboard's whole hot path."""
        where = ""
        args: Sequence = ()
        if device_ids:
            marks = ",".join("?" for _ in device_ids)
            where = "WHERE device_id IN (%s)" % marks
            args = tuple(device_ids)
        sql = ("SELECT * FROM samples WHERE id IN "
               "(SELECT MAX(id) FROM samples %s GROUP BY device_id)" % where)
        out: Dict[str, Reading] = {}
        for row in self._rows(sql, args):
            out[row["device_id"]] = self._reading(row)
        return out

    def history(self, device_id: str, metric: str = "cpu", hours: float = 24,
                limit: int = 2000) -> List[Tuple[float, Optional[float]]]:
        """`[(epoch, value)]`, oldest first — just what a sparkline needs."""
        column = metric if metric in HOT_METRICS + ("latency_ms", "loss") else None
        since = (now_utc() - timedelta(hours=hours)).timestamp()
        if column:
            rows = self._rows(
                "SELECT ts, %s AS value FROM samples WHERE device_id=? AND ts>=?"
                " ORDER BY ts ASC LIMIT ?" % column, (device_id, since, limit))
            return [(row["ts"], row["value"]) for row in rows]
        rows = self._rows("SELECT ts, metrics FROM samples WHERE device_id=? AND ts>=?"
                          " ORDER BY ts ASC LIMIT ?", (device_id, since, limit))
        out = []
        for row in rows:
            try:
                value = json.loads(row["metrics"]).get(metric)
            except ValueError:
                value = None
            out.append((row["ts"], value))
        return out

    def uptime(self, device_id: str, hours: float = 24) -> Dict[str, float]:
        """Availability over a window, from the samples themselves."""
        since = (now_utc() - timedelta(hours=hours)).timestamp()
        row = self._one("""SELECT COUNT(*) AS total,
                                  SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up,
                                  SUM(CASE WHEN status='degraded' THEN 1 ELSE 0 END) AS degraded,
                                  SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down
                           FROM samples WHERE device_id=? AND ts>=?""", (device_id, since))
        total = (row["total"] if row else 0) or 0
        if not total:
            return {"total": 0, "up": 0, "degraded": 0, "down": 0, "percent": 0.0}
        good = (row["up"] or 0) + 0.5 * (row["degraded"] or 0)
        return {"total": total, "up": row["up"] or 0, "degraded": row["degraded"] or 0,
                "down": row["down"] or 0, "percent": round(100.0 * good / total, 2)}

    def fleet(self, hours: float = 24) -> Dict[str, object]:
        """The numbers the top of the dashboard shows."""
        since = (now_utc() - timedelta(hours=hours)).timestamp()
        row = self._one("""SELECT COUNT(*) AS total,
                                  SUM(CASE WHEN status='up' THEN 1 ELSE 0 END) AS up,
                                  SUM(CASE WHEN status='degraded' THEN 1 ELSE 0 END) AS degraded,
                                  SUM(CASE WHEN status='down' THEN 1 ELSE 0 END) AS down,
                                  AVG(latency_ms) AS latency
                           FROM samples WHERE ts>=?""", (since,))
        devices = self._one("SELECT COUNT(*) AS n, SUM(enabled) AS switched_on FROM devices")
        return {"devices": devices["n"] if devices else 0,
                "enabled": (devices["switched_on"] if devices else 0) or 0,
                "samples": row["total"] if row else 0,
                "up": row["up"] if row else 0, "degraded": row["degraded"] if row else 0,
                "down": row["down"] if row else 0,
                "latency": round(row["latency"], 1) if row and row["latency"] else None,
                "since": datetime.fromtimestamp(since, timezone.utc).isoformat(timespec="seconds")}

    # ----------------------------------------------------------------- interfaces
    def save_interfaces(self, device_id: str, rows: Sequence[Interface]) -> None:
        stamp = iso()
        with self._write() as db:
            for row in rows:
                db.execute(
                    """INSERT INTO interfaces (device_id, idx, name, alias, type, speed_mbps,
                            admin, oper, in_octets, out_octets, in_bps, out_bps, in_util,
                            out_util, in_errors, out_errors, in_discards, out_discards, phys,
                            last_change, mtu, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(device_id, idx) DO UPDATE SET
                         name=excluded.name, alias=excluded.alias, type=excluded.type,
                         speed_mbps=excluded.speed_mbps, admin=excluded.admin,
                         oper=excluded.oper, in_octets=excluded.in_octets,
                         out_octets=excluded.out_octets, in_bps=excluded.in_bps,
                         out_bps=excluded.out_bps, in_util=excluded.in_util,
                         out_util=excluded.out_util, in_errors=excluded.in_errors,
                         out_errors=excluded.out_errors, in_discards=excluded.in_discards,
                         out_discards=excluded.out_discards, phys=excluded.phys,
                         last_change=excluded.last_change, mtu=excluded.mtu,
                         updated_at=excluded.updated_at""",
                    (device_id, row.index, row.name, row.alias, row.type, row.speed_mbps,
                     row.admin, row.oper, row.in_octets, row.out_octets, row.in_bps,
                     row.out_bps, row.in_util, row.out_util, row.in_errors, row.out_errors,
                     row.in_discards, row.out_discards, row.phys, row.last_change, row.mtu,
                     stamp))

    def interfaces(self, device_id: str) -> List[Interface]:
        rows = self._rows("SELECT * FROM interfaces WHERE device_id=? ORDER BY idx",
                          (device_id,))
        out: List[Interface] = []
        for row in rows:
            out.append(Interface(
                index=row["idx"], name=row["name"], alias=row["alias"], type=row["type"],
                speed_mbps=row["speed_mbps"] or 0, admin=row["admin"], oper=row["oper"],
                in_octets=row["in_octets"] or 0, out_octets=row["out_octets"] or 0,
                in_bps=row["in_bps"] or 0, out_bps=row["out_bps"] or 0,
                in_util=row["in_util"] or 0, out_util=row["out_util"] or 0,
                in_errors=row["in_errors"] or 0, out_errors=row["out_errors"] or 0,
                in_discards=row["in_discards"] or 0, out_discards=row["out_discards"] or 0,
                phys=row["phys"], last_change=row["last_change"] or 0, mtu=row["mtu"] or 0))
        return out

    # --------------------------------------------------------------------- events
    def add_event(self, event: Event) -> int:
        when = parse_iso(event.at) or now_utc()
        event.at = iso(when)
        with self._write() as db:
            cursor = db.execute(
                """INSERT INTO events (at, ts, device_id, kind, severity, subject, message,
                                       value, notified, detail)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (event.at, when.timestamp(), event.device_id, event.kind, event.severity,
                 event.subject, event.message, event.value, 1 if event.notified else 0,
                 json.dumps(event.detail, ensure_ascii=False)))
            return int(cursor.lastrowid or 0)

    def events(self, hours: float = 24, device_id: str = "", severity: str = "",
               limit: int = 200) -> List[Event]:
        since = (now_utc() - timedelta(hours=hours)).timestamp()
        sql = "SELECT * FROM events WHERE ts>=?"
        args: List = [since]
        if device_id:
            sql += " AND device_id=?"; args.append(device_id)
        if severity:
            sql += " AND severity=?"; args.append(severity)
        sql += " ORDER BY ts DESC LIMIT ?"; args.append(limit)
        return [self._event(row) for row in self._rows(sql, args)]

    def last_event(self, device_id: str, kind: str = "", subject: str = "") -> Optional[Event]:
        sql = "SELECT * FROM events WHERE device_id=?"
        args: List = [device_id]
        if kind:
            sql += " AND kind=?"; args.append(kind)
        if subject:
            sql += " AND subject=?"; args.append(subject)
        sql += " ORDER BY ts DESC LIMIT 1"
        row = self._one(sql, args)
        return self._event(row) if row else None

    def open_problem(self, device_id: str, kind: str, subject: str = "",
                     before: str = "") -> Optional[Event]:
        """Is this exact trouble still open? — the question that stops alert storms.

        `before` is the moment of the event being judged. It matters because the
        poller stores an event before it alerts about it: without this, every event
        would find itself in the table and conclude it had already been sent.
        """
        sql = """SELECT * FROM events WHERE device_id=? AND kind=?"""
        args: List = [device_id, kind]
        if subject:
            sql += " AND subject=?"; args.append(subject)
        if before:
            sql += " AND ts < ?"; args.append((parse_iso(before) or now_utc()).timestamp())
        sql += """ AND ts >= (SELECT COALESCE(MAX(ts), 0) FROM events e2
                               WHERE e2.device_id=events.device_id AND e2.kind IN (?, ?))
                  ORDER BY ts DESC LIMIT 1"""
        args += [_resolve_kind(kind), kind]
        row = self._one(sql, args)
        return self._event(row) if row else None

    def mark_notified(self, event_id: int) -> None:
        with self._write() as db:
            db.execute("UPDATE events SET notified=1 WHERE id=?", (event_id,))

    def pending_notifications(self, limit: int = 50) -> List[Event]:
        rows = self._rows("SELECT * FROM events WHERE notified=0 ORDER BY ts ASC LIMIT ?",
                          (limit,))
        return [self._event(row) for row in rows]

    # -------------------------------------------------------------------- rollups
    def _rollup(self, device_id: str, when: datetime, metrics: Dict[str, float]) -> None:
        hour = when.timestamp() - (when.timestamp() % 3600)
        rows = [(device_id, hour, key, value) for key, value in metrics.items()
                if isinstance(value, (int, float))]
        if not rows:
            return
        with self._write() as db:
            for device_id, hour, key, value in rows:
                db.execute(
                    """INSERT INTO rollups (device_id, hour, metric, low, avg, high, samples)
                       VALUES (?,?,?,?,?,?,1)
                       ON CONFLICT(device_id, hour, metric) DO UPDATE SET
                         low=MIN(rollups.low, excluded.low),
                         high=MAX(rollups.high, excluded.high),
                         avg=(rollups.avg * rollups.samples + excluded.avg)
                             / (rollups.samples + 1),
                         samples=rollups.samples + 1""",
                    (device_id, hour, key, value, value, value))

    def rolled(self, device_id: str, metric: str = "cpu", hours: float = 720
               ) -> List[Tuple[float, float, float]]:
        """`[(hour, low, avg, high)]` — thin enough to graph a month of history."""
        since = (now_utc() - timedelta(hours=hours)).timestamp()
        rows = self._rows("""SELECT hour, low, high FROM rollups
                             WHERE device_id=? AND metric=? AND hour>=?
                             ORDER BY hour ASC""", (device_id, metric, since))
        return [(row["hour"], row["low"], row["high"]) for row in rows]

    # ------------------------------------------------------------------ retention
    def prune(self, sample_days: int = DEFAULT_SAMPLE_DAYS, event_days: int = DEFAULT_EVENT_DAYS,
              rollup_days: int = DEFAULT_ROLLUP_DAYS) -> Dict[str, int]:
        """Old samples go, old events stay — the story of an outage outlives its graph."""
        removed: Dict[str, int] = {}
        limits = (("samples", sample_days), ("events", event_days), ("rollups", rollup_days))
        with self._write() as db:
            for table, days in limits:
                cut = (now_utc() - timedelta(days=days)).timestamp()
                cursor = db.execute("DELETE FROM %s WHERE ts < ?" % table, (cut,)) \
                    if table != "rollups" else db.execute("DELETE FROM rollups WHERE hour < ?",
                                                          (cut,))
                removed[table] = cursor.rowcount or 0
        return removed

    def vacuum(self) -> None:
        with self._lock:
            self.db.execute("VACUUM")

    def size(self) -> int:
        if str(self.path) == ":memory:":
            return 0
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    # --------------------------------------------------------------------- meta
    def set_meta(self, key: str, value: str) -> None:
        with self._write() as db:
            db.execute("INSERT INTO meta (key, value) VALUES (?,?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

    def meta(self, key: str, default: str = "") -> str:
        row = self._one("SELECT value FROM meta WHERE key=?", (key,))
        return row["value"] if row else default

    # -------------------------------------------------------------- row → object
    @staticmethod
    def _reading(row) -> Reading:
        try:
            metrics = json.loads(row["metrics"] or "{}")
        except ValueError:
            metrics = {}
        return Reading(device_id=row["device_id"], at=row["at"], status=row["status"],
                       latency_ms=row["latency_ms"], loss=row["loss"], metrics=metrics,
                       message=row["message"] or "", seconds=row["seconds"] or 0.0)

    @staticmethod
    def _event(row) -> Event:
        try:
            detail = json.loads(row["detail"] or "{}")
        except ValueError:
            detail = {}
        return Event(at=row["at"], device_id=row["device_id"], kind=row["kind"],
                     severity=row["severity"], subject=row["subject"] or "",
                     message=row["message"] or "", value=row["value"],
                     notified=bool(row["notified"]), detail=detail)


def _resolve_kind(kind: str) -> str:
    """The event that closes a given kind of trouble."""
    return {"down": "up", "up": "down", "degraded": "recovered",
            "recovered": "degraded", "threshold": "cleared", "cleared": "threshold",
            "interface-down": "interface-up", "interface-up": "interface-down"}.get(kind, kind)
