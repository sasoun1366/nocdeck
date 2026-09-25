"""Fixtures for the whole suite: a throwaway home, a fake agent, a stopped clock.

Nothing here touches the network. The SNMP tests build their own packets and decode
them; the engine tests drive the collector through a fake client that answers the
same OIDs a real device would; the alert tests use a fake opener that records what
would have been sent.
"""

from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nocdeck import mibs                                          # noqa: E402
from nocdeck.config import Config                                 # noqa: E402
from nocdeck.model import Device, Interface, Reading              # noqa: E402
from nocdeck.snmp import INTEGER, NULL, OBJECT_ID, OCTET_STRING, TIMETICKS, VarBind  # noqa: E402
from nocdeck.store import Store                                   # noqa: E402

#: A fixed instant, for assertions that are about content rather than recency.
FROZEN = datetime(2026, 9, 21, 6, 30, tzinfo=timezone.utc)


def ago(minutes: float = 0, hours: float = 0, seconds: float = 0) -> datetime:
    """`minutes` ago, on the real clock.

    History windows ("the last 24 hours") are relative to now, so a test that wants
    a sample to be inside one has to place it relative to now — which is what this
    is for.
    """
    return datetime.now(timezone.utc) - timedelta(hours=hours, minutes=minutes,
                                                  seconds=seconds)


def ago_iso(minutes: float = 0, hours: float = 0, seconds: float = 0) -> str:
    return ago(minutes=minutes, hours=hours, seconds=seconds).isoformat(timespec="seconds")


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = tmp_path / "nocdeck-home"
    root.mkdir()
    monkeypatch.setenv("NOCDECK_HOME", str(root))
    return root


@pytest.fixture
def config(home):
    return Config()


@pytest.fixture
def store(home):
    database = Store(home / "nocdeck.db")
    yield database
    database.close()


@pytest.fixture
def switch():
    return Device(name="core-sw-01", host="10.0.0.2", id="core-sw-01", kind="switch",
                  community="public", group="dc", interval=30)


@pytest.fixture
def server():
    return Device(name="srv-dc-01", host="10.0.0.30", id="srv-dc-01", kind="server",
                  community="public", group="servers", tcp_ports=[22], interval=60)


class FakeAgent:
    """A device that answers exactly the OIDs it is given, in one table.

    Build it with `FakeAgent(scalars={...}, tables={...})`, hand it to `FakeClient`,
    and the collector cannot tell the difference between this and a switch.
    """

    def __init__(self, scalars: Optional[Dict[str, object]] = None,
                 tables: Optional[Dict[str, Dict[str, object]]] = None,
                 refuse: Sequence[str] = (), error: Optional[str] = None):
        self.scalars: Dict[str, object] = dict(scalars or {})
        self.tables: Dict[str, Dict[str, object]] = dict(tables or {})
        self.refuse = tuple(refuse)
        self.error = error
        self.asked: List[str] = []

    def get(self, oids: Sequence[str]) -> List[VarBind]:
        from nocdeck.snmp import SnmpError

        self.asked.extend(oids)
        if self.error:
            raise SnmpError(self.error)
        out: List[VarBind] = []
        for oid in oids:
            if any(oid.startswith(prefix) for prefix in self.refuse):
                raise SnmpError("no such name: %s" % oid)
            value = self.scalars.get(oid, None)
            out.append(VarBind(oid, value, _tag(value)))
        return out

    def walk(self, root: str, ceiling: int = 4000, bulk: Optional[int] = None) -> List[VarBind]:
        if any(root.startswith(prefix) for prefix in self.refuse):
            return []
        rows = self.tables.get(root, {})
        return [VarBind(oid, value, _tag(value)) for oid, value in sorted(rows.items())][:ceiling]

    def close(self) -> None:
        pass


def _tag(value) -> int:
    if value is None:
        return NULL
    if isinstance(value, bool):
        return INTEGER
    if isinstance(value, int):
        return INTEGER
    if isinstance(value, str) and value.count(".") >= 3 and value[0].isdigit():
        return OBJECT_ID
    return OCTET_STRING


class FakeClient:
    """The client-shaped wrapper the collector expects, over a FakeAgent."""

    def __init__(self, agent: FakeAgent):
        self.agent = agent
        self.requests = 0
        self.last_latency = 0.01

    def get(self, oids):
        self.requests += 1
        return self.agent.get(oids)

    def walk(self, root, ceiling=4000, bulk=None):
        self.requests += 1
        return self.agent.walk(root, ceiling, bulk)

    def get_next(self, oid):
        rows = self.agent.walk(oid.rsplit(".", 1)[0])
        for row in rows:
            if row.oid > oid:
                return row
        return None

    def close(self):
        pass


def system_scalars(descr="RouterOS core-sw-01 by MikroTik",
                   object_id="1.3.6.1.4.1.14988.1", name="core-sw-01",
                   uptime=86_400_00) -> Dict[str, object]:
    return {mibs.SYS["descr"]: descr, mibs.SYS["object_id"]: object_id,
            mibs.SYS["name"]: name, mibs.SYS["uptime"]: uptime,
            mibs.SYS["location"]: "rack 1", mibs.SYS["contact"]: "noc@example.net"}


def interface_table(count: int = 3, speed: int = 1000, oper_down: Sequence[int] = (),
                    in_octets: int = 10 ** 9) -> Dict[str, Dict[str, object]]:
    """An IF-MIB table with `count` ports, high-capacity counters included."""
    roots = {
        mibs.IF["name"]: "ether%d", mibs.IF["descr"]: "ether%d",
        mibs.IF["alias"]: "port %d", mibs.IF["type"]: 6, mibs.IF["high_speed"]: speed,
        mibs.IF["admin_status"]: 1, mibs.IF["oper_status"]: 1,
        mibs.IF["hc_in_octets"]: in_octets,
        mibs.IF["hc_out_octets"]: in_octets // 2, mibs.IF["in_errors"]: 0,
        mibs.IF["out_errors"]: 0, mibs.IF["in_discards"]: 0, mibs.IF["out_discards"]: 0,
        mibs.IF["phys_address"]: "00:11:22:33:44:55", mibs.IF["last_change"]: 120,
        mibs.IF["mtu"]: 1500,
    }
    table: Dict[str, Dict[str, object]] = {}
    for root, value in roots.items():
        column: Dict[str, object] = {}
        for index in range(1, count + 1):
            if root == mibs.IF["oper_status"]:
                item: object = 2 if index in oper_down else 1
            elif isinstance(value, str):
                item = value % index if "%d" in value else value
            else:
                item = value
            column["%s.%d" % (root, index)] = item
        table[root] = column
    # the interface index itself, which the collector reads to name a port
    table[mibs.IF["index"]] = {"%s.%d" % (mibs.IF["index"], i): i
                               for i in range(1, count + 1)}
    return table


def sensor_table(temperature=42.0, fan=4200, optical=-6.5
                 ) -> Dict[str, Dict[str, object]]:
    """ENTITY-SENSOR-MIB, in the units the standard actually means."""
    raw = [(1, 8, 5, 1, int(round(temperature * 10)), "chassis temperature"),
           (2, 10, 6, 0, fan, "fan 1"),
           (3, 4, 5, 1, 121, "input voltage"),
           (4, 14, 4, 2, int(round(optical * 100)), "sfp rx power")]
    table: Dict[str, Dict[str, object]] = {}
    for index, kind, scale, precision, value, name in raw:
        table.setdefault(mibs.ENTITY_SENSOR["type"], {})[
            "%s.%d" % (mibs.ENTITY_SENSOR["type"], index)] = kind
        table.setdefault(mibs.ENTITY_SENSOR["scale"], {})[
            "%s.%d" % (mibs.ENTITY_SENSOR["scale"], index)] = scale
        table.setdefault(mibs.ENTITY_SENSOR["precision"], {})[
            "%s.%d" % (mibs.ENTITY_SENSOR["precision"], index)] = precision
        table.setdefault(mibs.ENTITY_SENSOR["value"], {})[
            "%s.%d" % (mibs.ENTITY_SENSOR["value"], index)] = value
        table.setdefault(mibs.ENTITY_SENSOR["status"], {})[
            "%s.%d" % (mibs.ENTITY_SENSOR["status"], index)] = 1
        table.setdefault(mibs.ENTITY_SENSOR["name"], {})[
            "%s.%d" % (mibs.ENTITY_SENSOR["name"], index)] = name
    return table


def mikrotik_agent(**kwargs) -> FakeAgent:
    """A RouterOS switch: identity, its health scalars, interfaces and sensors."""
    scalars = system_scalars(**kwargs)
    for row in mibs.VENDOR_METRICS:
        if row.vendor != "mikrotik" or row.table:
            continue
        # values as a RouterOS box reports them: whole degrees, tenths of a volt
        scalars.setdefault(row.oid, {
            "cpu": 21, "temperature": 43, "voltage": 121, "fan": 4200,
            "sessions": 1180, "frequency": 1400,
        }.get(row.key))
    return FakeAgent(scalars=scalars,
                     tables={**interface_table(4), **sensor_table()})


def reading(status="up", **metrics) -> Reading:
    return Reading(device_id="core-sw-01", at="2026-09-21T06:30:00+00:00", status=status,
                   metrics=metrics)


def sample_interfaces(count: int = 3) -> List[Interface]:
    return [Interface(index=i, name="ether%d" % i, oper="up", speed_mbps=1000,
                      in_octets=10 ** 9, out_octets=10 ** 9) for i in range(1, count + 1)]


class FakeOpener:
    """Stands in for `urllib.request.urlopen`: records the request, answers a blob."""

    def __init__(self, payload: bytes = b'{"ok":true,"result":{"message_id":7}}',
                 status: int = 200, boom: Optional[Exception] = None):
        self.payload = payload
        self.status = status
        self.boom = boom
        self.calls: List[Dict[str, object]] = []

    def __call__(self, request, timeout=None, **kwargs):
        body = request.data
        self.calls.append({
            "url": getattr(request, "full_url", str(request)),
            "method": getattr(request, "method", None) or "GET",
            "body": body,
            "json": json.loads(body.decode("utf-8")) if body else None,
        })
        if self.boom:
            raise self.boom
        return FakeResponse(self.payload, self.status)


class FakeResponse:
    def __init__(self, payload: bytes, status: int = 200):
        self.payload = payload
        self.status = status

    def read(self, *args):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False
