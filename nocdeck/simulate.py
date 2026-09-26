"""A world of imaginary switches, so the dashboard can be seen before it is trusted.

`nocdeck demo` fills the inventory with a plausible estate — a RouterOS switch, a
Cisco access switch, a FortiGate, a Windows and a Linux server, a UPS, a printer, an
access point — and then polls them through a **fake SNMP agent**.

The trick worth noticing: the fake agent answers the same OIDs a real one would, so
everything downstream is the real thing. The same collector, the same thresholds,
the same metrics, the same events, the same dashboard. Nothing here shortcuts the
logic it is demonstrating — which is also why it is a good way to try a threshold
before pointing the tool at production.
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from . import mibs, probe
from .model import Device, Interface, Reading, iso, now_utc, slug
from .snmp import INTEGER, NULL, OBJECT_ID, OCTET_STRING, TIMETICKS, VarBind

#: name, ip, kind, vendor, group — the estate the demo builds.
ESTATE: Sequence[Tuple[str, str, str, str, str]] = (
    ("core-sw-01", "10.20.0.2", "switch", "mikrotik", "dc"),
    ("core-sw-02", "10.20.0.3", "switch", "mikrotik", "dc"),
    ("edge-router", "10.20.0.1", "router", "mikrotik", "dc"),
    ("fw-hq", "10.20.0.10", "firewall", "fortinet", "dc"),
    ("acc-sw-floor1", "10.20.1.11", "switch", "cisco", "campus"),
    ("acc-sw-floor2", "10.20.1.12", "switch", "hpe", "campus"),
    ("ap-lobby", "10.20.2.21", "ap", "ubiquiti", "campus"),
    ("srv-dc-01", "10.20.3.31", "server", "linux", "servers"),
    ("srv-file-01", "10.20.3.32", "server", "windows", "servers"),
    ("ups-rack-a", "10.20.4.41", "ups", "apc", "power"),
    ("printer-2f", "10.20.5.51", "printer", "printer", "campus"),
)

#: One device in the demo estate speaks SNMPv3, because a demo where nothing uses the
#: feature is a demo of a different feature. The credentials are printed by `nocdeck
#: demo` — they are imaginary, and they are the point: a username and two passphrases
#: where the rest of the estate has a community string.
DEMO_V3 = {
    "fw-hq": {"user": "nocmon", "auth": "sha256", "auth_key": "demo-auth-passphrase",
              "priv": "aes", "priv_key": "demo-priv-passphrase"},
}

PORTS_BY_KIND = {
    "switch": 24, "router": 8, "firewall": 8, "server": 4, "ap": 4, "ups": 1, "printer": 1,
}
SPEEDS = {"switch": 1000, "router": 1000, "firewall": 1000, "server": 10000, "ap": 1000,
          "ups": 100, "printer": 100}


@dataclass
class SimPort:
    index: int
    name: str
    alias: str
    speed: int
    up: bool = True
    in_octets: int = 0
    out_octets: int = 0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    mtu: int = 1500
    last_change: int = 0


@dataclass
class SimNode:
    """The state behind one imaginary device: what drifts, and what changed."""

    device: Device
    seed: int = 0
    uptime: float = 86400.0
    cpu: float = 20.0
    memory: float = 45.0
    temperature: float = 38.0
    fan: float = 4200.0
    voltage: float = 12.1
    optical: Optional[float] = -6.5
    battery: float = 100.0
    disk: float = 40.0
    sessions: float = 1200.0
    ports: List[SimPort] = field(default_factory=list)
    down_until: float = 0.0                      # an outage in progress
    port_flap_at: float = 0.0
    trend: float = 0.0                           # a slow drift, for the demo of an alert
    phase: float = 0.0
    random: random.Random = field(default_factory=random.Random)

    def build(self) -> None:
        self.random = random.Random(self.seed or hash(self.device.key()) & 0xFFFF)
        self.phase = self.random.random() * 6.28
        count = PORTS_BY_KIND.get(self.device.kind, 4)
        speed = SPEEDS.get(self.device.kind, 1000)
        role = {"switch": "Gi", "router": "ether", "firewall": "port", "server": "eth",
                "ap": "eth", "ups": "mgmt", "printer": "eth"}.get(self.device.kind, "if")
        for index in range(1, count + 1):
            alias = ""
            if index == 1:
                alias = "uplink"
            elif index == 2 and self.device.kind == "switch":
                alias = "trunk to core"
            self.ports.append(SimPort(index=index, name="%s%d" % (role, index), alias=alias,
                                      speed=speed, up=index != count,
                                      in_octets=self.random.randint(10 ** 9, 10 ** 10),
                                      out_octets=self.random.randint(10 ** 9, 10 ** 10),
                                      in_errors=self.random.randint(0, 4)))
        self.cpu = {"server": 35.0, "switch": 18.0, "router": 22.0, "firewall": 40.0,
                    "ap": 25.0, "ups": 5.0, "printer": 3.0}.get(self.device.kind, 20.0)
        self.memory = {"server": 62.0, "switch": 42.0, "router": 48.0, "firewall": 65.0,
                       "ap": 55.0, "ups": 20.0, "printer": 30.0}.get(self.device.kind, 45.0)
        self.temperature = {"switch": 42.0, "router": 44.0, "firewall": 47.0, "server": 41.0,
                            "ap": 49.0, "ups": 28.0, "printer": 33.0}.get(self.device.kind, 40.0)
        if self.device.kind in ("server", "firewall"):
            self.disk = 55.0 if "file" in self.device.name else 38.0

    # ------------------------------------------------------------------- advance
    def step(self, seconds: float) -> None:
        noise = self.random.uniform(-1, 1)
        wave = math.sin(time.time() / 900.0 + self.phase) * 6.0
        self.cpu = _clamp(self.cpu + wave * 0.15 + noise * 1.5 + self.trend * 0.02, 1, 100)
        self.memory = _clamp(self.memory + noise * 0.4, 5, 99)
        self.temperature = _clamp(self.temperature + noise * 0.25 + (self.cpu - 30) * 0.01,
                                  18, 95)
        self.fan = _clamp(self.fan + noise * 40, 0, 12000)
        self.voltage = round(_clamp(self.voltage + noise * 0.02, 10, 14), 2)
        self.uptime += seconds
        if self.optical is not None:
            self.optical = round(_clamp(self.optical + noise * 0.05, -28, -2), 2)
        self.battery = _clamp(self.battery - seconds / 86400.0 * 2.0, 0, 100)
        if self.device.kind in ("server", "firewall", "printer"):
            self.disk = _clamp(self.disk + seconds / 86400.0 * 0.35, 5, 99)
        self.sessions = _clamp(self.sessions + noise * 20, 10, 200000)
        for port in self.ports:
            if not port.up:
                continue
            rate = self.random.uniform(2e6, 4.5e8) / max(1, len(self.ports))
            port.in_octets += int(rate * seconds / 8 * self.random.uniform(0.6, 1.4))
            port.out_octets += int(rate * seconds / 8 * self.random.uniform(0.6, 1.4))
            if self.random.random() < 0.002:
                port.in_errors += 1

    # -------------------------------------------------------------- SNMP answers
    def scalar(self, oid: str):
        """The scalar OIDs a real agent would answer for this kind of box."""
        sys = mibs.SYS
        if oid == sys["descr"]:
            template = VENDOR_DESCR.get(self.device.vendor, "{name} (vendor not stated)")
            return template.format(name=self.device.name)
        if oid == sys["object_id"]:
            return VENDOR_OID.get(self.device.vendor, "1.3.6.1.4.1.8072.3.2.10")
        if oid == sys["uptime"]:
            return int(self.uptime * 100)
        if oid == sys["name"]:
            return self.device.name
        if oid == sys["location"]:
            return self.device.location or self.device.group or "rack"
        if oid == sys["contact"]:
            return "noc@example.net"
        # the uptime row is also a vendor-table row for RouterOS and VMware
        for row in mibs.VENDOR_METRICS:
            if row.key == "uptime" and row.oid == oid and row.vendor == self.device.vendor:
                return int(self.uptime * 100)
        for row in mibs.VENDOR_METRICS:
            if row.oid != oid or row.table or row.vendor != self.device.vendor:
                continue
            # the wire carries the scaled integer; `metric_for` gives the real number
            return _wire(self.metric_for(row.key), row)
        return None

    def metric_for(self, key: str):
        """The real-world number this imaginary device is showing right now."""
        return {
            "cpu": self.cpu, "memory": self.memory, "temperature": self.temperature,
            "fan": self.fan, "voltage": self.voltage, "optical": self.optical,
            "battery": self.battery, "disk": self.disk, "sessions": self.sessions,
            "uptime": int(self.uptime), "power": self.voltage * 120,
            "frequency": 1400.0, "runtime": 62.0,
        }.get(key)

    def walk(self, root: str) -> List[VarBind]:
        """A table the collector will recognise: interfaces, sensors, storage, PoE."""
        out: List[VarBind] = []
        if root.startswith("1.3.6.1.2.1.2.2.1") or root.startswith("1.3.6.1.2.1.31.1.1"):
            out.extend(self._interface_walk(root))
        elif root.startswith("1.3.6.1.2.1.99.1.1") or root.startswith("1.3.6.1.2.1.47.1.1"):
            out.extend(self._sensor_walk(root))
        elif root.startswith("1.3.6.1.2.1.25.2.3") and self.device.kind in ("server",
                                                                            "printer"):
            out.extend(self._storage_walk(root))
        elif root.startswith("1.3.6.1.2.1.25.3.3") and self.device.kind == "server":
            out.extend(self._cpu_walk(root))
        elif root.startswith("1.3.6.1.4.1.2021.9.1") and self.device.kind == "server":
            out.extend(self._ucd_disk_walk(root))
        elif self._vendor_table(root):
            out.extend(self._vendor_table(root))
        elif root in (mibs.POE["port_detect"], mibs.POE["port_enable"]):
            for port in self.ports:
                value = 3 if port.up else 2
                out.append(VarBind("%s.%d" % (root, port.index),
                                   value if root == mibs.POE["port_detect"]
                                   else (1 if port.up else 2), INTEGER))
        return out

    def _vendor_table(self, root: str) -> List[VarBind]:
        """The vendor's own tables — Cisco CPU pools, Huawei cards, SFP optics.

        Two rows each, which is what a small chassis looks like and enough for the
        reducers to do something real (a mean over CPU pools, a maximum over
        temperatures).
        """
        rows = [row for row in mibs.VENDOR_METRICS
                if row.table and row.vendor == self.device.vendor and row.oid == root]
        if not rows:
            return []
        metrics = [row for row in rows if row.oid == root]
        out: List[VarBind] = []
        for label, row in enumerate(metrics):
            for index in (1, 2):
                # the second row of a fan table is slower; of a temperature table hotter
                drift = 1.0 if index == 1 else (0.85 if row.key == "fan" else 1.12)
                value = self.metric_for(row.key)
                if value is None:
                    continue
                out.append(VarBind("%s.%d" % (root, index),
                                   _wire(value * drift, row), INTEGER))
        return out

    def _interface_walk(self, root: str) -> List[VarBind]:
        column = {"1.3.6.1.2.1.2.2.1.2": "descr", "1.3.6.1.2.1.2.2.1.3": "type",
                  "1.3.6.1.2.1.2.2.1.4": "mtu", "1.3.6.1.2.1.2.2.1.5": "speed32",
                  "1.3.6.1.2.1.2.2.1.6": "phys", "1.3.6.1.2.1.2.2.1.7": "admin",
                  "1.3.6.1.2.1.2.2.1.8": "oper", "1.3.6.1.2.1.2.2.1.9": "last_change",
                  "1.3.6.1.2.1.2.2.1.10": "in_octets32", "1.3.6.1.2.1.2.2.1.14": "in_errors",
                  "1.3.6.1.2.1.2.2.1.16": "out_octets32", "1.3.6.1.2.1.2.2.1.20": "out_errors",
                  "1.3.6.1.2.1.31.1.1.1.1": "name", "1.3.6.1.2.1.31.1.1.1.15": "high_speed",
                  "1.3.6.1.2.1.31.1.1.1.18": "alias", "1.3.6.1.2.1.31.1.1.1.6": "hc_in",
                  "1.3.6.1.2.1.31.1.1.1.10": "hc_out"}.get(root)
        if not column:
            return []
        out: List[VarBind] = []
        for port in self.ports:
            oid = "%s.%d" % (root, port.index)
            if column == "descr" or column == "name":
                out.append(VarBind(oid, port.name, OCTET_STRING))
            elif column == "alias":
                out.append(VarBind(oid, port.alias, OCTET_STRING))
            elif column == "phys":
                out.append(VarBind(oid, "00:0c:29:%02x:%02x:%02x" % (port.index, 0x11,
                                                                    port.index * 3 % 255),
                                   OCTET_STRING))
            elif column == "type":
                out.append(VarBind(oid, 6, INTEGER))
            elif column == "mtu":
                out.append(VarBind(oid, port.mtu, INTEGER))
            elif column == "speed32":
                out.append(VarBind(oid, port.speed * 10 ** 6, INTEGER))
            elif column == "high_speed":
                out.append(VarBind(oid, port.speed, INTEGER))
            elif column == "admin":
                out.append(VarBind(oid, 1, INTEGER))
            elif column == "oper":
                out.append(VarBind(oid, 1 if port.up else 2, INTEGER))
            elif column == "last_change":
                changed = 0 if port.up else 3600
                out.append(VarBind(oid, changed, TIMETICKS))
            elif column == "in_octets32":
                out.append(VarBind(oid, port.in_octets % (2 ** 32), INTEGER))
            elif column == "out_octets32":
                out.append(VarBind(oid, port.out_octets % (2 ** 32), INTEGER))
            elif column == "hc_in":
                out.append(VarBind(oid, port.in_octets, INTEGER))
            elif column == "hc_out":
                out.append(VarBind(oid, port.out_octets, INTEGER))
            else:
                out.append(VarBind(oid, getattr(port, column), INTEGER))
        return out

    def _sensor_walk(self, root: str) -> List[VarBind]:
        """ENTITY-SENSOR: temperature, a fan, a voltage, and the SFP's dBm."""
        base = root.rsplit(".", 1)[0] if not root.endswith(("1.99.1.1.1", "47.1.1.1.1")) \
            else root
        # entPhySensorScale is a power of ten: 5 means the raw number is tenths, 6 whole
        # units, 4 hundredths. Getting this right is the whole point of the standard.
        sensors = [(1, 8, 5, 1, int(round(self.temperature * 10)), "chassis temperature")]
        if self.device.kind in ("switch", "router", "firewall", "server"):
            sensors.append((2, 10, 6, 0, int(round(self.fan)), "fan 1"))
            sensors.append((3, 4, 5, 1, int(round(self.voltage * 10)), "input voltage"))
        if self.device.kind in ("switch", "router", "firewall"):
            sensors.append((4, 14, 4, 2, int(round((self.optical or -7.0) * 100)),
                            "sfp rx power"))
        out: List[VarBind] = []
        for index, sensor_type, scale, precision, raw, name in sensors:
            if root.endswith("99.1.1.1.1"):
                out.append(VarBind("%s.%d" % (root, index), sensor_type, INTEGER))
            elif root.endswith("99.1.1.1.2"):
                out.append(VarBind("%s.%d" % (root, index), scale, INTEGER))
            elif root.endswith("99.1.1.1.3"):
                out.append(VarBind("%s.%d" % (root, index), precision, INTEGER))
            elif root.endswith("99.1.1.1.4"):
                out.append(VarBind("%s.%d" % (root, index), raw, INTEGER))
            elif root.endswith("99.1.1.1.5"):
                out.append(VarBind("%s.%d" % (root, index), 1, INTEGER))
            elif root.endswith("47.1.1.1.1.7"):
                out.append(VarBind("%s.%d" % (root, index), name, OCTET_STRING))
            elif root.endswith("47.1.1.1.1.2"):
                out.append(VarBind("%s.%d" % (root, index), name, OCTET_STRING))
        return out

    def _storage_walk(self, root: str) -> List[VarBind]:
        tables = [(mibs.HR["storage_descr"], OCTET_STRING, None), (mibs.HR["storage_alloc"], INTEGER, None)]
        storage = [("C:\\ Label: System", 4096, 60), ("D:\\ Data", 8192, 22)]
        if root == mibs.HR["storage_descr"]:
            return [VarBind("%s.%d" % (root, i + 1), name, OCTET_STRING)
                    for i, (name, _size, _pc) in enumerate(storage)]
        if root == mibs.HR["storage_alloc"]:
            return [VarBind("%s.%d" % (root, i + 1), 4096, INTEGER)
                    for i in range(len(storage))]
        if root == mibs.HR["storage_size"]:
            return [VarBind("%s.%d" % (root, i + 1), size * 1024 * 1024 // 4096, INTEGER)
                    for i, (_n, size, _pc) in enumerate(storage)]
        if root == mibs.HR["storage_used"]:
            return [VarBind("%s.%d" % (root, i + 1),
                            int(size * 1024 * 1024 // 4096 * self.disk / 100), INTEGER)
                    for i, (_n, size, _pc) in enumerate(storage)]
        return []

    def _cpu_walk(self, root: str) -> List[VarBind]:
        cores = 8 if self.device.kind == "server" else 2
        scale = self.cpu / 100.0
        return [VarBind("%s.%d" % (root, core + 1), int(round(self.cpu * 100 / 100)), INTEGER)
                for core in range(cores)]

    def _ucd_disk_walk(self, root: str) -> List[VarBind]:
        filesystems = [("/", 200, self.disk), ("/var/log", 50, self.disk + 4)]
        if root == mibs.UCD["disk_path"]:
            return [VarBind("%s.%d" % (root, i + 1), name, OCTET_STRING)
                    for i, (name, _size, _pc) in enumerate(filesystems)]
        if root == mibs.UCD["disk_total"]:
            return [VarBind("%s.%d" % (root, i + 1), size * 1024, INTEGER)
                    for i, (_n, size, _pc) in enumerate(filesystems)]
        if root == mibs.UCD["disk_avail"]:
            return [VarBind("%s.%d" % (root, i + 1),
                            int(size * 1024 * (100 - pc) / 100), INTEGER)
                    for i, (_n, size, pc) in enumerate(filesystems)]
        if root == mibs.UCD["disk_percent"]:
            return [VarBind("%s.%d" % (root, i + 1), int(pc), INTEGER)
                    for i, (_n, _size, pc) in enumerate(filesystems)]
        return []


VENDOR_DESCR = {
    "mikrotik": "RouterOS {name} (CRS326-24G-2S+) by MikroTik",
    "cisco": "Cisco IOS Software, C2960S Software (C2960S-UNIVERSALK9-M), Version 15.2(2)E",
    "hpe": "HP ProCurve Switch 2920-24G (J9726A), revision WB.16.02",
    "fortinet": "FortiGate-100F v7.4.1,build2463,230131 (GA.F)",
    "ubiquiti": "UniFi Switch/AP, UniFi 6.6.55, Ubiquiti Inc.",
    "linux": "Linux {name} 6.8.0-31-generic #31-Ubuntu SMP PREEMPT_DYNAMIC x86_64",
    "windows": "Hardware: Intel64 Family 6 Model 85 - Software: Windows Version 6.3 (Build 20348)",
    "apc": "APC Web/SNMP Management Card (MB:v4.3.4 PF:v6.8.2) Smart-UPS 3000",
    "printer": "HP LaserJet Enterprise M507 (HP LaserJet) printer",
    "generic": "{name} SNMP agent",
}
VENDOR_OID = {
    "mikrotik": "1.3.6.1.4.1.14988.1", "cisco": "1.3.6.1.4.1.9.1.1208",
    "hpe": "1.3.6.1.4.1.11.2.3.7.11.69", "fortinet": "1.3.6.1.4.1.12356.101.1.1002",
    "ubiquiti": "1.3.6.1.4.1.41112.1.6", "linux": "1.3.6.1.4.1.8072.3.2.10",
    "windows": "1.3.6.1.4.1.311.1.1.3.1.2", "apc": "1.3.6.1.4.1.318.1.3.27",
    "printer": "1.3.6.1.4.1.11.2.3.9.1", "generic": "1.3.6.1.4.1.8072.3.2.10",
}


class SimClient:
    """A client-shaped object the collector cannot tell from the real one."""

    def __init__(self, node: SimNode, agent=None):
        self.node = node
        self.agent = agent
        self.requests = 0
        self.last_latency = 0.01

    def close(self) -> None:
        pass

    def get(self, oids: Sequence[str]) -> List[VarBind]:
        self.requests += 1
        out: List[VarBind] = []
        for oid in oids:
            value = self.node.scalar(oid)
            if value is None:
                out.append(VarBind(oid, None, NULL))
            elif isinstance(value, int):
                out.append(VarBind(oid, value, INTEGER))
            else:
                tag = OBJECT_ID if oid.endswith(".1.2.0") else OCTET_STRING
                out.append(VarBind(oid, str(value), tag))
        return out

    def walk(self, root: str, ceiling: int = 4000, bulk: Optional[int] = None) -> List[VarBind]:
        self.requests += 1
        return self.node.walk(root)[:ceiling]

    def get_next(self, oid: str) -> Optional[VarBind]:
        rows = self.walk(oid.rsplit(".", 1)[0])
        for row in rows:
            if row.oid > oid:
                return row
        return None


class Simulator:
    """The poller's two injection points, pointed at imaginary gear."""

    def __init__(self, nodes: Dict[str, SimNode], seed: int = 7, outage: bool = True):
        self.nodes = nodes
        self.random = random.Random(seed)
        self.started = time.time()
        self.outage = outage
        self.outage_done = False
        self.port_done = False
        self.v3_agents: Dict[str, object] = {}       # one USM agent per v3 device
        self.v3_wires: Dict[str, object] = {}

    # -------------------------------------------------------------- injection
    def node_for(self, device: Device) -> SimNode:
        """The imaginary box behind an address.

        The address decides, not the name: if somebody adds `10.20.0.10` under a second
        name, that is the same firewall, and the demo says so — the same way a real
        estate answers two names for one management address.
        """
        node = self.nodes.get(device.key())
        if node is not None:
            return node
        for candidate in self.nodes.values():
            if device.address and candidate.device.address == device.address:
                return candidate
            if device.host and candidate.device.host == device.host:
                return candidate
        node = SimNode(device=device, seed=abs(hash(device.key())) % 9999)
        node.build()
        self.nodes[device.key()] = node
        return node

    def client_for(self, device: Device):
        """A client for this device: a v3 one for v3 gear, a stand-in for the rest.

        A simulated v3 device is not answered by a shortcut. It gets a real
        `snmp.Client` talking to a real USM session over a loopback socket.
        """
        node = self.node_for(device)
        if (device.version or "") == "3" or (node.device.version or "") == "3":
            return self.v3_client_for(device, node)
        return SimClient(node)

    def v3_client_for(self, device: Device, node: Optional[SimNode] = None):
        """The real client, over a socket that goes nowhere but here."""
        from . import snmp
        from .simv3 import LoopbackSocket, V3Agent, V3User

        node = node or self.node_for(device)
        # The *device's* credentials are what the agent knows, and the record is what the
        # client sends. When they are the same record that is a formality; when a person
        # has just typed a passphrase into the add form, that is the whole test — the
        # demo refuses a wrong passphrase exactly the way a switch does, with a REPORT,
        # rather than accepting anything typed at it.
        known = node.device
        user = V3User(name=known.user or device.user,
                      auth_protocol=(known.auth or device.auth),
                      auth_password=(known.auth_key or device.auth_key),
                      priv_protocol=(known.priv or device.priv),
                      priv_password=(known.priv_key or device.priv_key))
        agent = V3Agent(node=node, users={user.name: user})
        agent.engine_id = b"\x80\x00\x00\x02" + ("nocdeck-%s" % node.device.id)[:13] \
            .encode("utf-8").ljust(13, b"\x00")
        self.v3_agents[device.key()] = agent
        wire = LoopbackSocket(agent)
        client = snmp.Client(snmp.Agent(host=device.target(), port=device.port,
                                        version="3", user=device.user, auth=device.auth,
                                        auth_key=device.auth_key, priv=device.priv,
                                        priv_key=device.priv_key, context=device.context,
                                        keys_are_hex=device.keys_are_hex),
                             timeout=2.0, retries=1, sock=wire)
        self.v3_wires[device.key()] = wire
        return client

    def prober(self, host: str, count: int = 3, timeout: float = 1.5, tcp_fallback=()):
        for node in self.nodes.values():
            if node.device.address == host or node.device.host == host:
                if node.down_until > time.time():
                    return probe.ProbeResult(ok=False, status="down", loss=100.0,
                                             method="sim", latency_ms=None,
                                             detail="simulated outage")
                return probe.ProbeResult(ok=True, status="up",
                                         latency_ms=round(self.random.uniform(0.4, 9.0), 2),
                                         loss=0.0, method="sim", detail="simulated")
        return probe.ProbeResult(ok=False, status="down", method="sim", detail="unknown host")

    def tcp_prober(self, host: str, port: int, timeout: float = 2.0):
        node = self._node_for(host)
        if node is None:
            return probe.ProbeResult(ok=False, status="up" if False else "unknown",
                                     method="sim", detail="unknown host")
        if node.down_until > time.time():
            return probe.ProbeResult(ok=False, status="down", method="sim",
                                     detail="simulated outage")
        # the management port is always open on the imaginary gear; 8291 is RouterOS
        if port in (22, 161, 8291, 443):
            return probe.ProbeResult(ok=True, status="up", latency_ms=1.0, method="sim",
                                     detail="port %d open (simulated)" % port)
        return probe.ProbeResult(ok=False, status="down", method="sim",
                                 detail="port %d closed (simulated)" % port)

    def http_prober(self, url: str, timeout: float = 5.0, expect_status: int = 0):
        host = url.split("//", 1)[-1].split("/", 1)[0].split(":")[0]
        node = self._node_for(host)
        if node is None or node.down_until > time.time():
            return probe.ProbeResult(ok=False, status="down", method="sim",
                                     detail="no answer (simulated)")
        return probe.ProbeResult(ok=True, status="up", latency_ms=8.0, method="sim",
                                 detail="HTTP 200 in 8 ms · certificate 96 d (simulated)",
                                 extra={"status_code": 200, "tls_days": 96})

    def _node_for(self, host: str) -> Optional[SimNode]:
        for node in self.nodes.values():
            if node.device.address == host or node.device.host == host:
                return node
        return None

    # ---------------------------------------------------------------- the story
    def advance(self, seconds: float, elapsed: float = 0.0) -> None:
        """Time passes in the imaginary estate, including a small drama.

        The drama is the point: an outage at two minutes in, a port that drops at
        four, and one server whose temperature walks up to the warning line. That is
        what makes the dashboard worth looking at, and what proves the alert path
        works before anyone trusts it with a real rack.
        """
        for node in self.nodes.values():
            node.step(seconds)
        if not self.outage:
            return
        if not self.outage_done and elapsed > 90:
            node = self.nodes.get("ap-lobby")
            if node:
                node.down_until = time.time() + 240
                self.outage_done = True
        if self.outage_done and not self.port_done and elapsed > 200:
            node = self.nodes.get("acc-sw-floor2")
            if node and node.ports:
                node.ports[-1].up = False
                self.port_done = True
        node = self.nodes.get("srv-file-01")
        if node and elapsed > 60:
            node.trend = min(1.0, (elapsed - 60) / 900.0)
            node.temperature = min(88.0, node.temperature + 0.02)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _wire(value: Optional[float], row: mibs.Metric):
    """A real-world number as the integer an SNMP agent would put on the wire."""
    if value is None:
        return None
    scaled = float(value) * (row.divisor or 1.0)
    return int(round(scaled))


# ------------------------------------------------------------------- building


def build_world(store, config, size: Optional[int] = None) -> Dict[str, SimNode]:
    """Fill the inventory with the demo estate and return the simulator's nodes."""
    estate = ESTATE[:size] if size else ESTATE
    nodes: Dict[str, SimNode] = {}
    for index, (name, address, kind, vendor, group) in enumerate(estate):
        device = Device(name=name, host=address, id=slug(name), kind=kind, vendor=vendor,
                        group=group, location="rack %d" % (index % 4 + 1),
                        community="public", version="2c", interval=30,
                        tcp_ports=[22, 161] if kind in ("switch", "router", "server") else [],
                        http_url="https://%s/" % address if kind == "server" else "",
                        tags=["demo"])
        if name in DEMO_V3:
            device.version = "3"
            device.community = ""
            device.user = DEMO_V3[name]["user"]
            device.auth = DEMO_V3[name]["auth"]
            device.auth_key = DEMO_V3[name]["auth_key"]
            device.priv = DEMO_V3[name]["priv"]
            device.priv_key = DEMO_V3[name]["priv_key"]
        device.address = address
        device.first_seen = iso()
        node = SimNode(device=device, seed=index * 31 + 7)
        node.build()
        nodes[device.key()] = node
        store.save_device(device)
    return nodes


def build_simulator(store, config, size: Optional[int] = None, seed: int = 7,
                    outage: bool = True) -> Tuple[Dict[str, SimNode], Simulator]:
    nodes = build_world(store, config, size)
    return nodes, Simulator(nodes, seed=seed, outage=outage)
