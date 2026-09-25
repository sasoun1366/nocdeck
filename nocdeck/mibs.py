"""What the numbers mean: the OID knowledge this tool carries with it.

Two layers, and the difference between them is the reason this file exists.

**The standard layer** works on almost anything with an IP: `SNMPv2-MIB` for the
identity and uptime, `IF-MIB` for every interface, `HOST-RESOURCES-MIB` for CPU,
memory and disks on servers, `UCD-SNMP-MIB` for the same on Linux, and
`ENTITY-SENSOR-MIB` for temperatures, fans, voltages and optical power in dBm.
A device that speaks only standards still shows up as a full page.

**The vendor layer** is for the numbers the standards do not carry — the exact
CPU and temperature registers of a RouterOS box, a Cisco chassis, a FortiGate, a
Huawei switch, an APC UPS, a printer's toner. Each row is one OID and what to call
it; when a device answers, the row is used, and when it does not, it is simply
absent. Nothing here is guessed: an OID that is not in a table is not requested.

The table is data, not code, so an estate with something unusual can extend it
without touching the tool: drop a JSON file in `~/.nocdeck/mibs/` and it is merged
in at start-up (see `custom_rows`).
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

# --------------------------------------------------------------------- identity

SYS = {
    "descr": "1.3.6.1.2.1.1.1.0",
    "object_id": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "contact": "1.3.6.1.2.1.1.4.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
    "services": "1.3.6.1.2.1.1.7.0",
}
SYSTEM_SCALARS = list(SYS.values())

# ------------------------------------------------------------------ interface

IF = {
    "index": "1.3.6.1.2.1.2.2.1.1",
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "type": "1.3.6.1.2.1.2.2.1.3",
    "mtu": "1.3.6.1.2.1.2.2.1.4",
    "speed": "1.3.6.1.2.1.2.2.1.5",
    "phys_address": "1.3.6.1.2.1.2.2.1.6",
    "admin_status": "1.3.6.1.2.1.2.2.1.7",
    "oper_status": "1.3.6.1.2.1.2.2.1.8",
    "last_change": "1.3.6.1.2.1.2.2.1.9",
    "in_octets": "1.3.6.1.2.1.2.2.1.10",
    "out_octets": "1.3.6.1.2.1.2.2.1.16",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
    "in_discards": "1.3.6.1.2.1.2.2.1.13",
    "out_discards": "1.3.6.1.2.1.2.2.1.19",
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "alias": "1.3.6.1.2.1.31.1.1.1.18",          # the human name: "uplink to core"
    "high_speed": "1.3.6.1.2.1.31.1.1.1.15",      # Mbps, survives above 4 Gbps
    "hc_in_octets": "1.3.6.1.2.1.31.1.1.1.6",     # 64-bit counters: no wrap every 5 min
    "hc_out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "promiscuous": "1.3.6.1.2.1.31.1.1.1.16",
    "connector": "1.3.6.1.2.1.31.1.1.1.17",
}
#: Walked in this order, and each root is the *column*, so `rows()` can line them up.
INTERFACE_COLUMNS = [
    ("name", IF["name"]), ("descr", IF["descr"]), ("alias", IF["alias"]),
    ("type", IF["type"]), ("speed", IF["high_speed"]), ("speed_low", IF["speed"]),
    ("admin", IF["admin_status"]), ("oper", IF["oper_status"]),
    ("in_octets", IF["hc_in_octets"]), ("out_octets", IF["hc_out_octets"]),
    ("in_octets_low", IF["in_octets"]), ("out_octets_low", IF["out_octets"]),
    ("in_errors", IF["in_errors"]), ("out_errors", IF["out_errors"]),
    ("in_discards", IF["in_discards"]), ("out_discards", IF["out_discards"]),
    ("phys", IF["phys_address"]), ("last_change", IF["last_change"]),
    ("mtu", IF["mtu"]),
]

#: ifType values worth spelling out — the rest are shown as their number.
IFTYPE = {
    6: "ethernet", 7: "802.3", 1: "other", 24: "loopback", 131: "tunnel",
    53: "propVirtual", 161: "lag", 135: "l2vlan", 136: "l3ipvlan", 23: "ppp",
    71: "wifi", 136: "ipVlan", 62: "fastEthernet", 117: "gigabitEthernet",
    13: "ddd", 54: "propMultiplexor", 105: "bridge", 161: "ieee8023adLag",
}
IFADMIN = {1: "up", 2: "down", 3: "testing"}
IFOPER = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant", 6: "notPresent",
          7: "lowerLayerDown"}

# --------------------------------------------------------------- host resources

HR = {
    "uptime": "1.3.6.1.2.1.25.1.1.0",
    "processes": "1.3.6.1.2.1.25.1.6.0",
    "users": "1.3.6.1.2.1.25.1.5.0",
    "cpu_load": "1.3.6.1.2.1.25.3.3.1.2",                 # per processor, %
    "cpu_descr": "1.3.6.1.2.1.25.3.2.1.3",
    "storage_descr": "1.3.6.1.2.1.25.2.3.1.3",
    "storage_alloc": "1.3.6.1.2.1.25.2.3.1.4",
    "storage_size": "1.3.6.1.2.1.25.2.3.1.5",
    "storage_used": "1.3.6.1.2.1.25.2.3.1.6",
    "storage_type": "1.3.6.1.2.1.25.2.3.1.2",
    "run_name": "1.3.6.1.2.1.25.4.2.1.2",
    "run_cpu": "1.3.6.1.2.1.25.5.1.1.1",
    "run_mem": "1.3.6.1.2.1.25.5.1.1.2",
}
HR_TABLES = ["cpu_load", "storage_descr", "storage_size", "storage_used", "storage_alloc"]

# -------------------------------------------------------------- linux / net-snmp

UCD = {
    "cpu_user": "1.3.6.1.4.1.2021.11.9.0",
    "cpu_system": "1.3.6.1.4.1.2021.11.10.0",
    "cpu_idle": "1.3.6.1.4.1.2021.11.11.0",
    "load_1": "1.3.6.1.4.1.2021.10.1.3.1",
    "load_5": "1.3.6.1.4.1.2021.10.1.3.2",
    "load_15": "1.3.6.1.4.1.2021.10.1.3.3",
    "mem_total": "1.3.6.1.4.1.2021.4.5.0",
    "mem_avail": "1.3.6.1.4.1.2021.4.6.0",
    "mem_buffers": "1.3.6.1.4.1.2021.4.14.0",
    "mem_cached": "1.3.6.1.4.1.2021.4.15.0",
    "swap_total": "1.3.6.1.4.1.2021.4.3.0",
    "swap_avail": "1.3.6.1.4.1.2021.4.4.0",
    "disk_path": "1.3.6.1.4.1.2021.9.1.2",
    "disk_device": "1.3.6.1.4.1.2021.9.1.3",
    "disk_total": "1.3.6.1.4.1.2021.9.1.6",
    "disk_avail": "1.3.6.1.4.1.2021.9.1.7",
    "disk_percent": "1.3.6.1.4.1.2021.9.1.9",
}
UCD_TABLES = ["disk_path", "disk_total", "disk_avail", "disk_percent"]

# ------------------------------------------------------------------- sensors

ENTITY_SENSOR = {
    "type": "1.3.6.1.2.1.99.1.1.1.1",
    "scale": "1.3.6.1.2.1.99.1.1.1.2",
    "precision": "1.3.6.1.2.1.99.1.1.1.3",
    "value": "1.3.6.1.2.1.99.1.1.1.4",
    "status": "1.3.6.1.2.1.99.1.1.1.5",
    "name": "1.3.6.1.2.1.47.1.1.1.1.7",            # entPhysicalName, same index
    "descr": "1.3.6.1.2.1.47.1.1.1.1.2",
}
ENTITY_SENSOR_TABLES = ["type", "value", "scale", "precision", "status", "name"]

#: entPhySensorType → the canonical metric it feeds, and the unit to print.
SENSOR_TYPES = {
    3: ("voltage", "V"), 4: ("voltage", "V"), 5: ("current", "A"), 6: ("power", "W"),
    7: ("frequency", "Hz"), 8: ("temperature", "°C"), 9: ("humidity", "%RH"),
    10: ("fan", "rpm"), 12: ("truth", ""), 14: ("optical", "dBm"),
    15: ("optical", "dBm"), 16: ("optical", "dBm"), 17: ("optical", "dBm"),
}
SENSOR_STATUS = {1: "ok", 2: "unavailable", 3: "nonoperational"}

#: entPhySensorScale → the power of ten the value is multiplied by.
SENSOR_SCALE = {1: 1e-9, 2: 1e-6, 3: 1e-3, 4: 1e-2, 5: 1e-1, 6: 1, 7: 10, 8: 100,
                9: 1000, 10: 10000, 11: 100000, 12: 1000000, 13: 10000000,
                14: 100000000, 15: 1000000000}

# ---------------------------------------------------------------- power over ethernet

POE = {
    "port_enable": "1.3.6.1.2.1.105.1.1.1.3",
    "port_detect": "1.3.6.1.2.1.105.1.1.1.6",
    "port_class": "1.3.6.1.2.1.105.1.1.1.10",
    "main_power": "1.3.6.1.2.1.105.1.3.1.1.4",     # watts, whole PSE
}
POE_DETECT = {1: "disabled", 2: "searching", 3: "delivering", 4: "fault", 5: "test",
              6: "otherFault"}

# ------------------------------------------------------------------- vendor rows


@dataclass
class Metric:
    """One number a device can be asked for, and how to present it."""

    key: str                      # canonical: cpu, memory, temperature, …
    label: str                    # what the dashboard prints
    oid: str
    unit: str = ""
    divisor: float = 1.0          # some agents report hundredths of a degree
    vendor: str = ""              # which family this row belongs to
    table: bool = False           # does the OID start more than one row?
    note: str = ""

    def value_of(self, raw) -> Optional[float]:
        if raw is None:
            return None
        if isinstance(raw, str):
            raw = raw.strip()
            if not raw:
                return None
            try:
                raw = float(raw)
            except ValueError:
                return None
        if isinstance(raw, (bytes, bytearray)):
            return None
        if isinstance(raw, bool):
            raw = int(raw)
        if not isinstance(raw, (int, float)):
            return None
        return float(raw) / self.divisor if self.divisor != 1.0 else float(raw)


#: The vendor table. One row per OID; `vendor` is matched against the fingerprint,
#: and an empty vendor means "standard — ask everyone". Everything here is a scalar
#: unless `table=True`, in which case the whole subtree is walked and the metric is
#: summarised (max for temperature, mean for cpu, sum for watts).
VENDOR_METRICS: List[Metric] = [
    # ---- MikroTik RouterOS (mtxrHealth)
    Metric("cpu", "CPU load", "1.3.6.1.4.1.14988.1.1.3.14.0", "%", vendor="mikrotik"),
    Metric("temperature", "Board temperature", "1.3.6.1.4.1.14988.1.1.3.10.0", "°C",
           vendor="mikrotik"),
    Metric("temperature", "CPU temperature", "1.3.6.1.4.1.14988.1.1.3.11.0", "°C",
           vendor="mikrotik"),
    Metric("voltage", "Board voltage", "1.3.6.1.4.1.14988.1.1.3.8.0", "V",
           divisor=10.0, vendor="mikrotik"),
    Metric("voltage", "Core voltage", "1.3.6.1.4.1.14988.1.1.3.3.0", "V",
           divisor=10.0, vendor="mikrotik"),
    Metric("power", "PSU voltage", "1.3.6.1.4.1.14988.1.1.3.5.0", "V",
           divisor=10.0, vendor="mikrotik"),
    Metric("fan", "Fan speed", "1.3.6.1.4.1.14988.1.1.3.7.0", "rpm", vendor="mikrotik"),
    Metric("frequency", "CPU frequency", "1.3.6.1.4.1.14988.1.1.3.9.0", "MHz",
           vendor="mikrotik"),
    Metric("uptime", "Uptime", "1.3.6.1.2.1.1.3.0", "s", vendor=""),
    Metric("sessions", "Active sessions", "1.3.6.1.4.1.14988.1.1.8.1.0", "",
           vendor="mikrotik"),
    Metric("temperature", "SFP temperature", "1.3.6.1.4.1.14988.1.1.19.1.1.2", "°C",
           vendor="mikrotik", table=True),
    Metric("optical", "SFP Rx power", "1.3.6.1.4.1.14988.1.1.19.1.1.3", "dBm",
           divisor=1000.0, vendor="mikrotik", table=True),
    Metric("optical", "SFP Tx power", "1.3.6.1.4.1.14988.1.1.19.1.1.4", "dBm",
           divisor=1000.0, vendor="mikrotik", table=True),

    # ---- Cisco (IOS / IOS-XE / NX-OS)
    Metric("cpu", "CPU 5-minute", "1.3.6.1.4.1.9.9.109.1.1.1.1.8", "%", vendor="cisco",
           table=True),
    Metric("cpu", "CPU (older IOS)", "1.3.6.1.4.1.9.2.1.56.0", "%", vendor="cisco"),
    Metric("memory", "Memory used (%)", "1.3.6.1.4.1.9.9.48.1.1.1.5", "bytes",
           vendor="cisco", table=True),
    Metric("memory", "Memory free (bytes)", "1.3.6.1.4.1.9.9.48.1.1.1.6", "bytes",
           vendor="cisco", table=True),
    Metric("temperature", "Chassis temperature", "1.3.6.1.4.1.9.9.13.1.3.1.3", "°C",
           vendor="cisco", table=True),
    Metric("fan", "Fan state", "1.3.6.1.4.1.9.9.13.1.4.1.3", "", vendor="cisco",
           table=True),
    Metric("voltage", "Supply voltage", "1.3.6.1.4.1.9.9.13.1.5.1.3", "mV",
           divisor=1000.0, vendor="cisco", table=True),
    Metric("power", "Power supply state", "1.3.6.1.4.1.9.9.13.1.6.1.3", "", vendor="cisco",
           table=True),

    # ---- HPE / Aruba (ProCurve + Comware)
    Metric("cpu", "CPU utilisation", "1.3.6.1.4.1.11.2.14.11.5.1.9.5.0", "%",
           vendor="hpe"),
    Metric("memory", "Memory free (%)", "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.1.3.0", "%",
           vendor="hpe"),
    Metric("temperature", "Chassis temperature", "1.3.6.1.4.1.11.2.14.11.1.2.6.1.4.0", "°C",
           vendor="hpe"),
    # ---- Aruba / ArubaOS-Switch
    Metric("cpu", "CPU utilisation", "1.3.6.1.4.1.14823.2.2.1.1.1.3.1.1.10.0", "%",
           vendor="aruba"),

    # ---- Ubiquiti (UniFi switches and APs)
    Metric("temperature", "Board temperature", "1.3.6.1.4.1.41112.1.6.3.5.0", "°C",
           vendor="ubiquiti"),
    Metric("memory", "Memory used", "1.3.6.1.4.1.10002.1.1.1.4.2.1.6.0", "%",
           vendor="ubiquiti"),

    # ---- Juniper (Junos)
    Metric("cpu", "CPU (RE)", "1.3.6.1.4.1.2636.3.1.13.1.8.9.1.0.0", "%", vendor="juniper",
           table=True),
    Metric("temperature", "Temperature", "1.3.6.1.4.1.2636.3.1.13.1.7", "°C",
           vendor="juniper", table=True),
    Metric("memory", "Memory (RE)", "1.3.6.1.4.1.2636.3.1.13.1.11", "%", vendor="juniper",
           table=True),

    # ---- Huawei (VRP)
    Metric("cpu", "CPU usage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.5", "%", vendor="huawei",
           table=True),
    Metric("memory", "Memory usage", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.7", "%",
           vendor="huawei", table=True),
    Metric("temperature", "Temperature", "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.11", "°C",
           vendor="huawei", table=True),

    # ---- Fortinet (FortiGate)
    Metric("cpu", "CPU usage", "1.3.6.1.4.1.12356.101.4.1.3.0", "%", vendor="fortinet"),
    Metric("memory", "Memory usage", "1.3.6.1.4.1.12356.101.4.1.4.0", "%",
           vendor="fortinet"),
    Metric("sessions", "Sessions", "1.3.6.1.4.1.12356.101.4.1.8.0", "", vendor="fortinet"),
    Metric("temperature", "Temperature", "1.3.6.1.4.1.12356.101.4.1.10.0", "°C",
           vendor="fortinet"),

    # ---- APC (UPS) — the device that tells you the room lost power
    Metric("battery", "Battery capacity", "1.3.6.1.4.1.318.1.1.1.2.2.1.0", "%", vendor="apc"),
    Metric("temperature", "Battery temperature", "1.3.6.1.4.1.318.1.1.1.2.2.2.0", "°C",
           vendor="apc"),
    Metric("runtime", "Runtime left", "1.3.6.1.4.1.318.1.1.1.2.2.3.0", "min",
           divisor=6000.0, vendor="apc"),
    Metric("voltage", "Input voltage", "1.3.6.1.4.1.318.1.1.1.3.2.1.0", "V", vendor="apc"),
    Metric("power", "Output load", "1.3.6.1.4.1.318.1.1.1.4.2.3.0", "%", vendor="apc"),
    Metric("temperature", "Ambient temperature", "1.3.6.1.4.1.318.1.1.1.2.2.2.0", "°C",
           vendor="apc"),

    # ---- VMware ESXi
    Metric("cpu", "CPU usage", "1.3.6.1.4.1.6876.3.1.1.4.0", "MHz", vendor="vmware"),
    Metric("memory", "Memory used", "1.3.6.1.4.1.6876.3.1.1.6.0", "MB", vendor="vmware"),
    Metric("uptime", "Uptime", "1.3.6.1.4.1.6876.1.1.0", "s", vendor="vmware"),

    # ---- Dell iDRAC (servers)
    Metric("temperature", "Ambient temperature", "1.3.6.1.4.1.674.10892.5.4.700.20.1.6.1.1",
           "°C", vendor="dell"),
    Metric("fan", "Fan speed", "1.3.6.1.4.1.674.10892.5.4.700.12.1.6", "rpm", vendor="dell",
           table=True),
    Metric("power", "System power", "1.3.6.1.4.1.674.10892.5.4.600.30.1.6.1.3", "W",
           vendor="dell"),

    # ---- printers (RFC 3805) — toner, and whether the paper is out
    Metric("disk", "Marker life count", "1.3.6.1.2.1.43.10.2.1.4.1.1", "pages",
           vendor="printer"),
    Metric("percent", "Supply remaining", "1.3.6.1.2.1.43.11.1.1.9.1", "%",
           vendor="printer", table=True),
]

#: MIB text for the fingerprint, longest first, so "Cisco IOS-XE" beats "Cisco".
FINGERPRINTS = [
    ("mikrotik", ("routeros", "mikrotik")),
    ("cisco", ("cisco ios", "ios-xe", "ios xe", "cisco systems", "nx-os", "catalyst",
               "cisco")),
    ("juniper", ("junos", "juniper")),
    ("huawei", ("huawei", "vrp")),
    ("fortinet", ("fortigate", "fortios", "fortinet")),
    ("hpe", ("procurve", "hewlett", "hpe", "hp ") ),
    ("aruba", ("aruba",)),
    ("ubiquiti", ("unifi", "ubiquiti", "edgeos", "airmax")),
    ("apc", ("apc ", "american power", "smart-ups", "ups")),
    ("vmware", ("vmware", "esxi")),
    ("dell", ("idrac", "dell", "poweredge")),
    ("printer", ("printer", "laserjet", "kyocera", "ricoh", "canon i", "xerox", "epson")),
    ("linux", ("linux", "ubuntu", "debian", "centos", "rhel", "fedora", "net-snmp")),
    ("windows", ("windows", "microsoft")),
    ("tp-link", ("tp-link", "tplink")),
    ("zyxel", ("zyxel",)),
    ("arista", ("arista", "eos")),
    ("extreme", ("extreme networks", "extremexos")),
    ("synology", ("synology", "dsm")),
    ("qnap", ("qnap",)),
    ("paloalto", ("palo alto", "pan-os")),
    ("checkpoint", ("check point", "checkpoint",)),
    ("sonicwall", ("sonicwall",)),
    ("netgear", ("netgear",)),
    ("ruckus", ("ruckus",)),
    ("brocade", ("brocade",)),
    ("avaya", ("avaya",)),
    ("sophos", ("sophos", "xg firewall")),
    ("mcafee", ("mcafee",)),
]


def fingerprint(descr: str = "", object_id: str = "") -> str:
    """Which family of gear this is, from what it says about itself.

    `sysDescr` is the useful one — "RouterOS RB4011", "Cisco IOS Software, C2960" —
    and `sysObjectID` catches the rest, because vendor enterprise numbers live at
    the front of it.
    """
    text = ("%s %s" % (descr or "", object_id or "")).lower()
    for family, needles in FINGERPRINTS:
        for needle in needles:
            if needle in text:
                return family
    # Nothing in the description: read the enterprise number off sysObjectID. Longest
    # prefix first, because 1.3.6.1.4.1.9 (Cisco) is a prefix of nobody else's, but a
    # vendor with a deeper arc must win over one whose arc merely starts the same way.
    oid = str(object_id or "")
    for prefix in sorted(ENTERPRISE, key=len, reverse=True):
        if oid.startswith(prefix + "."):
            return ENTERPRISE[prefix]
    return "generic"


ENTERPRISE = {
    "1.3.6.1.4.1.14988": "mikrotik", "1.3.6.1.4.1.9": "cisco", "1.3.6.1.4.1.2636": "juniper",
    "1.3.6.1.4.1.2011": "huawei", "1.3.6.1.4.1.12356": "fortinet",
    "1.3.6.1.4.1.11": "hpe", "1.3.6.1.4.1.14823": "aruba",
    "1.3.6.1.4.1.41112": "ubiquiti", "1.3.6.1.4.1.10002": "ubiquiti",
    "1.3.6.1.4.1.318": "apc", "1.3.6.1.4.1.6876": "vmware", "1.3.6.1.4.1.674": "dell",
    "1.3.6.1.4.1.1916": "extreme", "1.3.6.1.4.1.30065": "arista",
    "1.3.6.1.4.1.6574": "synology", "1.3.6.1.4.1.24681": "qnap",
    "1.3.6.1.4.1.25461": "paloalto", "1.3.6.1.4.1.2620": "checkpoint",
    "1.3.6.1.4.1.8741": "sonicwall", "1.3.6.1.4.1.4526": "netgear",
    "1.3.6.1.4.1.25053": "ruckus", "1.3.6.1.4.1.1588": "brocade",
    "1.3.6.1.4.1.11863": "tp-link",
}


def vendor_from_oid(object_id: Optional[str]) -> str:
    if not object_id:
        return ""
    for prefix, family in sorted(ENTERPRISE.items(), key=lambda row: -len(row[0])):
        if object_id.startswith(prefix):
            return family
    return ""


# ------------------------------------------------------------------ the ask list


def metrics_for(vendor: str, extras: Sequence[Metric] = ()) -> List[Metric]:
    """Every row to try on a device of this family: standard rows plus its own."""
    wanted: List[Metric] = []
    for row in list(VENDOR_METRICS) + list(extras):
        if row.vendor and row.vendor != vendor:
            continue
        wanted.append(row)
    return wanted


def scalar_oids(vendor: str, extras: Sequence[Metric] = ()) -> List[str]:
    return [row.oid for row in metrics_for(vendor, extras) if not row.table]


def table_roots(vendor: str, extras: Sequence[Metric] = ()) -> List[str]:
    roots = [row.oid for row in metrics_for(vendor, extras) if row.table]
    roots += [IF[column[1]] for column in INTERFACE_COLUMNS if "hc_" in column[1] or True]
    return _unique(roots)


def standard_table_roots() -> List[str]:
    """The walks that are worth doing on *any* device, vendor or not."""
    roots = [IF[name] for name in ("name", "descr", "alias", "type", "high_speed", "speed",
                                   "admin_status", "oper_status", "hc_in_octets",
                                   "hc_out_octets", "in_octets", "out_octets", "in_errors",
                                   "out_errors", "in_discards", "out_discards",
                                   "phys_address", "last_change")]
    roots += [HR[name] for name in HR_TABLES] + [UCD[name] for name in UCD_TABLES]
    roots += [ENTITY_SENSOR[name] for name in ENTITY_SENSOR_TABLES]
    roots += [POE["port_detect"], POE["port_enable"]]
    return _unique(roots)


def _unique(items: Iterable[str]) -> List[str]:
    out: List[str] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


# ------------------------------------------------------------------ the reverse map

LABELS: Dict[str, str] = {
    SYS["descr"]: "description", SYS["object_id"]: "object id", SYS["uptime"]: "uptime",
    SYS["name"]: "name", SYS["location"]: "location", SYS["contact"]: "contact",
    HR["processes"]: "processes", HR["users"]: "logged-in users",
    UCD["cpu_idle"]: "CPU idle", UCD["load_1"]: "load (1 min)",
    ENTITY_SENSOR["value"]: "sensor value",
}
for _row in VENDOR_METRICS:
    LABELS.setdefault(_row.oid, _row.label)
for _key, _oid in IF.items():
    LABELS.setdefault(_oid, "if%s" % _key.replace("_", "-"))
for _key, _oid in POE.items():
    LABELS.setdefault(_oid, "PoE %s" % _key.replace("_", " "))


def label_for(oid: str) -> str:
    """A human name for an OID, best effort, without shipping a compiler."""
    if oid in LABELS:
        return LABELS[oid]
    if oid.startswith("1.3.6.1.4.1."):
        parts = oid.split(".")
        family = vendor_from_oid(oid)
        return "%s enterprise OID …%s" % (family or "vendor", ".".join(parts[-3:]))
    if oid.startswith("1.3.6.1.2.1."):
        return "standard OID …%s" % ".".join(oid.split(".")[-3:])
    return oid


# ------------------------------------------------------------------ custom rows


def custom_rows(home: Optional[pathlib.Path] = None) -> List[Metric]:
    """Extra OIDs from `~/.nocdeck/mibs/*.json`.

    The file is either a list of rows, or an object with a `metrics` list. A row
    needs `key`, `label` and `oid`; `vendor`, `unit`, `divisor` and `table` are
    optional. Anything malformed is skipped rather than crashing a poll: this is a
    file people will hand-edit at two in the morning.
    """
    if home is None:
        import os
        home = pathlib.Path(os.environ.get("NOCDECK_HOME") or "~/.nocdeck").expanduser()
    folder = pathlib.Path(home) / "mibs"
    rows: List[Metric] = []
    if not folder.is_dir():
        return rows
    for path in sorted(folder.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        entries = data.get("metrics") if isinstance(data, dict) else data
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            try:
                rows.append(Metric(
                    key=str(entry["key"]), label=str(entry.get("label") or entry["key"]),
                    oid=str(entry["oid"]), unit=str(entry.get("unit") or ""),
                    divisor=float(entry.get("divisor") or 1.0),
                    vendor=str(entry.get("vendor") or ""),
                    table=bool(entry.get("table"))))
            except (KeyError, TypeError, ValueError):
                continue
    return rows


# ------------------------------------------------------------------- canonical

#: The metrics a device card can show, in the order they are ranked for display.
CANONICAL = ("cpu", "memory", "temperature", "fan", "voltage", "power", "optical",
             "disk", "battery", "runtime", "sessions", "load", "humidity", "frequency",
             "percent")
