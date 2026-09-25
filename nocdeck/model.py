"""The nouns: a device, its interfaces, a reading, a threshold, a status.

Everything the tool decides is decided from these objects, and every one of them
can be written to JSON and read back — which is what makes the store, the web
dashboard, the desktop window and the tests share one vocabulary.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

#: Worst-first. `up` beats `unknown` beats `degraded` beats `down`, and the
#: dashboard sorts by it, so the sickest device is never below the fold.
STATUS_ORDER = {"down": 0, "degraded": 1, "unknown": 2, "up": 3, "maintenance": 4}
STATUS_COLOUR = {"up": "#3ddc84", "degraded": "#ffb648", "down": "#ff5f56",
                 "unknown": "#7a8b9c", "maintenance": "#5aa9e6"}


def worst(*statuses: str) -> str:
    """The status a device shows when its checks disagree."""
    known = [s for s in statuses if s]
    if not known:
        return "unknown"
    return min(known, key=lambda s: STATUS_ORDER.get(s, 2))


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(when: Optional[datetime] = None) -> str:
    return (when or now_utc()).astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(text: str) -> Optional[datetime]:
    try:
        when = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def slug(text: str) -> str:
    """A device id: stable, readable, safe in a URL and a file name."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return cleaned[:48] or "device"


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(str(text).strip())
        return True
    except ValueError:
        return False


# ------------------------------------------------------------------- thresholds


#: Some canonical metric names differ from their threshold field, because "optical"
#: on a card is "-7 dBm" and in the settings it is "optical_dbm".
THRESHOLD_FIELD = {"optical": "optical_dbm", "runtime": "runtime_min"}

#: Metrics where a *low* number is the bad one. A UPS at 100 % battery is fine; a
#: UPS at 10 % is the reason the alert exists. Optical receive power is the same
#: shape: -7 dBm is a healthy SFP and -27 dBm is a broken fibre.
LOW_IS_BAD = ("battery", "optical", "optical_dbm", "runtime", "runtime_min", "fan", "percent")


@dataclass
class Thresholds:
    """When a number stops being fine, in the direction that number actually goes.

    Each metric has one line, `warn`, and the red line sits `critical_bump` further
    along — upward for CPU, memory, temperature, disk, latency and loss, downward
    for battery, optical power, runtime and fan speed. `trouble()` is the only place
    that logic lives, so the dashboard, the events and the alerts cannot disagree.
    """

    cpu: float = 85.0
    memory: float = 90.0
    temperature: float = 70.0
    disk: float = 90.0
    battery: float = 40.0
    latency_ms: float = 200.0
    loss: float = 20.0
    optical_dbm: float = -20.0          # dBm: below this, the fibre is dying
    runtime_min: float = 10.0           # minutes of UPS runtime left
    critical_bump: float = 8.0          # how far past `warn` the red line sits

    def direction(self, metric: str) -> str:
        field = THRESHOLD_FIELD.get(metric, metric)
        return "low" if field in LOW_IS_BAD else "high"

    def limits(self, metric: str) -> Optional[tuple]:
        """`(warn, crit)`, in the order they are crossed for this metric."""
        field = THRESHOLD_FIELD.get(metric, metric)
        if field not in self.__dataclass_fields__ or field == "critical_bump":
            return None
        warn = float(getattr(self, field))
        if self.direction(metric) == "low":
            return warn, warn - abs(self.critical_bump)
        return warn, warn + abs(self.critical_bump)

    def trouble(self, metric: str, value: Optional[float]) -> Optional[str]:
        """`None`, `"degraded"` or `"critical"` for one reading. One rule, one place."""
        if value is None:
            return None
        pair = self.limits(metric)
        if pair is None:
            return None
        warn, crit = pair
        if self.direction(metric) == "low":
            if value <= crit:
                return "critical"
            return "degraded" if value <= warn else None
        if value >= crit:
            return "critical"
        return "degraded" if value >= warn else None

    def as_dict(self) -> Dict[str, float]:
        return asdict(self)


#: Sensible per-class defaults, so a printer is not alarmed at 60 °C and a server
#: is not allowed to cook. A device can always carry its own overrides.
CLASS_THRESHOLDS = {
    "server": Thresholds(cpu=90, memory=92, temperature=80, disk=88),
    "switch": Thresholds(cpu=85, memory=90, temperature=75, disk=90),
    "router": Thresholds(cpu=85, memory=90, temperature=78, disk=90),
    "firewall": Thresholds(cpu=85, memory=88, temperature=75, disk=90),
    "ups": Thresholds(battery=50, temperature=45),
    "printer": Thresholds(temperature=60, disk=95),
    "ap": Thresholds(cpu=90, memory=90, temperature=72, disk=95),
    "generic": Thresholds(),
}


def thresholds_for(kind: str, overrides: Optional[Dict[str, float]] = None) -> Thresholds:
    base = CLASS_THRESHOLDS.get(kind, CLASS_THRESHOLDS["generic"])
    values = base.as_dict()
    for key, value in (overrides or {}).items():
        if key in values and value is not None:
            values[key] = float(value)
    return Thresholds(**values)


# ----------------------------------------------------------------------- device


@dataclass
class Device:
    """One thing with an IP address."""

    name: str
    host: str                                   # what to connect to (ip or name)
    id: str = ""
    kind: str = "generic"                       # server, switch, router, ups, printer…
    group: str = ""                             # "campus", "dc-rack-3"
    location: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    enabled: bool = True

    # ---- SNMP
    snmp: bool = True
    version: str = "2c"                         # 1, 2c, or 3 (v3 is reported, not polled)
    community: str = "public"
    port: int = 161
    user: str = ""
    auth: str = ""
    priv: str = ""
    interval: int = 60                          # seconds between polls

    # ---- other checks, all optional
    ping: bool = True
    tcp_ports: List[int] = field(default_factory=list)
    http_url: str = ""
    expect_status: int = 0                      # 0 = "any 2xx/3xx"
    tls_warn_days: int = 21
    snmp_only: bool = False                     # do not ping it: SNMP is the check

    thresholds: Dict[str, float] = field(default_factory=dict)

    # ---- learned, not configured
    vendor: str = ""
    sys_name: str = ""
    sys_descr: str = ""
    sys_object_id: str = ""
    sys_location: str = ""
    sys_contact: str = ""
    address: str = ""                           # the IP it answered from
    first_seen: str = ""
    last_seen: str = ""

    # ------------------------------------------------------------------ helpers
    def key(self) -> str:
        return self.id or slug(self.name or self.host)

    def limits(self) -> Thresholds:
        return thresholds_for(self.kind, self.thresholds)

    def target(self) -> str:
        return self.address or self.host

    def alive_interval(self) -> int:
        return max(10, int(self.interval))

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Device":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in (data or {}).items() if k in known and v is not None}
        device = cls(**{k: v for k, v in clean.items() if k not in ("tags", "tcp_ports",
                                                                   "thresholds")})
        device.tags = [str(t) for t in (data.get("tags") or [])]
        device.tcp_ports = [int(p) for p in (data.get("tcp_ports") or [])]
        device.thresholds = {str(k): float(v) for k, v in (data.get("thresholds") or {}).items()
                             if isinstance(v, (int, float))}
        if not device.id:
            device.id = slug(device.name or device.host)
        return device

    @classmethod
    def from_row(cls, row) -> "Device":
        return cls.from_dict(json.loads(row["json"]))

    def match(self, needle: str) -> bool:
        """Does this device answer to a search box?"""
        text = needle.strip().lower()
        if not text:
            return True
        haystack = [self.name, self.host, self.address, self.kind, self.group,
                    self.location, self.vendor, self.sys_name, self.sys_descr,
                    self.notes, " ".join(self.tags)]
        return any(text in str(part).lower() for part in haystack if part)


# ------------------------------------------------------------------- interfaces


@dataclass
class Interface:
    index: int
    name: str = ""
    descr: str = ""
    alias: str = ""
    type: str = ""
    speed_mbps: float = 0.0
    admin: str = ""
    oper: str = ""
    in_octets: int = 0
    out_octets: int = 0
    in_bps: float = 0.0                          # filled in from two readings
    out_bps: float = 0.0
    in_util: float = 0.0                         # % of link speed
    out_util: float = 0.0
    in_errors: int = 0
    out_errors: int = 0
    in_discards: int = 0
    out_discards: int = 0
    error_delta: int = 0
    phys: str = ""
    last_change: int = 0
    mtu: int = 0

    def label(self) -> str:
        return self.alias or self.name or self.descr or ("if%d" % self.index)

    def up(self) -> bool:
        return self.oper == "up"

    def rate(self, previous: Optional["Interface"], seconds: float) -> None:
        """Octet counters into bits per second; the only arithmetic SNMP needs."""
        if previous is None or seconds <= 0:
            return
        for side in ("in", "out"):
            current = getattr(self, "%s_octets" % side)
            older = getattr(previous, "%s_octets" % side)
            if current >= older >= 0:
                bps = (current - older) * 8.0 / seconds
                setattr(self, "%s_bps" % side, bps)
                if self.speed_mbps:
                    setattr(self, "%s_util" % side,
                            round(100.0 * bps / (self.speed_mbps * 1e6), 2))
        self.error_delta = max(0, (self.in_errors + self.out_errors)
                               - (previous.in_errors + previous.out_errors))

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------- readings


@dataclass
class Reading:
    """One poll of one device."""

    device_id: str
    at: str = ""
    status: str = "unknown"
    latency_ms: Optional[float] = None
    loss: Optional[float] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    facts: Dict[str, Any] = field(default_factory=dict)     # uptime, version strings…
    checks: Dict[str, str] = field(default_factory=dict)    # per-check status
    message: str = ""
    interfaces: List[Interface] = field(default_factory=list)
    seconds: float = 0.0

    def metric(self, key: str) -> Optional[float]:
        value = self.metrics.get(key)
        return float(value) if isinstance(value, (int, float)) else None

    def uptime_seconds(self) -> Optional[float]:
        value = self.facts.get("uptime")
        if isinstance(value, (int, float)) and value > 0:
            return float(value) / 100.0 if value > 4_000_000_000 else float(value)
        return None

    def uptime_text(self) -> str:
        seconds = self.uptime_seconds()
        if seconds is None:
            return ""
        return human_seconds(seconds)

    def as_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["interfaces"] = [row.as_dict() for row in self.interfaces]
        return out


def human_seconds(seconds: float) -> str:
    seconds = int(max(0, seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return "%dd %dh" % (days, hours)
    if hours:
        return "%dh %dm" % (hours, minutes)
    return "%dm" % minutes


def human_bps(bps: float) -> str:
    for unit, size in (("G", 1e9), ("M", 1e6), ("k", 1e3)):
        if abs(bps) >= size:
            return "%.1f %sbps" % (bps / size, unit)
    return "%.0f bps" % bps


def human_bytes(value: float) -> str:
    for unit, size in (("TB", 1e12), ("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if abs(value) >= size:
            return "%.1f %s" % (value / size, unit)
    return "%.0f B" % value


# ----------------------------------------------------------------------- events


@dataclass
class Event:
    """Something that changed, which is what a person actually wants to know."""

    at: str
    device_id: str
    kind: str                    # down, up, degraded, recovered, threshold, interface
    severity: str = "warning"    # info, warning, critical
    subject: str = ""            # which metric or interface
    message: str = ""
    value: Optional[float] = None
    notified: bool = False
    detail: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        """Two events with the same fingerprint are the same trouble, still going on."""
        return "%s|%s|%s" % (self.device_id, self.kind, self.subject)


@dataclass
class AlertTarget:
    """Where a message goes."""

    kind: str                     # telegram, email, webhook
    name: str = ""
    token: str = ""               # telegram bot token
    chat_id: str = ""
    server: str = ""              # smtp host
    port: int = 587
    username: str = ""
    password: str = ""
    sender: str = ""
    to: List[str] = field(default_factory=list)
    url: str = ""                 # webhook
    method: str = "POST"
    min_severity: str = "warning"  # info, warning, critical
    enabled: bool = True
    quiet_hours: str = ""          # "23:00-07:00", local time

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertTarget":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in (data or {}).items() if k in known and v is not None}
        target = cls(**{k: v for k, v in clean.items() if k != "to"})
        target.to = [str(x) for x in (data.get("to") or [])]
        return target


SEVERITY_ORDER = {"info": 0, "warning": 1, "critical": 2}


def severity_at_least(severity: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(severity, 1) >= SEVERITY_ORDER.get(floor, 1)
