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
    version: str = "2c"                         # "1", "2c", or "3"
    community: str = "public"                   # v1/v2c only
    port: int = 161
    # ---- SNMPv3 (USM). `auth`/`priv` are protocol names ("sha256", "aes"); the keys
    # hold the passphrases, or the already-localized keys in hex when `keys_are_hex`.
    user: str = ""
    auth: str = ""
    auth_key: str = ""
    priv: str = ""
    priv_key: str = ""
    context: str = ""                           # a v3 context name; usually empty
    keys_are_hex: bool = False
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

    #: Fields that must never reach a browser, a log line, or an export by accident.
    SECRETS = ("community", "auth_key", "priv_key")

    def credentials(self) -> str:
        """What this device authenticates with, said without saying the secret."""
        if self.version == "3":
            return "v3 user %s (%s/%s)" % (self.user or "?", self.auth or "noAuth",
                                           self.priv or "noPriv")
        return "v%s community …%s" % (self.version, (self.community or "?")[-2:])

    def validate(self) -> List[str]:
        """Everything wrong with this device record, in words a person can act on.

        One function, used by the add form, the desktop dialog and `nocdeck add`, so a
        device cannot be saved by one route in a state another route would refuse.
        """
        problems: List[str] = []
        if not (self.host or "").strip():
            problems.append("an address is required (an IP or a hostname)")
        if not 0 < int(self.port or 0) < 65536:
            problems.append("port %s is not a port" % self.port)
        version = str(self.version)
        if version not in ("1", "2c", "3"):
            problems.append("version %r is not one of 1, 2c, 3" % version)
        if version == "3":
            if not (self.user or "").strip():
                problems.append("SNMPv3 needs a username — the community string is a "
                                "v1/v2c idea and v3 has none")
            if self.auth and not self.auth_key:
                problems.append("authentication protocol %s is set but no passphrase is"
                                % self.auth)
            if self.priv and not self.auth:
                problems.append("privacy (%s) requires authentication: RFC 3414 does not "
                                "allow encrypting without authenticating" % self.priv)
            if self.priv and not self.priv_key:
                problems.append("privacy protocol %s is set but no passphrase is"
                                % self.priv)
            try:
                from .snmpv3 import PRIV_PROTOCOLS, AUTH_PROTOCOLS
                if self.auth and self.auth.lower() not in AUTH_PROTOCOLS:
                    problems.append("unknown authentication protocol %r (%s)"
                                    % (self.auth, ", ".join(sorted(set(AUTH_PROTOCOLS)))))
                if self.priv and self.priv.lower() not in PRIV_PROTOCOLS:
                    problems.append("unknown privacy protocol %r (%s)"
                                    % (self.priv, ", ".join(sorted(set(PRIV_PROTOCOLS)))))
            except ImportError:                     # pragma: no cover - always present
                pass
        elif not (self.community or "").strip():
            problems.append("a v%s device needs a community string" % version)
        if int(self.interval or 0) < 5:
            problems.append("a poll interval under 5 seconds will flood a small device")
        return problems

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> Dict[str, Any]:
        """The device as a dashboard, an API response or a log line may show it.

        The passphrases stay out. A web dashboard is reachable from the network and a
        JSON response is the easiest thing in the world to leave open, so the secrets
        are replaced by whether they are set — which is all a person reading a device
        list needs to know.
        """
        data = self.as_dict()
        for field_name in self.SECRETS:
            value = data.get(field_name) or ""
            data[field_name] = ""
            data["%s_set" % field_name] = bool(value)
        return data

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False, sort_keys=True)

    @classmethod
    def from_payload(cls, payload: Dict[str, Any],
                     existing: Optional["Device"] = None) -> "Device":
        """A device built out of what a person typed into a form or a command line.

        Two rules make the difference between a form people trust and a form that
        quietly wipes their credentials:

        * A secret that was left blank keeps the one already stored. A form always
          submits its fields, so an empty passphrase box means "I did not retype it",
          not "delete it".
        * Anything the form did not mention keeps its old value, so a web form that
          knows about five fields cannot drop the ten fields it never showed.
        """
        existing = existing or cls(name="", host="")
        payload = payload or {}

        def text(name: str, fallback=None):
            if name not in payload:
                return getattr(existing, name) if fallback is None else fallback
            value = payload.get(name)
            if value is None:
                return getattr(existing, name)
            return str(value).strip()

        def number(name: str, default: int) -> int:
            raw = payload.get(name, None)
            if raw in (None, ""):
                return int(getattr(existing, name, default) or default)
            try:
                return int(str(raw).strip())
            except (TypeError, ValueError):
                return int(getattr(existing, name, default) or default)

        def flag(name: str, default: bool) -> bool:
            if name not in payload:
                return bool(getattr(existing, name, default))
            value = payload.get(name)
            if isinstance(value, str):
                return value.strip().lower() not in ("", "0", "false", "off", "no")
            return bool(value)

        def secret(name: str) -> str:
            typed = str(payload.get(name) or "").strip()
            return typed or str(getattr(existing, name, "") or "")

        def ports() -> List[int]:
            raw = payload.get("tcp_ports", None)
            if raw is None:
                return list(existing.tcp_ports)
            if isinstance(raw, str):
                raw = [part for part in raw.replace(" ", ",").split(",") if part]
            out: List[int] = []
            for part in raw:
                try:
                    port = int(part)
                except (TypeError, ValueError):
                    continue
                if 0 < port < 65536 and port not in out:
                    out.append(port)
            return out

        device = cls(
            name=text("name") or text("host") or existing.name,
            host=text("host") or existing.host,
            id=str(payload.get("id") or "").strip() or slug(text("name") or text("host")
                                                            or existing.name or ""),
            kind=text("kind") or existing.kind,
            group=text("group"), location=text("location"), notes=text("notes"),
            version=text("version") or existing.version, port=number("port", 161),
            community=secret("community"),
            user=text("user"), auth=text("auth"), auth_key=secret("auth_key"),
            priv=text("priv"), priv_key=secret("priv_key"), context=text("context"),
            keys_are_hex=flag("keys_are_hex", False),
            interval=number("interval", 60), snmp=flag("snmp", True),
            ping=flag("ping", True), snmp_only=flag("snmp_only", existing.snmp_only),
            tcp_ports=ports(), http_url=text("http_url"),
            expect_status=number("expect_status", 0),
            tls_warn_days=number("tls_warn_days", existing.tls_warn_days),
            enabled=flag("enabled", True),
            tags=[str(tag).strip() for tag in (payload.get("tags")
                                               or existing.tags or [])
                  if str(tag).strip()] if not isinstance(payload.get("tags"), str)
            else [tag.strip() for tag in str(payload.get("tags")).split(",") if tag.strip()],
        )
        device.address = str(payload.get("address") or existing.address or "").strip()
        device.first_seen = existing.first_seen or iso()
        return device

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

    #: Fields that must never reach a browser, a log line, or an export by accident.
    SECRETS = ("community", "auth_key", "priv_key")

    def credentials(self) -> str:
        """What this device authenticates with, said without saying the secret."""
        if self.version == "3":
            return "v3 user %s (%s/%s)" % (self.user or "?", self.auth or "noAuth",
                                           self.priv or "noPriv")
        return "v%s community …%s" % (self.version, (self.community or "?")[-2:])

    def validate(self) -> List[str]:
        """Everything wrong with this device record, in words a person can act on.

        One function, used by the add form, the desktop dialog and `nocdeck add`, so a
        device cannot be saved by one route in a state another route would refuse.
        """
        problems: List[str] = []
        if not (self.host or "").strip():
            problems.append("an address is required (an IP or a hostname)")
        if not 0 < int(self.port or 0) < 65536:
            problems.append("port %s is not a port" % self.port)
        version = str(self.version)
        if version not in ("1", "2c", "3"):
            problems.append("version %r is not one of 1, 2c, 3" % version)
        if version == "3":
            if not (self.user or "").strip():
                problems.append("SNMPv3 needs a username — the community string is a "
                                "v1/v2c idea and v3 has none")
            if self.auth and not self.auth_key:
                problems.append("authentication protocol %s is set but no passphrase is"
                                % self.auth)
            if self.priv and not self.auth:
                problems.append("privacy (%s) requires authentication: RFC 3414 does not "
                                "allow encrypting without authenticating" % self.priv)
            if self.priv and not self.priv_key:
                problems.append("privacy protocol %s is set but no passphrase is"
                                % self.priv)
            try:
                from .snmpv3 import PRIV_PROTOCOLS, AUTH_PROTOCOLS
                if self.auth and self.auth.lower() not in AUTH_PROTOCOLS:
                    problems.append("unknown authentication protocol %r (%s)"
                                    % (self.auth, ", ".join(sorted(set(AUTH_PROTOCOLS)))))
                if self.priv and self.priv.lower() not in PRIV_PROTOCOLS:
                    problems.append("unknown privacy protocol %r (%s)"
                                    % (self.priv, ", ".join(sorted(set(PRIV_PROTOCOLS)))))
            except ImportError:                     # pragma: no cover - always present
                pass
        elif not (self.community or "").strip():
            problems.append("a v%s device needs a community string" % version)
        if int(self.interval or 0) < 5:
            problems.append("a poll interval under 5 seconds will flood a small device")
        return problems

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> Dict[str, Any]:
        """The device as a dashboard, an API response or a log line may show it.

        The passphrases stay out. A web dashboard is reachable from the network and a
        JSON response is the easiest thing in the world to leave open, so the secrets
        are replaced by whether they are set — which is all a person reading a device
        list needs to know.
        """
        data = self.as_dict()
        for field_name in self.SECRETS:
            value = data.get(field_name) or ""
            data[field_name] = ""
            data["%s_set" % field_name] = bool(value)
        return data


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

    #: Fields that must never reach a browser, a log line, or an export by accident.
    SECRETS = ("community", "auth_key", "priv_key")

    def credentials(self) -> str:
        """What this device authenticates with, said without saying the secret."""
        if self.version == "3":
            return "v3 user %s (%s/%s)" % (self.user or "?", self.auth or "noAuth",
                                           self.priv or "noPriv")
        return "v%s community …%s" % (self.version, (self.community or "?")[-2:])

    def validate(self) -> List[str]:
        """Everything wrong with this device record, in words a person can act on.

        One function, used by the add form, the desktop dialog and `nocdeck add`, so a
        device cannot be saved by one route in a state another route would refuse.
        """
        problems: List[str] = []
        if not (self.host or "").strip():
            problems.append("an address is required (an IP or a hostname)")
        if not 0 < int(self.port or 0) < 65536:
            problems.append("port %s is not a port" % self.port)
        version = str(self.version)
        if version not in ("1", "2c", "3"):
            problems.append("version %r is not one of 1, 2c, 3" % version)
        if version == "3":
            if not (self.user or "").strip():
                problems.append("SNMPv3 needs a username — the community string is a "
                                "v1/v2c idea and v3 has none")
            if self.auth and not self.auth_key:
                problems.append("authentication protocol %s is set but no passphrase is"
                                % self.auth)
            if self.priv and not self.auth:
                problems.append("privacy (%s) requires authentication: RFC 3414 does not "
                                "allow encrypting without authenticating" % self.priv)
            if self.priv and not self.priv_key:
                problems.append("privacy protocol %s is set but no passphrase is"
                                % self.priv)
            try:
                from .snmpv3 import PRIV_PROTOCOLS, AUTH_PROTOCOLS
                if self.auth and self.auth.lower() not in AUTH_PROTOCOLS:
                    problems.append("unknown authentication protocol %r (%s)"
                                    % (self.auth, ", ".join(sorted(set(AUTH_PROTOCOLS)))))
                if self.priv and self.priv.lower() not in PRIV_PROTOCOLS:
                    problems.append("unknown privacy protocol %r (%s)"
                                    % (self.priv, ", ".join(sorted(set(PRIV_PROTOCOLS)))))
            except ImportError:                     # pragma: no cover - always present
                pass
        elif not (self.community or "").strip():
            problems.append("a v%s device needs a community string" % version)
        if int(self.interval or 0) < 5:
            problems.append("a poll interval under 5 seconds will flood a small device")
        return problems

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> Dict[str, Any]:
        """The device as a dashboard, an API response or a log line may show it.

        The passphrases stay out. A web dashboard is reachable from the network and a
        JSON response is the easiest thing in the world to leave open, so the secrets
        are replaced by whether they are set — which is all a person reading a device
        list needs to know.
        """
        data = self.as_dict()
        for field_name in self.SECRETS:
            value = data.get(field_name) or ""
            data[field_name] = ""
            data["%s_set" % field_name] = bool(value)
        return data

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

    #: Fields that must never reach a browser, a log line, or an export by accident.
    SECRETS = ("community", "auth_key", "priv_key")

    def credentials(self) -> str:
        """What this device authenticates with, said without saying the secret."""
        if self.version == "3":
            return "v3 user %s (%s/%s)" % (self.user or "?", self.auth or "noAuth",
                                           self.priv or "noPriv")
        return "v%s community …%s" % (self.version, (self.community or "?")[-2:])

    def validate(self) -> List[str]:
        """Everything wrong with this device record, in words a person can act on.

        One function, used by the add form, the desktop dialog and `nocdeck add`, so a
        device cannot be saved by one route in a state another route would refuse.
        """
        problems: List[str] = []
        if not (self.host or "").strip():
            problems.append("an address is required (an IP or a hostname)")
        if not 0 < int(self.port or 0) < 65536:
            problems.append("port %s is not a port" % self.port)
        version = str(self.version)
        if version not in ("1", "2c", "3"):
            problems.append("version %r is not one of 1, 2c, 3" % version)
        if version == "3":
            if not (self.user or "").strip():
                problems.append("SNMPv3 needs a username — the community string is a "
                                "v1/v2c idea and v3 has none")
            if self.auth and not self.auth_key:
                problems.append("authentication protocol %s is set but no passphrase is"
                                % self.auth)
            if self.priv and not self.auth:
                problems.append("privacy (%s) requires authentication: RFC 3414 does not "
                                "allow encrypting without authenticating" % self.priv)
            if self.priv and not self.priv_key:
                problems.append("privacy protocol %s is set but no passphrase is"
                                % self.priv)
            try:
                from .snmpv3 import PRIV_PROTOCOLS, AUTH_PROTOCOLS
                if self.auth and self.auth.lower() not in AUTH_PROTOCOLS:
                    problems.append("unknown authentication protocol %r (%s)"
                                    % (self.auth, ", ".join(sorted(set(AUTH_PROTOCOLS)))))
                if self.priv and self.priv.lower() not in PRIV_PROTOCOLS:
                    problems.append("unknown privacy protocol %r (%s)"
                                    % (self.priv, ", ".join(sorted(set(PRIV_PROTOCOLS)))))
            except ImportError:                     # pragma: no cover - always present
                pass
        elif not (self.community or "").strip():
            problems.append("a v%s device needs a community string" % version)
        if int(self.interval or 0) < 5:
            problems.append("a poll interval under 5 seconds will flood a small device")
        return problems

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> Dict[str, Any]:
        """The device as a dashboard, an API response or a log line may show it.

        The passphrases stay out. A web dashboard is reachable from the network and a
        JSON response is the easiest thing in the world to leave open, so the secrets
        are replaced by whether they are set — which is all a person reading a device
        list needs to know.
        """
        data = self.as_dict()
        for field_name in self.SECRETS:
            value = data.get(field_name) or ""
            data[field_name] = ""
            data["%s_set" % field_name] = bool(value)
        return data

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
