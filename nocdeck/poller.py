"""The engine: read a device, decide what it means, write it down, shout if needed.

The shape of one poll:

1. **Ask** — SNMP (identity, health, every interface), ping, the ports, the URL, all
   at once, because a device with four checks must cost one timeout, not four.
2. **Decide** — the checks become one status, worst-first, with hysteresis: two
   failures before `down`, two successes before `up` again. One lost packet is not
   an outage and a dashboard that says it is will be ignored.
3. **Write** — the reading goes into `samples`, the ports into `interfaces`, and the
   hourly rollup is updated.
4. **Tell** — a *transition* becomes an event, and events go to the alert targets.

Everything here is injectable: the SNMP client, the probes and the clock. That is
how the test suite exercises the whole engine without a network, and how the demo
mode makes a dashboard full of imaginary switches do interesting things.
"""

from __future__ import annotations

import concurrent.futures as futures
import json
import statistics
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import mibs, probe
from .model import (Device, Event, Interface, Reading, human_bps, human_bytes, iso, now_utc,
                    parse_iso, worst)
from .snmp import Agent, Client, SnmpError, VarBind

#: How a table-shaped metric collapses into one number. Temperature hurts at its
#: hottest, a fan is a warning at its slowest, optical power is bad when it is low.
REDUCERS = {
    "temperature": max, "fan": min, "optical": min, "battery": min, "runtime": min,
    "cpu": statistics.mean, "memory": max, "voltage": statistics.mean,
    "power": sum, "current": statistics.mean, "frequency": max, "sessions": sum,
    "load": max, "humidity": max, "disk": max, "percent": min, "uptime": max,
}


def reduce_metric(key: str, values: Sequence[float]) -> Optional[float]:
    if not values:
        return None
    reducer = REDUCERS.get(key, statistics.mean)
    try:
        return float(reducer(values))
    except (statistics.StatisticsError, TypeError, ValueError):
        return None


# ------------------------------------------------------------------- SNMP reading


@dataclass
class SnmpReading:
    """What one SNMP conversation produced."""

    ok: bool = False
    metrics: Dict[str, float] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    facts: Dict[str, object] = field(default_factory=dict)
    interfaces: List[Interface] = field(default_factory=list)
    sensors: List[Dict[str, object]] = field(default_factory=list)
    filesystems: List[Dict[str, object]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    seconds: float = 0.0
    vendor: str = ""


def _index_of(oid: str, root: str) -> Optional[int]:
    """The table row an OID belongs to — the arc after the column."""
    if not oid.startswith(root + "."):
        return None
    tail = oid[len(root) + 1:]
    first = tail.split(".", 1)[0]
    return int(first) if first.isdigit() else None


def match_columns(walked: Dict[str, List[VarBind]]) -> Dict[str, Dict[int, VarBind]]:
    """`{column-root: {row-index: varbind}}` — the shape every table builder wants."""
    out: Dict[str, Dict[int, VarBind]] = {}
    for root, binds in walked.items():
        column: Dict[int, VarBind] = {}
        for bind in binds:
            index = _index_of(bind.oid, root)
            if index is not None:
                column[index] = bind
        out[root] = column
    return out


def build_interfaces(columns: Dict[str, Dict[int, VarBind]]) -> List[Interface]:
    """IF-MIB columns into port objects, high-capacity counters preferred."""
    wanted = {root: key for key, root in mibs.INTERFACE_COLUMNS}
    rows: Dict[int, Interface] = {}
    for root, column in columns.items():
        key = wanted.get(root)
        if not key:
            continue
        for index, bind in column.items():
            row = rows.get(index) or (rows.setdefault(index, Interface(index=index)))
            if key in ("in_octets", "out_octets"):
                # 64-bit counters when the device has them, 32-bit when it does not
                setattr(row, key, int(bind.as_int() or 0))
            elif key == "in_octets_low":
                if not row.in_octets:
                    row.in_octets = int(bind.as_int() or 0)
            elif key == "out_octets_low":
                if not row.out_octets:
                    row.out_octets = int(bind.as_int() or 0)
            elif key == "speed":
                row.speed_mbps = float(bind.as_int() or 0)
            elif key == "speed_low":
                if not row.speed_mbps:
                    row.speed_mbps = float(bind.as_int() or 0) / 1e6
            elif key == "type":
                code = bind.as_int(0) or 0
                row.type = mibs.IFTYPE.get(code, "type-%d" % code)
            elif key == "admin":
                row.admin = mibs.IFADMIN.get(bind.as_int(0) or 0, "?")
            elif key == "oper":
                row.oper = mibs.IFOPER.get(bind.as_int(0) or 0, "?")
            elif key in ("name", "descr", "alias", "phys"):
                setattr(row, key, bind.as_text().strip())
            else:
                setattr(row, key, int(bind.as_int() or 0))
    out = [row for index, row in sorted(rows.items()) if row.name or row.descr]
    for row in out:
        if not row.name:
            row.name = row.descr or ("if%d" % row.index)
        if row.speed_mbps and row.speed_mbps < 1000:
            row.speed_mbps = float(round(row.speed_mbps))
    return out


def build_storage(columns: Dict[str, Dict[int, VarBind]], walked: Dict[str, List[VarBind]]
                  ) -> Tuple[List[Dict[str, object]], Dict[str, float]]:
    """Filesystems from HOST-RESOURCES or UCD — whichever the device answers.

    Servers give both; switches give neither. The percentage is what the dashboard
    watches, the names are what the detail page lists.
    """
    filesystems: List[Dict[str, object]] = []
    metrics: Dict[str, float] = {}

    def add(name: str, total: Optional[float], used: Optional[float],
            percent: Optional[float] = None, source: str = "") -> None:
        if total is None and used is None and percent is None:
            return
        if percent is None and total and used is not None:
            percent = round(100.0 * used / total, 1)
        filesystems.append({"name": name, "total": total, "used": used,
                            "percent": percent, "source": source})
        if percent is not None:
            metrics["disk"] = max(metrics.get("disk", 0.0), float(percent))

    # HOST-RESOURCES-MIB
    descr = columns.get(mibs.HR["storage_descr"], {})
    size = columns.get(mibs.HR["storage_size"], {})
    used = columns.get(mibs.HR["storage_used"], {})
    alloc = columns.get(mibs.HR["storage_alloc"], {})
    for index, bind in descr.items():
        unit = float((alloc.get(index).as_int(1) if alloc.get(index) else 1) or 1)
        total = (size.get(index).as_int() if size.get(index) else None)
        user = (used.get(index).as_int() if used.get(index) else None)
        name = bind.as_text().strip()
        if total is None:
            continue
        if name.lower().startswith(("physical memory", "virtual memory", "swap")):
            continue
        add(name, total * unit, (user * unit) if user is not None else None, source="hr")

    # UCD-SNMP-MIB: the Linux filesystems, with the percentage already computed
    ucd_path = columns.get(mibs.UCD["disk_path"], {})
    ucd_total = columns.get(mibs.UCD["disk_total"], {})
    ucd_avail = columns.get(mibs.UCD["disk_avail"], {})
    ucd_percent = columns.get(mibs.UCD["disk_percent"], {})
    for index, bind in ucd_path.items():
        total = ucd_total.get(index).as_int() if ucd_total.get(index) else None
        avail = ucd_avail.get(index).as_int() if ucd_avail.get(index) else None
        percent = ucd_percent.get(index).as_int() if ucd_percent.get(index) else None
        add(bind.as_text().strip(), total, (total - avail) if total and avail else None,
            percent=percent, source="ucd")

    # Memory from UCD, if it is there
    total = _int_at(walked, mibs.UCD["mem_total"])
    avail = _int_at(walked, mibs.UCD["mem_avail"])
    if total:
        used_bytes = max(0, total - (avail or 0))
        metrics["memory"] = round(100.0 * used_bytes / total, 1)
        metrics["memory_total"] = float(total)
    return filesystems, metrics


def _int_at(walked: Dict[str, List[VarBind]], oid: str) -> Optional[int]:
    for bind in walked.get(oid, []):
        value = bind.as_int()
        if value is not None:
            return value
    return None


def build_sensors(columns: Dict[str, Dict[int, VarBind]]) -> Tuple[List[Dict[str, object]],
                                                                    Dict[str, float]]:
    """ENTITY-SENSOR-MIB: every temperature, fan, voltage and dBm the box knows about.

    This is the vendor-neutral win. A switch nobody has ever written a table for
    still reports its SFP receive power in dBm as sensor type 14, and its chassis
    temperature as type 8.
    """
    sensors: List[Dict[str, object]] = []
    metrics: Dict[str, List[float]] = {}
    kinds = columns.get(mibs.ENTITY_SENSOR["type"], {})
    values = columns.get(mibs.ENTITY_SENSOR["value"], {})
    scales = columns.get(mibs.ENTITY_SENSOR["scale"], {})
    precisions = columns.get(mibs.ENTITY_SENSOR["precision"], {})
    statuses = columns.get(mibs.ENTITY_SENSOR["status"], {})
    names = columns.get(mibs.ENTITY_SENSOR["name"], {})

    for index, value_bind in values.items():
        kind_bind = kinds.get(index)
        raw = value_bind.as_int()
        if raw is None or kind_bind is None:
            continue
        code = kind_bind.as_int(0) or 0
        metric, unit = mibs.SENSOR_TYPES.get(code, ("sensor", ""))
        if metric in ("truth", "sensor"):
            continue
        scale = (scales.get(index).as_int(6) if scales.get(index) else 6) or 6
        precision = (precisions.get(index).as_int(0) if precisions.get(index) else 0) or 0
        number = raw * mibs.SENSOR_SCALE.get(scale, 1.0)
        if precision:
            number = round(number, precision)
        name = (names.get(index).as_text().strip() if names.get(index) else "")
        status = mibs.SENSOR_STATUS.get(
            (statuses.get(index).as_int(1) if statuses.get(index) else 1) or 1, "ok")
        sensors.append({"name": name or ("sensor %d" % index), "metric": metric,
                        "value": round(number, 3), "unit": unit, "status": status,
                        "type": code, "index": index})
        if status == "ok":
            metrics.setdefault(metric, []).append(number)

    out: Dict[str, float] = {}
    for metric, numbers in metrics.items():
        reduced = reduce_metric(metric, numbers)
        if reduced is not None:
            out[metric] = round(reduced, 3)
            if metric == "optical":
                out.setdefault("optical_min", round(min(numbers), 3))
    return sensors, out


def collect_snmp(device: Device, timeout: float = 2.0, retries: int = 1, bulk: int = 25,
                 max_rows: int = 4000, client: Optional[Client] = None,
                 extras: Sequence[mibs.Metric] = ()) -> SnmpReading:
    """Everything one device will tell us, in one conversation.

    A device that answers the first GET and then refuses a walk is a real device;
    the errors are collected rather than raised, so a broken MIB costs a field, not
    the poll.
    """
    started = time.time()
    agent = Agent(host=device.target(), port=device.port, community=device.community,
                  version=device.version, user=device.user, auth=device.auth, priv=device.priv)
    reading = SnmpReading()
    own_client = client is None
    if own_client:
        client = Client(agent, timeout=timeout, retries=retries)
    elif isinstance(client, Client):
        # A real client handed in from outside should follow this device's address and
        # community; a stand-in (a simulator, a fake in the tests) already knows.
        client.agent = agent
    try:
        # ---- identity first: it decides which vendor rows are worth asking for
        try:
            identity = client.get(mibs.SYSTEM_SCALARS)
        except SnmpError as exc:
            reading.errors.append(str(exc))
            return reading
        facts: Dict[str, object] = {}
        for bind in identity:
            if bind.oid == mibs.SYS["descr"]:
                facts["descr"] = bind.as_text()
            elif bind.oid == mibs.SYS["object_id"]:
                facts["object_id"] = bind.as_text()
            elif bind.oid == mibs.SYS["uptime"]:
                ticks = bind.as_int()
                facts["uptime"] = ticks
                if ticks:
                    reading.metrics["uptime"] = ticks / 100.0     # TimeTicks are 1/100 s
            elif bind.oid == mibs.SYS["name"]:
                facts["sys_name"] = bind.as_text()
            elif bind.oid == mibs.SYS["location"]:
                facts["location"] = bind.as_text()
            elif bind.oid == mibs.SYS["contact"]:
                facts["contact"] = bind.as_text()
        reading.facts = facts
        vendor = mibs.fingerprint(str(facts.get("descr", "")), str(facts.get("object_id", "")))
        if vendor == "generic":
            vendor = mibs.vendor_from_oid(str(facts.get("object_id", ""))) or "generic"
        reading.vendor = vendor
        reading.ok = True

        # ---- the scalar rows: standard ones, plus this vendor's
        scalars = [row for row in mibs.metrics_for(vendor, extras) if not row.table]
        by_oid = {row.oid: row for row in scalars}
        if by_oid:
            try:
                for bind in client.get(list(by_oid)[:40]):
                    row = by_oid.get(bind.oid)
                    if row is None:
                        continue
                    number = row.value_of(bind.value)
                    if number is None:
                        continue
                    reading.metrics[row.key] = round(number, 3)
                    reading.labels.setdefault(row.key, row.label)
            except SnmpError as exc:
                reading.errors.append("scalars: %s" % exc)

        # ---- and the tables
        roots = list(mibs.standard_table_roots())
        roots += [row.oid for row in mibs.metrics_for(vendor, extras) if row.table]
        walked: Dict[str, List[VarBind]] = {}
        for root in _unique(roots):
            try:
                walked[root] = client.walk(root, ceiling=max_rows,
                                           bulk=bulk if device.version != "1" else None)
            except SnmpError as exc:
                walked[root] = []
                reading.errors.append("walk %s: %s" % (root, exc))

        columns = match_columns(walked)
        reading.interfaces = build_interfaces(columns)
        reading.filesystems, storage_metrics = build_storage(columns, walked)
        reading.sensors, sensor_metrics = build_sensors(columns)

        # host resources CPU and processes
        loads = [bind.as_int() for bind in columns.get(mibs.HR["cpu_load"], {}).values()]
        loads = [value for value in loads if isinstance(value, int) and value >= 0]
        if loads:
            reading.metrics["cpu"] = round(statistics.mean(loads), 1)
            reading.labels.setdefault("cpu", "CPU (host resources) · %d cores" % len(loads))
        processes = _int_at(walked, mibs.HR["processes"])
        if processes is not None:
            reading.facts["processes"] = processes
        idle = _int_at(walked, mibs.UCD["cpu_idle"])
        if idle is not None and "cpu" not in reading.metrics:
            reading.metrics["cpu"] = round(max(0.0, 100.0 - idle), 1)
            reading.labels.setdefault("cpu", "CPU (100 - idle)")
        load1 = _scalar_float(walked, mibs.UCD["load_1"])
        if load1 is not None:
            reading.facts["load"] = round(load1, 2)

        for key in ("memory", "disk"):
            if key not in reading.metrics and key in storage_metrics:
                reading.metrics[key] = storage_metrics[key]
        # ENTITY-SENSOR fills whatever the scalars did not: this is how a device with
        # no vendor table at all still shows a temperature and a dBm reading.
        for key, value in sensor_metrics.items():
            if key not in reading.metrics:
                reading.metrics[key] = round(value, 3)
                reading.labels.setdefault(key, "sensor · %s" % key)
        if "memory_total" in storage_metrics:
            reading.facts["memory_total"] = storage_metrics["memory_total"]

        # the vendor's table-shaped metrics (Cisco CPU pools, Huawei cards, SFP optics)
        table_rows = [row for row in mibs.metrics_for(vendor, extras) if row.table]
        grouped: Dict[str, List[float]] = {}
        for row in table_rows:
            binds = walked.get(row.oid)
            if not binds:
                continue
            numbers = [value for value in (row.value_of(bind.value) for bind in binds)
                       if value is not None]
            grouped.setdefault(row.key, []).extend(numbers)
            reading.labels.setdefault(row.key, row.label)
        for key, numbers in grouped.items():
            reduced = reduce_metric(key, numbers)
            if reduced is None:
                continue
            existing = reading.metrics.get(key)
            # A scalar row was asked for first and wins: the device's own answer for
            # the whole chassis beats one card, one pool or one SFP inside a table.
            if existing is None:
                reading.metrics[key] = round(reduced, 3)

        # PoE, if the switch has any
        delivering = [index for index, bind in columns.get(mibs.POE["port_detect"], {}).items()
                      if (bind.as_int(0) or 0) == 3]
        if delivering or mibs.POE["port_detect"] in columns:
            reading.facts["poe_ports"] = len(delivering)
            watts = _scalar_float(walked, mibs.POE["main_power"])
            if watts is not None:
                reading.facts["poe_watts"] = watts

        reading.facts["vendor"] = vendor
        reading.facts["sensors"] = len(reading.sensors)
        reading.facts["interfaces"] = len(reading.interfaces)
        return reading
    finally:
        reading.seconds = round(time.time() - started, 3)
        if own_client:
            client.close()


def _scalar_float(walked: Dict[str, List[VarBind]], oid: str) -> Optional[float]:
    """A scalar that arrived inside a table walk (an OID ending in .0)."""
    binds = walked.get(oid) or walked.get(oid.rstrip(".0")) or []
    for bind in binds:
        number = bind.as_int()
        if number is not None:
            return float(number)
    return None


def _unique(items: Iterable[str]) -> List[str]:
    seen: List[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


# ------------------------------------------------------------------ one device


def decide(device: Device, reading: Reading, previous: Optional[Reading],
           config) -> str:
    """The status of a device from its checks, worst-first.

    * any check `down` → **down**
    * latency or loss over the line, or a metric over its `warn` line → **degraded**
    * nothing measured → **unknown**
    * otherwise **up**
    """
    limits = device.limits()
    if config is not None and getattr(config, "thresholds", None):
        limits = config.threshold_object(device.thresholds)
    checks = {name: value for name, value in reading.checks.items() if value}
    if not checks:
        return "unknown"
    if any(value == "down" for value in checks.values()):
        return "down"
    if reading.latency_ms is not None and reading.latency_ms > limits.latency_ms:
        return "degraded"
    if reading.loss is not None and reading.loss > limits.loss:
        return "degraded"
    trouble = None
    for metric in ("cpu", "memory", "temperature", "disk", "battery", "optical", "runtime"):
        verdict = limits.trouble(metric, reading.metric(metric))
        if verdict == "critical":
            return "down"
        if verdict == "degraded":
            trouble = "degraded"
    if trouble:
        return trouble
    if any(value == "degraded" for value in checks.values()):
        return "degraded"
    return "up"


def poll_device(device: Device, config, previous: Optional[Reading] = None,
                previous_interfaces: Optional[Dict[int, Interface]] = None,
                client_factory: Optional[Callable[[Device], Client]] = None,
                prober: Optional[Callable[..., probe.ProbeResult]] = None,
                tcp_prober: Optional[Callable[..., probe.ProbeResult]] = None,
                http_prober: Optional[Callable[..., probe.ProbeResult]] = None,
                clock: Callable[[], float] = time.time) -> Reading:
    """One complete poll: SNMP, ping, ports and URL, in parallel."""
    started = clock()
    reading = Reading(device_id=device.key(), at=iso(now_utc()))
    prober = prober or probe.ping
    tcp_prober = tcp_prober or probe.tcp_check
    http_prober = http_prober or probe.http_check
    extras = mibs.custom_rows()
    snmp_slot: Dict[str, SnmpReading] = {}
    pending: Dict[futures.Future, str] = {}

    def ping_job():
        return prober(device.target(), config.ping_count, config.ping_timeout,
                      tcp_fallback=probe.FALLBACK_PORTS if config.tcp_fallback else ())

    def port_job(port: int):
        return tcp_prober(device.target(), int(port), config.snmp_timeout)

    def url_job():
        return http_prober(device.http_url, config.snmp_timeout * 2.5, device.expect_status)

    def snmp_job():
        made = client_factory(device) if client_factory else None
        snmp_slot["reading"] = collect_snmp(
            device, timeout=config.snmp_timeout, retries=config.snmp_retries,
            bulk=config.snmp_bulk, max_rows=config.max_table_rows, client=made, extras=extras)

    results: Dict[str, probe.ProbeResult] = {}
    with futures.ThreadPoolExecutor(max_workers=6) as pool:
        if device.ping and not device.snmp_only:
            pending[pool.submit(ping_job)] = "ping"
        for port in device.tcp_ports:
            pending[pool.submit(port_job, int(port))] = "tcp:%d" % int(port)
        if device.http_url:
            pending[pool.submit(url_job)] = "http"
        if device.snmp:
            pending[pool.submit(snmp_job)] = "snmp"
        for job in futures.as_completed(list(pending)):
            name = pending[job]
            if name == "snmp":
                continue                                   # read from `snmp_slot` below
            try:
                results[name] = job.result()
            except Exception as exc:                       # noqa: BLE001
                results[name] = probe.ProbeResult(status="unknown", detail=str(exc)[:120])
        for job, name in pending.items():
            if name == "snmp":
                try:
                    job.result()
                except Exception as exc:                   # noqa: BLE001
                    reading.message = "snmp: %s" % str(exc)[:160]

    # ---- collapse the results into one reading
    snmp_reading = snmp_slot.get("reading")
    if device.snmp:
        if snmp_reading and snmp_reading.ok:
            reading.checks["snmp"] = "up"
            reading.metrics.update(snmp_reading.metrics)
            reading.facts.update(snmp_reading.facts)
            reading.facts["address"] = device.target()
            reading.facts["vendor"] = snmp_reading.vendor
            reading.facts["sensors_list"] = snmp_reading.sensors
            reading.facts["filesystems"] = snmp_reading.filesystems
            reading.facts["snmp_seconds"] = snmp_reading.seconds
            if snmp_reading.labels:
                reading.facts["labels"] = dict(snmp_reading.labels)
            if snmp_reading.sensors:
                reading.facts["sensors"] = len(snmp_reading.sensors)
            # SNMP latency is a real measurement of the device, so use it when ICMP is
            # blocked but the community is right.
            reading.latency_ms = round(snmp_reading.seconds * 1000.0, 2)
            reading.interfaces = snmp_reading.interfaces
        else:
            reading.checks["snmp"] = "down"
            if snmp_reading and snmp_reading.errors:
                reading.message = snmp_reading.errors[0][:200]
    if "ping" in results:
        outcome = results["ping"]
        reading.checks["ping"] = outcome.status
        if outcome.latency_ms is not None:
            reading.latency_ms = outcome.latency_ms
        reading.loss = outcome.loss
        reading.facts["ping_method"] = outcome.method
        if outcome.detail and outcome.status != "up":
            reading.message = outcome.detail[:200]
    for name, outcome in results.items():
        if name.startswith("tcp:"):
            port = name.split(":", 1)[1]
            reading.checks["tcp-%s" % port] = outcome.status
            reading.facts.setdefault("ports", {})[port] = outcome.status
            if outcome.latency_ms is not None and reading.latency_ms is None:
                reading.latency_ms = outcome.latency_ms
    if "http" in results:
        outcome = results["http"]
        reading.checks["http"] = outcome.status
        reading.facts.update({"http": outcome.detail})
        if isinstance(outcome.extra, dict):
            reading.facts.update(outcome.extra)
            days = outcome.extra.get("tls_days")
            if isinstance(days, int) and days <= device.tls_warn_days:
                reading.checks["http"] = "degraded"

    if previous_interfaces and reading.interfaces:
        seconds = _seconds_between(previous, reading)
        for row in reading.interfaces:
            row.rate(previous_interfaces.get(row.index), seconds)

    reading.status = decide(device, reading, previous, config)
    reading.seconds = round(clock() - started, 3)
    return reading


def _seconds_between(previous: Optional[Reading], current: Reading) -> float:
    if previous is None:
        return 0.0
    older = parse_iso(previous.at)
    newer = parse_iso(current.at)
    if not older or not newer:
        return 0.0
    return max(1.0, (newer - older).total_seconds())


# --------------------------------------------------------------------- transitions


def events_for(device: Device, reading: Reading, previous: Optional[Reading],
               previous_interfaces: Optional[Dict[int, Interface]] = None,
               config=None) -> List[Event]:
    """What changed, in words a person can act on."""
    events: List[Event] = []
    was = (previous.status if previous else "") or ""
    now = reading.status

    if now == "down" and was != "down":
        events.append(Event(at=reading.at, device_id=device.key(), kind="down",
                            severity="critical", subject="device",
                            message="%s is down (%s)" % (device.name,
                                                         reading.message or "no answer")))
    elif now == "up" and was == "down":
        events.append(Event(at=reading.at, device_id=device.key(), kind="up",
                            severity="info", subject="device",
                            message="%s is back" % device.name))
    elif now == "degraded" and was in ("up", ""):
        events.append(Event(at=reading.at, device_id=device.key(), kind="degraded",
                            severity="warning", subject="device",
                            message="%s is degraded: %s"
                                    % (device.name, _degraded_reason(device, reading, config))))
    elif now == "up" and was == "degraded":
        events.append(Event(at=reading.at, device_id=device.key(), kind="recovered",
                            severity="info", subject="device",
                            message="%s is healthy again" % device.name))

    limits = device.limits()
    if config is not None and getattr(config, "thresholds", None):
        limits = config.threshold_object(device.thresholds)
    for metric in ("cpu", "memory", "temperature", "disk", "battery", "optical", "runtime"):
        value = reading.metric(metric)
        verdict = limits.trouble(metric, value)
        if verdict is None or value is None:
            continue
        severity = "critical" if verdict == "critical" else "warning"
        events.append(Event(at=reading.at, device_id=device.key(), kind="threshold",
                            severity=severity, subject=metric, value=round(value, 2),
                            message=threshold_message(device.name, metric, value, severity,
                                                      limits)))

    if previous_interfaces is not None:
        for row in reading.interfaces:
            was_row = previous_interfaces.get(row.index)
            if was_row is None or was_row.oper == row.oper:
                continue
            if row.oper == "down" and was_row.oper == "up":
                events.append(Event(at=reading.at, device_id=device.key(),
                                    kind="interface-down", severity="warning",
                                    subject=row.name,
                                    message="%s: port %s went down" % (device.name, row.label()),
                                    detail={"index": row.index, "alias": row.alias}))
            elif row.oper == "up" and was_row.oper == "down":
                events.append(Event(at=reading.at, device_id=device.key(),
                                    kind="interface-up", severity="info", subject=row.name,
                                    message="%s: port %s came up" % (device.name, row.label())))
            if row.error_delta and row.error_delta >= 50:
                events.append(Event(at=reading.at, device_id=device.key(), kind="threshold",
                                    severity="warning", subject="errors:%s" % row.name,
                                    value=float(row.error_delta),
                                    message="%s: %s gained %d errors since the last poll"
                                            % (device.name, row.label(), row.error_delta)))
    return events


#: Units for the metrics a threshold can watch, so an alert reads like a sentence.
UNITS = {"cpu": "%", "memory": "%", "disk": "%", "battery": "%", "temperature": " °C",
         "optical": " dBm", "runtime": " min", "fan": " rpm"}


def threshold_message(device_name: str, metric: str, value: float, verdict: str,
                      limits) -> str:
    """`"core-sw-01: temperature 78 °C is above the warning line (75)"` — a sentence.

    `verdict` is the severity the reading earned, which is also the word a person
    needs: a number over the warning line is a warning, over the critical line a
    critical. Whether "over" or "below" is the right preposition follows the metric's
    direction, so a flat UPS battery does not read as if it were overheating.
    """
    warn, crit = limits.limits(metric) or (0, 0)
    line = crit if verdict == "critical" else warn
    unit = UNITS.get(metric, "")
    preposition = "below" if limits.direction(metric) == "low" else "above"
    return "%s: %s %.1f%s is %s the %s line (%.0f)" % (
        device_name, metric, value, unit, preposition, verdict, line)


def _degraded_reason(device: Device, reading: Reading, config=None) -> str:
    limits = device.limits()
    if config is not None and getattr(config, "thresholds", None):
        limits = config.threshold_object(device.thresholds)
    notes: List[str] = []
    if reading.latency_ms is not None and reading.latency_ms > limits.latency_ms:
        notes.append("%.0f ms latency" % reading.latency_ms)
    if reading.loss:
        notes.append("%.0f%% loss" % reading.loss)
    for metric in ("cpu", "memory", "temperature", "disk", "battery", "optical", "runtime"):
        value = reading.metric(metric)
        if limits.trouble(metric, value):
            notes.append("%s %.1f" % (metric, value))
    failed = [name for name, value in reading.checks.items() if value == "down"]
    if failed:
        notes.append("checks down: %s" % ", ".join(failed))
    return ", ".join(notes) or "one check disagreed"


# ------------------------------------------------------------------------- poller


@dataclass
class PollOutcome:
    device: Device
    reading: Reading
    events: List[Event] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {"device": self.device.key(), "status": self.reading.status,
                "events": [event.as_dict() for event in self.events], "error": self.error}


class Poller:
    """The loop: which device is due, poll it, remember it, and say what changed.

    Hysteresis lives here, and is kept in the database's `meta` table under
    `hysteresis:<device>` so a restart does not forget that a device was already
    half-way down.
    """

    def __init__(self, store, config, on_events: Optional[Callable[[List[Event]], None]] = None,
                 client_factory: Optional[Callable[[Device], Client]] = None,
                 prober: Optional[Callable[..., probe.ProbeResult]] = None,
                 tcp_prober: Optional[Callable[..., probe.ProbeResult]] = None,
                 http_prober: Optional[Callable[..., probe.ProbeResult]] = None,
                 clock: Optional[Callable[[], float]] = None):
        self.store = store
        self.config = config
        self.on_events = on_events
        self.client_factory = client_factory
        self.prober = prober
        self.tcp_prober = tcp_prober
        self.http_prober = http_prober
        self.clock = clock or time.time
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._running: Dict[str, float] = {}
        self.stats: Dict[str, int] = {"polls": 0, "events": 0, "errors": 0}
        self.started_at = time.time()

    # ------------------------------------------------------------------ schedule
    def due(self, device: Device) -> bool:
        last = self.store.last_sample(device.key())
        if last is None:
            return True
        when = parse_iso(last.at)
        if when is None:
            return True
        return (now_utc() - when).total_seconds() >= device.alive_interval()

    def wait_seconds(self) -> float:
        """How long until the next device is due — the loop sleeps in these steps."""
        soonest = 300.0
        for device in self.store.devices(enabled_only=True):
            last = self.store.last_sample(device.key())
            when = parse_iso(last.at) if last else None
            now = now_utc()
            if when is None:
                return 1.0
            left = device.alive_interval() - (now - when).total_seconds()
            soonest = min(soonest, max(0.0, left))
        return max(1.0, min(soonest, 30.0))

    # --------------------------------------------------------------- one device
    def poll(self, device: Device, force: bool = False) -> PollOutcome:
        device_id = device.key()
        with self._lock:
            if device_id in self._running and not force:
                return PollOutcome(device, Reading(device_id=device_id, status="unknown"),
                                   error="already polling")
            self._running[device_id] = self.clock()
        try:
            previous = self.store.last_sample(device_id)
            previous_interfaces = {row.index: row for row in self.store.interfaces(device_id)}
            reading = poll_device(device, self.config, previous=previous,
                                  previous_interfaces=previous_interfaces,
                                  client_factory=self.client_factory, prober=self.prober,
                                  tcp_prober=self.tcp_prober, http_prober=self.http_prober,
                                  clock=self.clock)
            reading.status = self._hysteresis(device, reading, previous)
            reading.facts["uptime_text"] = reading.uptime_text()

            # learn the device's identity from what it just said
            vendor = str(reading.facts.get("vendor") or "")
            if vendor:
                device.vendor = vendor
            for key, attribute in (("sys_name", "sys_name"), ("descr", "sys_descr"),
                                   ("object_id", "sys_object_id"), ("location", "sys_location"),
                                   ("contact", "sys_contact")):
                value = reading.facts.get(key)
                if isinstance(value, str) and value:
                    setattr(device, attribute, value[:400])
            if not device.first_seen:
                device.first_seen = reading.at
            device.last_seen = reading.at
            device.address = str(reading.facts.get("address") or device.address or "")

            events = events_for(device, reading, previous, previous_interfaces, self.config)
            events = self._suppress_flaps(device, events, reading)

            self.store.add_sample(reading)
            if reading.interfaces:
                self.store.save_interfaces(device_id, reading.interfaces)
            self.store.save_device(device)
            for event in events:
                self.store.add_event(event)
            self.stats["polls"] += 1
            self.stats["events"] += len(events)
            if self.on_events and events:
                try:
                    self.on_events(events)
                except Exception:                                # noqa: BLE001
                    pass
            return PollOutcome(device, reading, events)
        except Exception as exc:                                 # noqa: BLE001
            self.stats["errors"] += 1
            return PollOutcome(device, Reading(device_id=device_id, status="unknown"),
                               error=str(exc)[:200])
        finally:
            with self._lock:
                self._running.pop(device_id, None)

    def poll_now(self, device_id: str) -> Optional[PollOutcome]:
        device = self.store.get_device(device_id)
        return self.poll(device, force=True) if device else None

    # --------------------------------------------------------------- hysteresis
    def _hysteresis(self, device: Device, reading: Reading,
                    previous: Optional[Reading]) -> str:
        """Raw status in, steady status out — the part that stops the dashboard flashing.

        `status` is the opinion the channel is currently showing, `streak` counts how
        many polls in a row have agreed with the *new* opinion. A device needs
        `failures_to_down` bad polls before it is called down, and `successes_to_up`
        good ones before it is called healthy again. In between, the last good opinion
        stands — which is exactly what "it blipped for one poll" should look like.
        """
        if previous is None:
            return reading.status          # nothing to be cautious about: this is the first look
        key = "hysteresis:%s" % device.key()
        try:
            state = json.loads(self.store.meta(key, "") or "{}")
        except ValueError:
            state = {}
        shown = str(state.get("status") or (previous.status if previous else "unknown"))
        streak = int(state.get("streak") or 0)
        raw = reading.status

        if raw == shown:
            self.store.set_meta(key, json.dumps({"status": shown, "streak": 0}))
            return shown

        streak += 1
        settle = (self.config.successes_to_up if raw == "up"
                  else self.config.failures_to_down)
        if streak < settle:
            self.store.set_meta(key, json.dumps({"status": shown, "streak": streak}))
            return shown                      # not enough evidence to change the opinion
        self.store.set_meta(key, json.dumps({"status": raw, "streak": 0}))
        return raw

    def _suppress_flaps(self, device: Device, events: List[Event], reading: Reading) -> List[Event]:
        """A port that bounces ten times an hour is one event, not ten."""
        if not events:
            return events
        window = float(self.config.flap_window_minutes)
        transitions = [event for event in self.store.events(hours=window / 60.0,
                                                            device_id=device.key(), limit=200)
                       if event.kind in ("interface-down", "interface-up", "down", "up")]
        by_subject: Dict[str, int] = {}
        for event in transitions:
            by_subject[event.subject] = by_subject.get(event.subject, 0) + 1
        out: List[Event] = []
        for event in events:
            if by_subject.get(event.subject, 0) >= self.config.flap_count:
                event.detail["flapping"] = True
                event.message += " (flapping — %d transitions in %d min)" % (
                    by_subject[event.subject] + 1, int(window))
            if event.kind == "interface-up" and by_subject.get(event.subject, 0) >= self.config.flap_count:
                continue                       # say the bad half, not both halves
            out.append(event)
        return out

    # ----------------------------------------------------------------- the loop
    def run_once(self, force: bool = False) -> List[PollOutcome]:
        devices = [device for device in self.store.devices(enabled_only=True)
                   if force or self.due(device)]
        if not devices:
            return []
        outcomes: List[PollOutcome] = []
        workers = max(1, min(self.config.workers, len(devices)))
        with futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for outcome in pool.map(self.poll, devices):
                outcomes.append(outcome)
        self.store.prune(self.config.sample_days, self.config.event_days,
                         self.config.rollup_days)
        return outcomes

    def serve_forever(self, on_cycle: Optional[Callable[[List[PollOutcome]], None]] = None,
                      idle: float = 2.0) -> None:
        self._stop.clear()
        while not self._stop.is_set():
            started = time.time()
            outcomes = self.run_once()
            if on_cycle:
                try:
                    on_cycle(outcomes)
                except Exception:                                 # noqa: BLE001
                    pass
            slept = 0.0
            while slept < max(idle, min(self.wait_seconds(), 30.0)) and not self._stop.is_set():
                time.sleep(min(0.5, idle))
                slept += 0.5

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> Dict[str, object]:
        return {"polls": self.stats["polls"], "events": self.stats["events"],
                "errors": self.stats["errors"],
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "devices": len(self.store.devices()),
                "in_flight": sorted(self._running)}
