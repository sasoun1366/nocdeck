"""Finding the gear: sweep a range, ask each address who it is, suggest a name.

The order is deliberate, because a LAN sweep on a Monday morning should not take
an hour:

1. **Alive check** — a TCP connect to a short list of ports is fast, needs no
   privileges and catches almost everything (a switch has 22 and 161, a printer 80,
   a server 443). ICMP is tried too, and *silence on both* is the only thing that
   counts as absent.
2. **SNMP probe** — one GET for `sysDescr`, tried against the configured
   communities. A device that answers becomes a candidate with its own name.
3. **Kind guess** — from the description, the object id, and the interface types.

Nothing is written to the inventory here: a scan produces a list a person accepts
with `nocdeck add --scan`, which is where the credentials get chosen too.
"""

from __future__ import annotations

import concurrent.futures as futures
import ipaddress
import re
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import mibs, probe
from .model import Device, slug
from .snmp import Agent, Client, SnmpError

#: Ports worth trying when deciding whether an address is alive.
QUICK_PORTS = (161, 22, 443, 80, 3389, 8291, 8080, 23, 445, 62078, 9100)


@dataclass
class Candidate:
    """A device a scan found, before anyone has decided to keep it."""

    host: str
    alive_by: str = ""                     # tcp:161, icmp, snmp
    community: str = ""
    name: str = ""
    descr: str = ""
    object_id: str = ""
    sys_name: str = ""
    location: str = ""
    vendor: str = ""
    kind: str = "generic"
    mac: str = ""
    interfaces: int = 0
    device: Optional[Device] = None        # the Device this would become

    def as_dict(self) -> Dict[str, object]:
        return {"host": self.host, "alive_by": self.alive_by, "community": self.community,
                "name": self.name, "descr": self.descr[:300], "object_id": self.object_id,
                "sys_name": self.sys_name, "vendor": self.vendor, "kind": self.kind,
                "mac": self.mac, "interfaces": self.interfaces}

    def to_device(self, group: str = "", interval: int = 60) -> Device:
        return Device(
            name=self.name or self.sys_name or self.host,
            host=self.host, id=slug(self.name or self.sys_name or self.host),
            kind=self.kind, group=group, location=self.location, vendor=self.vendor,
            community=self.community or "public", interval=interval,
            ping=self.alive_by in ("icmp", "command", "") or self.alive_by.startswith("tcp"))


# ------------------------------------------------------------------ ranges


def expand(target: str) -> List[str]:
    """`10.0.0.0/24`, `10.0.0.10-25`, `10.0.0.7` — the three ways people write it."""
    text = str(target).strip()
    if not text:
        return []
    try:
        network = ipaddress.ip_network(text, strict=False)
        if network.num_addresses > 2:
            return [str(address) for address in network.hosts()]
        return [str(address) for address in network]
    except ValueError:
        pass
    match = re.match(r"^([0-9.]+)-([0-9]+)$", text)
    if match:
        base, last = match.group(1), int(match.group(2))
        prefix, _, start = base.rpartition(".")
        try:
            first = int(start)
        except ValueError:
            return []
        if first <= last <= 255:
            return ["%s.%d" % (prefix, number) for number in range(first, last + 1)]
        return []            # `10.0.0.40-7` is a typo, and saying so beats scanning it
    if text.endswith(".*") or text.endswith(".0/24"):
        return expand(text.rstrip("*").rstrip(".") + ".0/24")
    return [text]


def expand_all(targets: Iterable[str], ceiling: int = 65536) -> List[str]:
    out: List[str] = []
    for target in targets:
        for host in expand(target):
            if host not in out:
                out.append(host)
            if len(out) >= ceiling:
                return out
    return out


# -------------------------------------------------------------- liveness


def tcp_alive(host: str, ports: Sequence[int] = QUICK_PORTS, timeout: float = 0.6
              ) -> Tuple[bool, str]:
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True, "tcp:%d" % port
        except OSError:
            continue
    return False, ""


def fresh_port(host: str, timeout: float = 0.4) -> bool:
    """A last resort that does not need privileges and does not need a service.

    Sending a UDP packet to a closed port on a live host usually comes back as an
    ICMP port-unreachable, which the kernel reports as a refusal — a connected UDP
    socket sees that as `ECONNREFUSED`, while an absent host times out.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, 33434))
            sock.send(b"\x00")
            try:
                sock.recv(1)
            except socket.timeout:
                return True                      # nothing came back: no refusal either
        finally:
            sock.close()
    except ConnectionRefusedError:
        return True
    except OSError:
        return False
    return True


def alive(host: str, timeout: float = 0.6, ports: Sequence[int] = QUICK_PORTS,
          icmp: bool = False) -> Tuple[bool, str]:
    """Is anyone home? TCP first (fast, unprivileged), ICMP only if asked."""
    if icmp:
        outcome = probe.ping(host, count=1, timeout=max(0.5, timeout), tcp_fallback=())
        if outcome.ok:
            return True, outcome.method
    ok, how = tcp_alive(host, ports, timeout)
    if ok:
        return True, how
    return (fresh_port(host, timeout), "udp") if fresh_port(host, timeout) else (False, "")


# -------------------------------------------------------------------- snmp probe


@dataclass
class SnmpProbe:
    ok: bool = False
    community: str = ""
    descr: str = ""
    object_id: str = ""
    sys_name: str = ""
    location: str = ""
    uptime: Optional[int] = None
    interfaces: int = 0
    version: str = "2c"
    detail: str = ""


def snmp_probe(host: str, communities: Sequence[str] = ("public",), timeout: float = 1.0,
               version: str = "2c", port: int = 161, name_interfaces: bool = True) -> SnmpProbe:
    """One GET per community until something answers. Cheap: two packets per try."""
    last = "no answer"
    for community in communities:
        agent = Agent(host=host, port=port, community=community, version=version)
        try:
            with Client(agent, timeout=timeout, retries=0) as client:
                binds = client.get([mibs.SYS["descr"], mibs.SYS["object_id"],
                                    mibs.SYS["name"], mibs.SYS["location"],
                                    mibs.SYS["uptime"]])
        except SnmpError as exc:
            last = str(exc)
            continue
        except OSError as exc:                  # a closed port, a bad route, no permission
            last = str(exc)
            continue
        got = {bind.oid: bind for bind in binds}
        result = SnmpProbe(
            ok=True, community=community, version=version,
            descr=(got.get(mibs.SYS["descr"]).as_text() if got.get(mibs.SYS["descr"]) else ""),
            object_id=(got.get(mibs.SYS["object_id"]).as_text()
                       if got.get(mibs.SYS["object_id"]) else ""),
            sys_name=(got.get(mibs.SYS["name"]).as_text() if got.get(mibs.SYS["name"]) else ""),
            location=(got.get(mibs.SYS["location"]).as_text()
                      if got.get(mibs.SYS["location"]) else ""),
            uptime=(got.get(mibs.SYS["uptime"]).as_int() if got.get(mibs.SYS["uptime"]) else None))
        if name_interfaces:
            try:
                with Client(agent, timeout=timeout, retries=0) as client:
                    rows = client.walk("1.3.6.1.2.1.2.2.1.2", ceiling=200)
                    result.interfaces = len(rows)
            except SnmpError:
                result.interfaces = 0
        return result
    return SnmpProbe(ok=False, detail=last)


def suggest_kind(descr: str = "", object_id: str = "", if_types: Sequence[str] = ()) -> str:
    """What sort of box is this? A guess, clearly labelled as one in the UI."""
    text = ("%s %s %s" % (descr, object_id, " ".join(if_types))).lower()
    rules = (
        ("ups", ("ups", "smart-ups", "american power", "battery", "smartups")),
        ("printer", ("printer", "laserjet", "officejet", "kyocera", "ricoh", "xerox",
                     "epson", "brother", "canon i")),
        ("firewall", ("firewall", "fortigate", "palo alto", "pan-os", "check point",
                      "sonicwall", "sophos", "asa ", "secure gateway")),
        ("ap", ("access point", "airmax", "unifi ap", "wap", "wireless", "wifi")),
        ("switch", ("switch", "catalyst", "procurve", "nexus", "crs", "css", "edgeswitch",
                    "gs1900", "tl-sg", "dgs-", "c29", "c35", "c37", "c92", "c93",
                    "ws-c", "ios software, c")),
        ("router", ("router", "routeros", "mikrotik", "gateway", "isr", "asr", "edge router",
                    "usg")),
        ("server", ("windows", "linux", "ubuntu", "debian", "red hat", "centos", "esxi",
                    "vmware", "proliant", "poweredge", "synology", "dsm", "qnap",
                    "freebsd", "server")),
        ("storage", ("nas", "storage", "netapp", "san", "isilon")),
        ("camera", ("camera", "cctv", "dahua", "hikvision", "axis")),
    )
    for kind, needles in rules:
        if any(needle in text for needle in needles):
            return kind
    if if_types and sum(1 for row in if_types if row in ("ethernet", "802.3")) > 8:
        return "switch"
    return "generic"


def mac_table(timeout: float = 3.0) -> Dict[str, str]:
    """The ARP cache, if the platform will show it — a name next to an address."""
    out: Dict[str, str] = {}
    for command in (["arp", "-a"], ["ip", "neigh"]):
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            continue
        for line in (done.stdout or "").splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})",
                              line)
            if match:
                out[match.group(1)] = match.group(2).replace("-", ":").lower()
        if out:
            break
    return out


# ---------------------------------------------------------------------- sweeping


def sweep(targets: Iterable[str], communities: Sequence[str] = ("public", "private"),
          workers: int = 64, timeout: float = 1.0, snmp_timeout: float = 1.0,
          icmp: bool = False, on_found: Optional[Callable[[Candidate], None]] = None,
          on_progress: Optional[Callable[[int, int], None]] = None,
          limit: int = 4096) -> List[Candidate]:
    """Sweep, and return what answered — with, where possible, the community that did.

    SNMP is asked first on each address because a device that answers SNMP is
    certainly alive, and that is the answer we actually wanted; the TCP/UDP probe
    is only for the rest.
    """
    hosts = expand_all(targets, ceiling=limit)
    found: List[Candidate] = []
    done = 0
    macs = mac_table()

    def look(host: str) -> Optional[Candidate]:
        result = snmp_probe(host, communities=communities, timeout=snmp_timeout)
        if result.ok:
            vendor = mibs.fingerprint(result.descr, result.object_id) or \
                mibs.vendor_from_oid(result.object_id) or "generic"
            kind = suggest_kind(result.descr, result.object_id)
            return Candidate(host=host, alive_by="snmp", community=result.community,
                             descr=result.descr, object_id=result.object_id,
                             sys_name=result.sys_name, location=result.location,
                             vendor=vendor, kind=kind, interfaces=result.interfaces,
                             name=(result.sys_name or result.descr.split(",")[0][:40]
                                   or host.rsplit(".", 1)[-1]),
                             mac=macs.get(host, ""))
        is_up, how = alive(host, timeout=timeout, icmp=icmp)
        if is_up:
            return Candidate(host=host, alive_by=how, mac=macs.get(host, ""),
                             name=host.rsplit(".", 1)[-1], kind="generic")
        return None

    with futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        jobs = {pool.submit(look, host): host for host in hosts}
        for job in futures.as_completed(jobs):
            done += 1
            if on_progress and (done % 16 == 0 or done == len(hosts)):
                on_progress(done, len(hosts))
            try:
                candidate = job.result()
            except Exception:                                   # noqa: BLE001
                candidate = None
            if candidate:
                found.append(candidate)
                if on_found:
                    on_found(candidate)
    found.sort(key=lambda row: tuple(int(part) for part in row.host.split("."))
               if row.host.count(".") == 3 else (999, 999, 999, 999))
    return found
