"""The checks that are not SNMP: is it there, how long does it take, is the port open.

Ping is the awkward one. ICMP needs a raw socket, which needs root — and a
monitoring tool that demands root will not get installed. So `ping()` tries the
raw socket first, falls back to the system `ping` command (which is setuid on every
platform that has it), and finally to a TCP connect, saying which one answered in
`method`. A server that blocks ICMP but answers on 443 is *up*, and treating it as
down is the classic way a dashboard loses its users' trust.
"""

from __future__ import annotations

import concurrent.futures as futures
import os
import platform
import re
import select
import socket
import ssl
import statistics
import struct
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

#: Ports a TCP fallback will try, in order — the ones a device that blocks ICMP
#: still has to answer on to be useful.
FALLBACK_PORTS = (443, 80, 22, 161, 3389, 8080, 8291)


@dataclass
class ProbeResult:
    """What one check found."""

    ok: bool = False
    latency_ms: Optional[float] = None
    loss: Optional[float] = None
    status: str = "unknown"               # up / down / degraded
    method: str = ""                      # raw, command, tcp, snmp
    detail: str = ""
    extra: Dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        return {"ok": self.ok, "latency_ms": self.latency_ms, "loss": self.loss,
                "status": self.status, "method": self.method, "detail": self.detail,
                "extra": self.extra}


class _IcmpEcho:
    """A bare ICMP echo request, so a socket can carry it where raw sockets are allowed."""

    @staticmethod
    def packet(identifier: int, sequence: int, size: int = 32) -> bytes:
        payload = bytes(range(size))
        header = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
        checksum = _checksum(header + payload)
        header = struct.pack("!BBHHH", 8, 0, checksum, identifier, sequence)
        return header + payload


def _checksum(blob: bytes) -> int:
    if len(blob) % 2:
        blob += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(blob) // 2), blob))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def icmp_ping(host: str, count: int = 3, timeout: float = 1.0, size: int = 32) -> ProbeResult:
    """Raw-socket ping. Needs root; callers should fall back, not fail."""
    try:
        address = socket.gethostbyname(host)
    except OSError as exc:
        return ProbeResult(status="down", detail="cannot resolve %s (%s)" % (host, exc))
    identifier = os.getpid() & 0xFFFF
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        return ProbeResult(status="unknown", method="raw",
                           detail="raw sockets need root")
    except OSError as exc:
        return ProbeResult(status="unknown", method="raw", detail=str(exc))

    latencies: List[float] = []
    try:
        sock.settimeout(timeout)
        for sequence in range(1, count + 1):
            started = time.time()
            try:
                sock.sendto(_IcmpEcho.packet(identifier, sequence, size), (address, 0))
            except OSError as exc:
                return ProbeResult(status="down", method="raw", detail=str(exc))
            deadline = started + timeout
            while True:
                left = deadline - time.time()
                if left <= 0:
                    break
                ready, _, _ = select.select([sock], [], [], left)
                if not ready:
                    break
                try:
                    data, peer = sock.recvfrom(2048)
                except OSError:
                    break
                if peer[0] != address:
                    continue
                if len(data) >= 28 and data[20] == 0:          # echo reply
                    latencies.append((time.time() - started) * 1000.0)
                    break
            time.sleep(0.05)
    finally:
        sock.close()

    if not latencies:
        return ProbeResult(ok=False, status="down", loss=100.0, method="raw",
                           detail="no echo reply")
    loss = round(100.0 * (count - len(latencies)) / count, 1)
    return ProbeResult(ok=True, status="up" if loss == 0 else "degraded",
                       latency_ms=round(statistics.mean(latencies), 2), loss=loss,
                       method="raw", detail="%d/%d replies" % (len(latencies), count))


def command_ping(host: str, count: int = 3, timeout: float = 2.0) -> ProbeResult:
    """The system `ping`, parsed. Setuid on every platform, so it works unprivileged."""
    windows = platform.system().lower().startswith("win")
    if windows:
        command = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    else:
        command = ["ping", "-c", str(count), "-W", str(max(1, int(round(timeout)))), host]
    try:
        done = subprocess.run(command, capture_output=True, text=True,
                              timeout=timeout * count + 5)
    except (OSError, subprocess.SubprocessError) as exc:
        return ProbeResult(status="unknown", method="command", detail=str(exc))

    output = (done.stdout or "") + (done.stderr or "")
    times = [float(value) for value in
             re.findall(r"time[=<]\s*([0-9.]+)\s*ms", output, re.IGNORECASE)]
    if not times:
        times = [float(value) for value in
                 re.findall(r"average\s*=\s*([0-9.]+)ms", output, re.IGNORECASE)]
    loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet )?loss", output, re.IGNORECASE)
    loss = float(loss_match.group(1)) if loss_match else (0.0 if times else 100.0)

    if done.returncode != 0 and not times:
        return ProbeResult(ok=False, status="down", loss=100.0, method="command",
                           detail=(output.strip().splitlines() or ["no reply"])[-1][:120])
    return ProbeResult(ok=True, status="up" if loss < 1 else "degraded",
                       latency_ms=round(statistics.mean(times), 2) if times else None,
                       loss=loss, method="command",
                       detail="%d replies" % len(times))


def tcp_check(host: str, port: int, timeout: float = 2.0) -> ProbeResult:
    started = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = (time.time() - started) * 1000.0
            return ProbeResult(ok=True, status="up", latency_ms=round(elapsed, 2),
                               method="tcp", detail="port %d open" % port,
                               extra={"port": port})
    except (OSError, socket.timeout) as exc:
        return ProbeResult(ok=False, status="down", method="tcp",
                           detail="port %d: %s" % (port, exc), extra={"port": port})


def ping(host: str, count: int = 3, timeout: float = 1.5,
         tcp_fallback: Sequence[int] = FALLBACK_PORTS) -> ProbeResult:
    """ICMP, then the command, then a TCP port — saying which one answered.

    A device that blocks ICMP is not down, and a dashboard that says it is will be
    ignored within a week. The fallback is on by default and can be turned off.
    """
    result = icmp_ping(host, count=count, timeout=timeout)
    if result.ok:
        return result
    if result.method == "raw" and "root" in result.detail:
        result = command_ping(host, count=count, timeout=timeout)
        if result.ok:
            return result
    if tcp_fallback:
        for port in tcp_fallback:
            second = tcp_check(host, port, timeout=timeout)
            if second.ok:
                second.status = "degraded"       # up, but not by ICMP: worth a note
                second.detail = ("ICMP silent, TCP %d answered" % port)
                second.extra["icmp"] = "silent"
                return second
    return result


def http_check(url: str, timeout: float = 5.0, expect_status: int = 0,
               expect_body: str = "") -> ProbeResult:
    """Status code, response time, certificate days left, and an optional body match."""
    if not url:
        return ProbeResult(status="unknown", detail="no url")
    if "://" not in url:
        url = "https://" + url
    started = time.time()
    request = urllib.request.Request(url, headers={"User-Agent": "nocdeck/1.0"})
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE              # report a bad certificate, don't die
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read(65536).decode("utf-8", "replace")
            code = response.status
    except urllib.error.HTTPError as exc:
        code = exc.code
        body = ""
        exc.read()
    except Exception as exc:                              # noqa: BLE001 — DNS, TLS, refused
        return ProbeResult(ok=False, status="down", method="http",
                           detail="%s" % exc.__class__.__name__ + ": " + str(exc)[:120])
    elapsed = round((time.time() - started) * 1000.0, 2)

    ok = (200 <= code < 400) if not expect_status else code == expect_status
    detail = "HTTP %d in %.0f ms" % (code, elapsed)
    extra: Dict[str, object] = {"status_code": code, "url": url}
    if expect_body and expect_body not in body:
        ok = False
        detail += " — body does not contain %r" % expect_body[:40]
    days = tls_days(url, timeout=timeout)
    if days is not None:
        extra["tls_days"] = days
        detail += " · certificate %d d" % days
    return ProbeResult(ok=ok, status="up" if ok else "down", latency_ms=elapsed,
                       method="http", detail=detail, extra=extra)


def tls_days(url: str, timeout: float = 5.0) -> Optional[int]:
    """Days until the certificate expires, or None when this is not TLS."""
    if not url.lower().startswith("https"):
        return None
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else "https://" + url)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return None
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                certificate = tls.getpeercert()
    except Exception:                                     # noqa: BLE001
        return None
    if not certificate or "notAfter" not in certificate:
        return None
    try:
        expires = datetime.strptime(certificate["notAfter"], "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return None
    return (expires - datetime.utcnow()).days


def dns_check(name: str, timeout: float = 3.0) -> ProbeResult:
    started = time.time()
    try:
        socket.setdefaulttimeout(timeout)
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(name, None)})
    except OSError as exc:
        return ProbeResult(ok=False, status="down", method="dns", detail=str(exc)[:120])
    return ProbeResult(ok=True, status="up",
                       latency_ms=round((time.time() - started) * 1000.0, 2), method="dns",
                       detail=", ".join(addresses[:3]), extra={"addresses": addresses})


def parallel(calls: Sequence[Tuple[str, tuple, dict]], workers: int = 8) -> Dict[str, ProbeResult]:
    """Run several checks at once — a device with four checks should cost one timeout."""
    out: Dict[str, ProbeResult] = {}
    with futures.ThreadPoolExecutor(max_workers=max(1, min(workers, len(calls) or 1))) as pool:
        jobs = {pool.submit(function, *args, **kwargs): name
                for name, (function, args, kwargs) in calls}
        for job in futures.as_completed(jobs):
            name = jobs[job]
            try:
                out[name] = job.result()
            except Exception as exc:                       # noqa: BLE001
                out[name] = ProbeResult(status="unknown", detail=str(exc)[:120])
    return out
