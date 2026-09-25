"""SNMP from scratch: BER, the three PDUs that matter, and a client that walks.

Why hand-written instead of `pysnmp`? Because this tool is meant to be dropped on a
Windows server with nothing but Python on it. SNMP v1 and v2c are small, well-specified
formats — an integer-length codec and a handful of tags — and the whole of them fits in
this file. (SNMPv3's privacy needs AES, which the standard library does not have; v3 is
therefore accepted for *discovery* and reported honestly as unsupported. See `v3_note`.)

The pieces:

* `encode_*` / `decode_*` — ASN.1 BER, the base-128 integer form, the OID form
* `Message` — version, community, and one PDU
* `Client` — UDP, with retries, timeouts, and the two ways to read a table
* `walk` — GETBULK where the device allows it, GETNEXT where it does not

Everything takes and returns plain Python values, so a caller never sees a tag byte.
"""

from __future__ import annotations

import random
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# --------------------------------------------------------------------- BER tags

INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_ID = 0x06
SEQUENCE = 0x30
IP_ADDRESS = 0x40
COUNTER32 = 0x41
GAUGE32 = 0x42
TIMETICKS = 0x43
OPAQUE = 0x44
COUNTER64 = 0x46
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82

# PDU tags
GET_REQUEST = 0xA0
GET_NEXT_REQUEST = 0xA1
GET_RESPONSE = 0xA2
SET_REQUEST = 0xA3
GET_BULK_REQUEST = 0xA5

#: Which decoder to use for a value tag, and what to call the result.
VALUE_KINDS = {
    INTEGER: "int", COUNTER32: "int", GAUGE32: "int", TIMETICKS: "int",
    COUNTER64: "int", OCTET_STRING: "text", OBJECT_ID: "oid", IP_ADDRESS: "ip",
    NULL: "null", OPAQUE: "bytes",
    NO_SUCH_OBJECT: "missing", NO_SUCH_INSTANCE: "missing", END_OF_MIB_VIEW: "end",
}

#: GET_RESPONSE error-status, as the RFC 1157 list people actually see.
ERROR_STATUS = {
    0: "no error",
    1: "too big",
    2: "no such name",
    3: "bad value",
    4: "read only",
    5: "general error",
    6: "no access",
    7: "wrong type",
    8: "wrong length",
    9: "wrong encoding",
    10: "wrong value",
    11: "no creation",
    12: "inconsistent value",
    13: "resource unavailable",
    14: "commit failed",
    15: "undo failed",
    16: "authorization error",
    17: "not writable",
    18: "inconsistent name",
}


class SnmpError(Exception):
    """Anything that stops a request: a timeout, a refusal, a mangled answer."""


class Timeout(SnmpError):
    """The device did not answer at all — the common case for a wrong community."""


# ------------------------------------------------------------------- encoding


def _length(size: int) -> bytes:
    if size < 0x80:
        return bytes([size])
    body = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _length(len(payload)) + payload


def encode_int(value: int) -> bytes:
    """Two's-complement, minimal length — the form every agent expects.

    `-128` is one byte (`80`), not two (`ff 80`); `128` is two (`00 80`), because a
    leading `80` would read as negative. Both edges are in the tests, because getting
    them wrong is the classic way an SNMP client works against one vendor and not
    another.
    """
    if value == 0:
        return _tlv(INTEGER, b"\x00")
    size = 1
    while not (-(1 << (8 * size - 1)) <= value < (1 << (8 * size - 1))):
        size += 1
    return _tlv(INTEGER, value.to_bytes(size, "big", signed=True))


def _unsigned(value: int, tag: int) -> bytes:
    if value < 0:
        raise SnmpError("an unsigned value cannot be negative: %r" % value)
    body = value.to_bytes((value.bit_length() + 7) // 8, "big") or b"\x00"
    if body[0] & 0x80:                           # unsigned: a leading zero is fine here
        body = b"\x00" + body
    return _tlv(tag, body)


def encode_octets(value) -> bytes:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return _tlv(OCTET_STRING, bytes(value))


def encode_oid(oid: str) -> bytes:
    """`"1.3.6.1.2.1.1.1.0"` → the dotted form's binary. The first two arcs share a byte."""
    parts = _arcs(oid)
    if len(parts) < 2:
        raise SnmpError("an OID needs at least two arcs: %r" % oid)
    body = bytearray()
    first = parts[0] * 40 + parts[1]
    if first > 0xFF:
        raise SnmpError("the second arc is too large for one byte: %r" % oid)
    body.append(first)
    for arc in parts[2:]:
        if arc < 0:
            raise SnmpError("negative arc in %r" % oid)
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body.extend(reversed(chunk))
    return _tlv(OBJECT_ID, bytes(body))


def _arcs(oid: str) -> List[int]:
    try:
        return [int(part) for part in str(oid).strip(".").split(".") if part != ""]
    except ValueError:
        raise SnmpError("not an OID: %r" % oid) from None


def encode_null() -> bytes:
    return _tlv(NULL, b"")


def encode_value(value, tag: Optional[int] = None) -> bytes:
    """A Python value into the tag an SNMP SET/GET payload wants."""
    if value is None:
        return encode_null()
    if isinstance(value, bool):
        return _unsigned(int(value), tag or INTEGER)
    if isinstance(value, int):
        return _unsigned(value, tag or COUNTER32)
    if isinstance(value, str):
        if tag == OBJECT_ID:
            return encode_oid(value)
        return encode_octets(value)
    if isinstance(value, (bytes, bytearray)):
        return _tlv(tag or OCTET_STRING, bytes(value))
    if isinstance(value, (tuple, list)) and len(value) == 4:
        return _tlv(IP_ADDRESS, bytes(int(part) for part in value))
    raise SnmpError("cannot encode %r as SNMP" % (value,))


# ------------------------------------------------------------------- decoding


@dataclass
class Reader:
    """A cursor over BER, raising `SnmpError` instead of IndexError."""

    data: bytes
    at: int = 0

    def byte(self) -> int:
        if self.at >= len(self.data):
            raise SnmpError("the answer ended early")
        value = self.data[self.at]
        self.at += 1
        return value

    def take(self, size: int) -> bytes:
        if self.at + size > len(self.data):
            raise SnmpError("the answer ended early")
        chunk = self.data[self.at:self.at + size]
        self.at += size
        return chunk

    def tlv(self) -> Tuple[int, bytes]:
        tag = self.byte()
        length = self.byte()
        if length & 0x80:
            count = length & 0x7F
            if count == 0:
                raise SnmpError("indefinite lengths are not part of SNMP")
            length = int.from_bytes(self.take(count), "big")
        return tag, self.take(length)


def decode_oid(payload: bytes) -> str:
    if not payload:
        raise SnmpError("an OID cannot be empty")
    first = payload[0]
    arcs = [first // 40, first % 40]
    value = 0
    for byte in payload[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    return ".".join(str(arc) for arc in arcs)


def decode_value(tag: int, payload: bytes):
    kind = VALUE_KINDS.get(tag)
    if kind is None:
        return ("raw", payload)
    if kind == "int":
        return int.from_bytes(payload, "big", signed=tag == INTEGER)
    if kind == "text":
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload.decode("latin-1", "replace")
    if kind == "oid":
        return decode_oid(payload)
    if kind == "ip":
        if len(payload) != 4:
            return ("raw", payload)
        return ".".join(str(part) for part in payload)
    if kind == "null":
        return None
    if kind == "bytes":
        return payload
    return None                                       # missing / end-of-view


# --------------------------------------------------------------------- message


@dataclass
class VarBind:
    oid: str
    value: object = None
    tag: int = NULL

    def as_int(self, default: Optional[int] = None) -> Optional[int]:
        if isinstance(self.value, bool):
            return int(self.value)
        if isinstance(self.value, int):
            return self.value
        if isinstance(self.value, str):
            text = self.value.strip()
            if text.lstrip("-").isdigit():
                return int(text)
        return default

    def as_text(self, default: str = "") -> str:
        if isinstance(self.value, str):
            return self.value
        if self.value is None:
            return default
        if isinstance(self.value, (bytes, bytearray)):
            return bytes(self.value).decode("latin-1", "replace").strip("\x00")
        return str(self.value)


@dataclass
class Message:
    version: int = 1                                # 0 = v1, 1 = v2c
    community: str = "public"
    pdu: int = GET_REQUEST
    request_id: int = 0
    error_status: int = 0
    error_index: int = 0
    varbinds: List[VarBind] = field(default_factory=list)
    non_repeaters: int = 0                          # GETBULK only
    max_repetitions: int = 0                        # GETBULK only

    # ------------------------------------------------------------------ encode
    def encode(self) -> bytes:
        if self.pdu == GET_BULK_REQUEST:
            head = encode_int(self.request_id) + encode_int(self.non_repeaters) \
                + encode_int(self.max_repetitions)
        else:
            head = encode_int(self.request_id) + encode_int(self.error_status) \
                + encode_int(self.error_index)
        bindings = b"".join(_tlv(SEQUENCE, encode_oid(b.oid) + encode_null())
                            for b in self.varbinds if b.value is None)
        valued = b"".join(_tlv(SEQUENCE, encode_oid(b.oid) + encode_value(b.value, b.tag))
                          for b in self.varbinds if b.value is not None)
        body = head + _tlv(SEQUENCE, bindings + valued)
        return _tlv(SEQUENCE, encode_int(self.version) + encode_octets(self.community)
                    + _tlv(self.pdu, body))

    # ------------------------------------------------------------------ decode
    @classmethod
    def decode(cls, blob: bytes) -> "Message":
        reader = Reader(blob)
        outer, payload = reader.tlv()
        if outer != SEQUENCE:
            raise SnmpError("not an SNMP message (tag 0x%02x)" % outer)
        inner = Reader(payload)
        tag, version = inner.tlv()
        if tag != INTEGER:
            raise SnmpError("no version field")
        message = cls(version=int.from_bytes(version, "big", signed=True))
        tag, community = inner.tlv()
        if tag != OCTET_STRING:
            raise SnmpError("no community field")
        message.community = community.decode("utf-8", "replace")
        tag, body = inner.tlv()
        message.pdu = tag
        if tag == 0xA8:                               # SNMPv3 message: say so clearly
            raise SnmpError("this is an SNMPv3 answer; only v1/v2c are implemented")
        if tag not in (GET_REQUEST, GET_NEXT_REQUEST, GET_RESPONSE, SET_REQUEST,
                       GET_BULK_REQUEST):
            raise SnmpError("unexpected PDU 0x%02x" % tag)
        # Every PDU has the same shape: request id, two integers, then the bindings.
        # For GETBULK the two integers are non-repeaters and max-repetitions, which is
        # why a request can be decoded with the same code as an answer.
        pdu = Reader(body)
        _tag, request = pdu.tlv()
        message.request_id = int.from_bytes(request, "big", signed=True)
        _tag, first = pdu.tlv()
        _tag, second = pdu.tlv()
        if tag == GET_BULK_REQUEST:
            message.non_repeaters = int.from_bytes(first, "big", signed=True)
            message.max_repetitions = int.from_bytes(second, "big", signed=True)
        else:
            message.error_status = int.from_bytes(first, "big", signed=True)
            message.error_index = int.from_bytes(second, "big", signed=True)
        _tag, bindings = pdu.tlv()
        message.varbinds = _decode_varbinds(bindings)
        return message

    def raise_for_status(self) -> None:
        if self.error_status:
            where = (" at index %d" % self.error_index) if self.error_index else ""
            raise SnmpError("agent refused: %s%s"
                            % (ERROR_STATUS.get(self.error_status,
                                                "error %d" % self.error_status), where))


def _decode_varbinds(payload: bytes) -> List[VarBind]:
    out: List[VarBind] = []
    reader = Reader(payload)
    while reader.at < len(reader.data):
        tag, one = reader.tlv()
        if tag != SEQUENCE:
            break
        inner = Reader(one)
        _tag, name = inner.tlv()
        vtag, value = inner.tlv()
        out.append(VarBind(decode_oid(name), decode_value(vtag, value), vtag))
    return out


# ---------------------------------------------------------------------- client


@dataclass
class Agent:
    """Where a device answers, and with what."""

    host: str
    port: int = 161
    community: str = "public"
    version: str = "2c"                             # "1", "2c", or "3" (v3 is refused)
    #: v3 fields, kept so a scan can say *why* a v3 device was skipped rather than
    #: pretending it was silence.
    user: str = ""
    auth: str = ""
    priv: str = ""

    def describe(self) -> str:
        return "%s:%d v%s community …%s" % (self.host, self.port, self.version,
                                            self.community[-2:] if self.community else "?")


class Client:
    """One UDP socket, a retry policy, and the tables.

    A new request id per call, a bounded retry count, and a receive loop that
    refuses answers to questions it did not ask — a busy network is full of them.
    """

    def __init__(self, agent: Agent, timeout: float = 2.0, retries: int = 1,
                 sock: Optional[socket.socket] = None):
        self.agent = agent
        self.timeout = timeout
        self.retries = max(0, retries)
        self._own_socket = sock is None
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self._own_socket:
            self.sock.settimeout(timeout)
        self._ids = random.Random()
        self.requests = 0
        self.last_latency = 0.0

    # ------------------------------------------------------------------ context
    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        if self._own_socket:
            try:
                self.sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------------ request
    def request(self, message: Message) -> Message:
        if self.agent.version == "3":
            raise SnmpError("SNMPv3 is not implemented (no AES in the standard library); "
                            "use v2c, or ask this tool to probe and report the device")
        message.version = 0 if self.agent.version == "1" else 1
        message.community = self.agent.community
        message.request_id = self._ids.randint(1, 0x7FFFFFF0)
        blob = message.encode()

        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            started = time.time()
            try:
                self.sock.sendto(blob, (self.agent.host, self.agent.port))
                self.requests += 1
            except OSError as exc:
                raise SnmpError("cannot reach %s: %s" % (self.agent.host, exc)) from None
            deadline = started + self.timeout
            while True:
                left = deadline - time.time()
                if left <= 0:
                    break
                try:
                    self.sock.settimeout(left)
                    data, _peer = self.sock.recvfrom(65535)
                except socket.timeout:
                    break
                except OSError as exc:
                    last = SnmpError("socket error: %s" % exc)
                    break
                try:
                    answer = Message.decode(data)
                except SnmpError:
                    continue                          # not ours, or not SNMP: keep listening
                if answer.request_id != message.request_id:
                    continue                          # an answer to somebody else's question
                self.last_latency = time.time() - started
                answer.raise_for_status()
                return answer
            last = last or Timeout("%s:%d did not answer in %.1fs"
                                   % (self.agent.host, self.agent.port, self.timeout))
        raise last if isinstance(last, SnmpError) else Timeout(str(last))

    # ------------------------------------------------------------------ getters
    def get(self, oids: Sequence[str]) -> List[VarBind]:
        bindings = [VarBind(oid) for oid in oids]
        answer = self.request(Message(pdu=GET_REQUEST, varbinds=bindings))
        return answer.varbinds

    def get_one(self, oid: str) -> Optional[VarBind]:
        got = self.get([oid])
        if not got:
            return None
        return got[0]

    def get_next(self, oid: str) -> Optional[VarBind]:
        answer = self.request(Message(pdu=GET_NEXT_REQUEST, varbinds=[VarBind(oid)]))
        return answer.varbinds[0] if answer.varbinds else None

    def get_bulk(self, oid: str, repetitions: int = 25) -> List[VarBind]:
        answer = self.request(Message(pdu=GET_BULK_REQUEST, non_repeaters=0,
                                      max_repetitions=max(1, repetitions),
                                      varbinds=[VarBind(oid)]))
        return answer.varbinds

    # ------------------------------------------------------------------- walking
    def walk(self, root: str, ceiling: int = 4000, bulk: Optional[int] = None) -> List[VarBind]:
        """Every row under `root`, in order.

        GETBULK (v2c) asks for a column at a time; v1 can only ask for the next one.
        The walk stops when the agent leaves the subtree, hands back the same OID
        twice (some agents do), or answers with an error — all of which real
        devices do on their bad days.
        """
        if not root.endswith("."):
            root = root + "."
        out: List[VarBind] = []
        cursor = root
        use_bulk = bool(bulk) if bulk is not None else self.agent.version != "1"
        seen = set()
        while len(out) < ceiling:
            try:
                if use_bulk:
                    batch = self.get_bulk(cursor, repetitions=bulk or 25)
                    if not batch:
                        break
                else:
                    one = self.get_next(cursor)
                    if one is None:
                        break
                    batch = [one]
            except SnmpError:
                raise
            moved = False
            for bind in batch:
                if not (bind.oid == root.rstrip(".") or bind.oid.startswith(root)):
                    return out                        # out of the subtree: done
                if bind.value is None:                # noSuchObject / endOfMibView
                    return out
                if bind.oid in seen:
                    return out
                seen.add(bind.oid)
                out.append(bind)
                cursor = bind.oid
                moved = True
            if not moved:
                break
        return out

    def table(self, root: str, columns: int = 1) -> Dict[str, List[VarBind]]:
        """A table as `column-oid → rows`, so callers think in columns, not streams."""
        rows: Dict[str, List[VarBind]] = {}
        for bind in self.walk(root):
            parts = bind.oid.split(".")
            column = ".".join(parts[:len(root.rstrip('.').split('.')) + columns])
            rows.setdefault(column, []).append(bind)
        return rows


def v3_note() -> str:
    """The honest sentence about SNMPv3, used by the CLI and the README."""
    return ("SNMPv1 and v2c are fully implemented, in the standard library only. "
            "SNMPv3 is detected and reported, but its authentication and privacy "
            "need AES/DES that Python's standard library does not ship — see "
            "`docs/snmp.md` for how to add it with `pysnmp` if your estate demands v3.")


def walk_many(agent: Agent, roots: Iterable[str], timeout: float = 2.0,
              retries: int = 1) -> Dict[str, List[VarBind]]:
    """Several subtree walks over one socket — the cheap way to poll a device."""
    out: Dict[str, List[VarBind]] = {}
    with Client(agent, timeout=timeout, retries=retries) as client:
        for root in roots:
            try:
                out[root] = client.walk(root)
            except SnmpError as exc:
                out[root] = []
                out.setdefault("__errors__", []).append(VarBind(root, str(exc), OCTET_STRING))
    return out
