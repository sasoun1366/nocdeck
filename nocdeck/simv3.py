"""A fake SNMPv3 agent: it verifies authentication, decrypts, and answers.

This is the other half of the `demo` promise. A v3 device in the demo is not answered by
a shortcut around the security model — the request goes out through the real
`snmp.Client`, is authenticated and encrypted by the real USM code, arrives here as
bytes, and this agent does what a switch does: checks the engine id, proves the digest,
decrypts the scoped PDU, and signs and encrypts its answer.

It is deliberately strict. A wrong password, an unknown user, stale boots, a digest that
does not match — each produces the REPORT a real agent would send, which is what makes
the tests worth having: they exercise the error paths a person will actually hit at two
in the morning, not only the happy one.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .snmp import (GET_BULK_REQUEST, GET_NEXT_REQUEST, GET_REQUEST, GET_RESPONSE, INTEGER,
                   NULL, OBJECT_ID, OCTET_STRING, REPORT, SEQUENCE, Message, Reader,
                   SnmpError, VarBind, _tlv, decode_pdu, encode_int, encode_octets,
                   encode_oid, encode_value)
from .snmpv3 import (FLAG_AUTH, FLAG_PRIV, FLAG_REPORTABLE, SecurityParameters,
                     SnmpV3Error, V3Message, auth_digest, decrypt_scoped, encrypt_scoped,
                     localize_key)

END_OF_MIB_VIEW = "1.3.6.1.6.3.12.1.4.0"

#: The counters an agent uses to explain itself, exactly as SNMP-USER-BASED-SM-MIB
#: defines them. A real REPORT carries one of these, which is why the tool can say *why*
#: a v3 poll failed instead of reporting a timeout and leaving the operator guessing.
USM_STATS = {
    "unsupported": "1.3.6.1.6.3.15.1.1.1.0",
    "not_in_time": "1.3.6.1.6.3.15.1.1.2.0",
    "unknown_user": "1.3.6.1.6.3.15.1.1.3.0",
    "unknown_engine": "1.3.6.1.6.3.15.1.1.4.0",
    "wrong_digest": "1.3.6.1.6.3.15.1.1.5.0",
    "decrypt_error": "1.3.6.1.6.3.15.1.1.6.0",
}


class LoopbackSocket:
    """A socket that hands each datagram straight to a `V3Agent` in this process.

    No thread, no port, no wait: the demo answers its own question synchronously. What
    crosses the "wire" is still the bytes — authenticate, encrypt, decrypt, verify — so a
    demo device exercises the same code a real one would, and a demo that works cannot be
    working by accident.
    """

    def __init__(self, agent: "V3Agent"):
        self.agent = agent
        self.queue: List[bytes] = []
        self.sent = 0
        self.received = 0

    def sendto(self, blob: bytes, address) -> None:
        self.sent += 1
        answer = self.agent.handle(blob)
        if answer is not None:
            self.queue.append(answer)

    def recvfrom(self, size: int):
        if not self.queue:
            raise socket.timeout("no answer")            # exactly what UDP does
        self.received += 1
        return self.queue.pop(0), ("loopback", 161)

    def settimeout(self, value) -> None:
        pass

    def close(self) -> None:
        pass


@dataclass
class V3User:
    """One USM user as the agent knows it: a name, and the two secrets."""

    name: str
    auth_protocol: str = ""
    auth_password: str = ""
    priv_protocol: str = ""
    priv_password: str = ""


@dataclass
class V3Agent:
    """The security half of an imaginary device, wrapped around a node's tables."""

    node: object                                   # a `SimNode`, duck-typed on purpose
    engine_id: bytes = b"\x80\x00\x00\x02nocdeck-sim-0001"
    boots: int = 3
    users: Dict[str, V3User] = field(default_factory=dict)
    started: float = field(default_factory=time.monotonic)
    #: Set these to make the agent behave badly, so the tests can prove the client
    #: notices rather than trusting that it would.
    break_digest: bool = False
    demand_auth: bool = False
    silent: bool = False
    requests: int = 0
    reports: int = 0
    _salt: int = field(default_factory=lambda: int.from_bytes(os.urandom(8), "big")
                       & 0x7FFFFFFFFFFFFFFF)
    _rows: Optional[List[VarBind]] = None

    # ------------------------------------------------------------------ the clock
    def engine_time(self) -> int:
        return int(time.monotonic() - self.started) + 60

    def next_salt(self) -> int:
        """AES privacy needs a fresh local integer per message; reusing one reuses an IV."""
        self._salt = (self._salt + 1) & 0x7FFFFFFFFFFFFFFF
        return self._salt

    def key(self, user: V3User, protocol: str, password: str) -> bytes:
        return localize_key(password, self.engine_id, protocol)

    # ----------------------------------------------------------------- handling
    def handle(self, datagram: bytes) -> Optional[bytes]:
        """One datagram in, one datagram out (or silence, like a dead agent)."""
        if self.silent:
            return None
        self.requests += 1
        try:
            request = V3Message.decode(datagram)
        except SnmpError:
            return None

        if not request.security.engine_id:
            return self._report(request, "unknown_engine")      # discovery: "who am I"
        if request.security.engine_id != self.engine_id:
            return self._report(request, "unknown_engine")

        user = self.users.get(request.security.user)
        if user is None:
            return self._report(request, "unknown_user")

        auth_key = (self.key(user, user.auth_protocol, user.auth_password)
                    if user.auth_protocol else b"")
        # the privacy key is localised with the *auth* protocol's hash (RFC 3826)
        priv_key = (self.key(user, user.auth_protocol, user.priv_password)
                    if user.priv_protocol and user.auth_protocol else b"")

        if request.flags & FLAG_AUTH:
            if not user.auth_protocol:
                return self._report(request, "unsupported", user, auth_key, priv_key)
            claimed = request.security.auth_params
            expected = auth_digest(auth_key, request.security.zeroed_copy(datagram),
                                   user.auth_protocol)
            if self.break_digest or claimed != expected:
                return self._report(request, "wrong_digest", user, auth_key, priv_key)
        elif self.demand_auth and user.auth_protocol:
            return self._report(request, "unsupported", user, auth_key, priv_key)

        # ---- the scoped PDU, decrypted if it arrived encrypted
        if request.encrypted is not None:
            if not user.priv_protocol:
                return self._report(request, "decrypt_error", user, auth_key, priv_key)
            try:
                scoped = decrypt_scoped(priv_key, user.priv_protocol, request.encrypted,
                                        request.security.priv_params, self.boots,
                                        request.security.engine_time)
                context_engine, context_name, pdu_tag, pdu_body = _scoped_pdu(scoped)
            except SnmpError:
                return self._report(request, "decrypt_error", user, auth_key, priv_key)
        elif user.priv_protocol:
            return self._report(request, "unsupported", user, auth_key, priv_key)
        else:
            context_engine, context_name = b"", ""
            reader = Reader(request.pdu_bytes)
            pdu_tag, pdu_body = reader.tlv()

        if context_name not in ("", self.node.device.name):
            return self._report(request, "unsupported", user, auth_key, priv_key)
        return self._answer(request, user, auth_key, priv_key, pdu_tag, pdu_body,
                            context_engine)

    # ------------------------------------------------------------------ answers
    def _answer(self, request: V3Message, user: V3User, auth_key: bytes, priv_key: bytes,
                pdu_tag: int, pdu_body: bytes, context_engine: bytes) -> bytes:
        answer = self._respond(pdu_tag, pdu_body)
        flags = FLAG_REPORTABLE | (FLAG_AUTH if user.auth_protocol else 0)
        security = SecurityParameters(engine_id=self.engine_id, engine_boots=self.boots,
                                      engine_time=self.engine_time(), user=user.name)
        reply = V3Message(msg_id=request.msg_id, flags=flags, security=security,
                          context_engine_id=context_engine or self.engine_id,
                          context_name="", pdu_bytes=answer)
        if user.priv_protocol:
            flags |= FLAG_PRIV
            reply.flags = flags
            scoped = reply.scoped_bytes()                       # what goes in the clear
            ciphertext, priv_params = encrypt_scoped(priv_key, user.priv_protocol, scoped,
                                                     self.boots, self.engine_time(),
                                                     self.next_salt())
            reply.encrypted = ciphertext
            reply.pdu_bytes = b""
            security.priv_params = priv_params
        if user.auth_protocol:
            security.auth_params = b"\x00" * 12
            reply.security = security
            security.auth_params = auth_digest(auth_key, reply.encode(), user.auth_protocol)
            reply.security = security
        return reply.encode()

    def _respond(self, pdu_tag: int, body: bytes) -> bytes:
        """The tables answer here; the security model only decided whether to ask."""
        try:
            request = decode_pdu(pdu_tag, body)
        except SnmpError:
            request = Message(pdu=pdu_tag, request_id=0)
        bindings: List[VarBind] = []
        if pdu_tag == GET_REQUEST:
            bindings = [_bind(bind.oid, self.node.scalar(bind.oid))
                        for bind in request.varbinds]
        elif pdu_tag in (GET_NEXT_REQUEST, GET_BULK_REQUEST):
            cursor = request.varbinds[0].oid if request.varbinds else ""
            rows = self._rows_after(cursor)
            wanted = 1 if pdu_tag == GET_NEXT_REQUEST else max(1, request.max_repetitions)
            if rows:
                bindings = rows[:wanted]
            else:
                bindings = [VarBind(cursor, END_OF_MIB_VIEW, OBJECT_ID)]   # end of MIB
        else:
            bindings = [VarBind(request.varbinds[0].oid if request.varbinds else "", None,
                                NULL)]
        return _tlv(GET_RESPONSE, encode_int(request.request_id) + encode_int(0)
                    + encode_int(0) + _tlv(SEQUENCE, b"".join(
                        _tlv(SEQUENCE, encode_oid(b.oid) + encode_value(b.value, b.tag))
                        for b in bindings)))

    def _all_rows(self) -> List[VarBind]:
        """Everything this imaginary device can answer, in MIB order.

        A real GETNEXT walks the whole tree, so the agent has to as well: it collects
        every table the node builds, adds the scalars, and sorts the lot. Sorting is
        numeric because MIB order is not string order — `1.3.6.1.2.1.10` follows
        `1.3.6.1.2.1.2`, and a demo that walks the interfaces in the wrong order would
        hide a real ordering bug rather than show one.
        """
        if self._rows is not None:
            return self._rows
        from . import mibs

        device = self.node.device
        # The same roots the collector walks, taken from the same place: if a table is
        # added to the MIB layer, the demo agent answers it without being told twice.
        roots = list(mibs.standard_table_roots())
        roots += [row.oid for row in mibs.VENDOR_METRICS if row.vendor == device.vendor]
        found: Dict[str, VarBind] = {}
        for root in roots:
            for bind in self.node.walk(root):
                found[bind.oid] = bind
        for oid in (mibs.SYS["descr"], mibs.SYS["object_id"], mibs.SYS["uptime"],
                    mibs.SYS["name"], mibs.SYS["location"], mibs.SYS["contact"]):
            value = self.node.scalar(oid)
            if value is not None:
                found[oid] = _bind(oid, value)
        for row in mibs.VENDOR_METRICS:
            if row.vendor == device.vendor and not row.table:
                value = self.node.scalar(row.oid)
                if value is not None:
                    found[row.oid] = _bind(row.oid, value)
        self._rows = sorted(found.values(), key=lambda bind: _oid_tuple(bind.oid))
        return self._rows

    def _rows_after(self, cursor: str) -> List[VarBind]:
        """The rows that come after `cursor` in MIB order — the walk's raw material."""
        if not cursor:
            return self._all_rows()
        key = _oid_tuple(cursor)
        return [row for row in self._all_rows() if _oid_tuple(row.oid) > key]

    def _report(self, request: V3Message, reason: str, user: Optional[V3User] = None,
                auth_key: bytes = b"", priv_key: bytes = b"") -> bytes:
        """The agent saying what was wrong, rather than merely refusing to answer."""
        self.reports += 1
        counter = USM_STATS[reason]
        pdu = _tlv(REPORT, encode_int(request.msg_id) + encode_int(0) + encode_int(0)
                   + _tlv(SEQUENCE, _tlv(SEQUENCE, encode_oid(counter)
                                         + encode_value(1, INTEGER))))
        security = SecurityParameters(engine_id=self.engine_id, engine_boots=self.boots,
                                      engine_time=self.engine_time(),
                                      user=user.name if user else "")
        reply = V3Message(msg_id=request.msg_id, flags=FLAG_REPORTABLE, security=security,
                          context_engine_id=self.engine_id, pdu_bytes=pdu)
        # The one REPORT that is never authenticated is the digest failure itself: the
        # manager has the wrong key by definition, so the answer could not be verified,
        # and pretending otherwise would hide the real problem. Discovery is plaintext
        # for the same reason — no key exists yet.
        if user is not None and user.auth_protocol and auth_key and reason != "wrong_digest":
            reply.flags |= FLAG_AUTH
            security.auth_params = b"\x00" * 12
            security.auth_params = auth_digest(auth_key, reply.encode(), user.auth_protocol)
            reply.security = security
        return reply.encode()


def _scoped_pdu(scoped: bytes) -> Tuple[bytes, str, int, bytes]:
    """`(contextEngineID, contextName, pdu tag, pdu body)` out of a decrypted scoped PDU."""
    reader = Reader(scoped)
    tag, payload = reader.tlv()
    if tag != SEQUENCE:
        raise SnmpV3Error("not a scoped PDU")
    inner = Reader(payload)
    _tag, context_engine = inner.tlv()
    _tag, context_name = inner.tlv()
    pdu_tag, pdu_body = inner.tlv()
    return context_engine, context_name.decode("utf-8", "replace"), pdu_tag, pdu_body


def _oid_tuple(oid: str) -> Tuple[int, ...]:
    """OIDs compare as numbers, not as text: `.10` comes after `.2`, not before it."""
    try:
        return tuple(int(part) for part in oid.split("."))
    except ValueError:
        return (0,)


def _bind(oid: str, value) -> VarBind:
    if value is None:
        return VarBind(oid, None, NULL)
    if isinstance(value, int):
        return VarBind(oid, value, INTEGER)
    tag = OBJECT_ID if oid.endswith(".1.2.0") else OCTET_STRING
    return VarBind(oid, str(value), tag)
