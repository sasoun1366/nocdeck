"""SNMPv3: the User-based Security Model, in the standard library.

v1 and v2c ask a device a question and it answers; v3 is a conversation. This module is
the part that makes that conversation legal — the one where a network engineer stops
sending `public` across the wire and uses a username with a password instead:

* **Discovery** — ask an unknown engine who it is (the empty-engineID request), read the
  engine id, boots and time out of the REPORT that comes back.
* **Authentication** — RFC 3414 §6: the password is stretched into a key, localised to
  that engine, and every message carries an HMAC of itself truncated to 12 octets.
  MD5, SHA-1 and the SHA-2 family.
* **Privacy** — RFC 3414 §8 (CBC-DES) and RFC 3826 (AES-CFB128): the scoped PDU is
  encrypted with a key derived the same way, and a per-message salt keeps two messages
  from sharing an IV.
* **Timeliness** — RFC 3414 §3.2: the engine time in the message must be within 150
  seconds of ours and the boots counter must match, which is what stops a recorded
  message being replayed tomorrow.

The BER work is shared with `snmp.py`; the ciphers are in `crypto.py`. Nothing here
reaches the network: a socket is handed in, so the tests can drive a validating fake
agent and the demo can answer as if it were a switch.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import crypto
from .snmp import (GET_REQUEST, INTEGER, OCTET_STRING, REPORT, SEQUENCE, Agent, Client,
                   Message, Reader, SnmpError, _length, _tlv, decode_pdu, encode_octets,
                   encode_int, encode_oid, encode_pdu)

__all__ = ["AUTH_PROTOCOLS", "PRIV_PROTOCOLS", "Session", "SecurityParameters",
           "SnmpV3Error", "StaleEngine", "V3Message", "auth_digest", "available",
           "decrypt_scoped", "encrypt_scoped", "localize_key", "protocols_help",
           "selftest", "stretch_password"]

#: The authentication protocols, by the names people type. `hashlib` names on the right.
AUTH_PROTOCOLS: Dict[str, str] = {
    "md5": "md5", "sha": "sha1", "sha1": "sha1", "sha-1": "sha1",
    "sha224": "sha224", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
}

#: The privacy protocols, and how many bytes of localized key each one needs.
PRIV_PROTOCOLS: Dict[str, Tuple[str, int]] = {
    "des": ("des", 16), "aes": ("aes", 16), "aes128": ("aes", 16),
    "aes192": ("aes", 24), "aes256": ("aes", 32),
}

SECURITY_MODEL_USM = 3

#: Message flags (RFC 3412 §6.4): privacy, authentication, and "answer me if you can".
FLAG_AUTH = 0x01
FLAG_PRIV = 0x02
FLAG_REPORTABLE = 0x04

#: RFC 3414 §3.2.7.a: further apart than this and the message is stale.
TIME_WINDOW = 150

#: REPORTs carry one of these in `usmStats…`; the numbers are what make an error message
#: worth reading.
USM_STATS = {
    "1.3.6.1.6.3.15.1.1.1.0": "the agent does not support this security level",
    "1.3.6.1.6.3.15.1.1.2.0": "not in the agent's time window — check its clock",
    "1.3.6.1.6.3.15.1.1.3.0": "no such user on the agent",
    "1.3.6.1.6.3.15.1.1.4.0": "the agent did not know its own engine id (discovery)",
    "1.3.6.1.6.3.15.1.1.5.0": "the authentication password (or protocol) is wrong",
    "1.3.6.1.6.3.15.1.1.6.0": "the agent could not decrypt the message — check the "
                              "privacy protocol and password",
}

MIB_ENGINE_ID = "1.3.6.1.6.3.10.2.1.1.0"


class SnmpV3Error(SnmpError):
    """Anything that went wrong in a v3 conversation, with the reason in the text."""


class StaleEngine(SnmpV3Error):
    """The agent rebooted: its boots counter moved, so its keys and clock are new."""


def available() -> bool:
    """v3 is always available: the ciphers ship with the tool."""
    return True


def protocols_help() -> str:
    return ("auth: %s · priv: %s" % (", ".join(sorted(set(AUTH_PROTOCOLS))),
                                     ", ".join(sorted(set(PRIV_PROTOCOLS)))))


# ------------------------------------------------------------------ key derivation


def _hash_name(protocol: str) -> str:
    name = AUTH_PROTOCOLS.get((protocol or "").lower().strip())
    if not name:
        raise SnmpV3Error("unknown authentication protocol %r — use one of: %s"
                          % (protocol, ", ".join(sorted(set(AUTH_PROTOCOLS)))))
    return name


def _priv_spec(protocol: str) -> Tuple[str, int]:
    spec = PRIV_PROTOCOLS.get((protocol or "").lower().strip())
    if not spec:
        raise SnmpV3Error("unknown privacy protocol %r — use one of: %s"
                          % (protocol, ", ".join(sorted(set(PRIV_PROTOCOLS)))))
    return spec


def stretch_password(password: str, protocol: str) -> bytes:
    """`Ku` — RFC 3414 A.2: the password repeated to a megabyte, then hashed.

    The megabyte is not a mistake and not an invitation to be clever. It is what makes
    the password expensive to guess offline, and every SNMP implementation does it the
    same way, which is the only reason passwords interoperate at all.
    """
    name = _hash_name(protocol)
    if not password:
        raise SnmpV3Error("a v3 password cannot be empty")
    raw = password.encode("utf-8")
    if not raw:
        raise SnmpV3Error("a v3 password cannot be empty")
    # Exactly one megabyte, not "about a megabyte" — and fed in phase. The RFC repeats
    # the password byte by byte until the buffer is full, so the repetition runs across
    # chunk boundaries: hashing `password * k` per chunk restarts the pattern wherever
    # the chunk size is not a multiple of the password length, which produces a
    # perfectly plausible wrong key. Nothing interoperates after that, and the symptom
    # is a mistyped-looking password on every device.
    digest = hashlib.new(name)
    position = 0
    while position < 1048576:
        size = min(65536, 1048576 - position)
        start = position % len(raw)
        digest.update((raw[start:] + raw * (size // len(raw) + 1))[:size])
        position += size
    return digest.digest()


def localize_key(password: str, engine_id: bytes, protocol: str) -> bytes:
    """`Kul` — RFC 3414 A.2: the stretched password bound to one engine.

    Two devices with the same password end up with different keys, which is the point
    of an engine id in a security model.
    """
    name = _hash_name(protocol)
    ku = stretch_password(password, protocol)
    digest = hashlib.new(name)
    digest.update(ku)
    digest.update(engine_id)
    digest.update(ku)
    return digest.digest()


def key_from_hex(text: str, protocol: str) -> bytes:
    """An operator who already has the localized key can paste it instead of a password."""
    cleaned = "".join(text.split()).replace(":", "").replace("-", "")
    try:
        key = bytes.fromhex(cleaned)
    except ValueError:
        raise SnmpV3Error("the key is not hex: %r" % text) from None
    if len(key) not in (16, 20, 24, 28, 32, 48, 64):
        raise SnmpV3Error("a localized key is 16 to 64 bytes, not %d" % len(key))
    return key


# ------------------------------------------------------------------- authentication


def auth_digest(key: bytes, message: bytes, protocol: str) -> bytes:
    """HMAC of the whole message, truncated to 12 octets (RFC 3414 §6.3.1)."""
    name = _hash_name(protocol)
    return hmac.new(key, message, name).digest()[:12]


# ------------------------------------------------------------------------ privacy


class _Salt:
    """A counter that must never repeat for one key. Random at boot, then +1."""

    def __init__(self) -> None:
        self.value = int.from_bytes(os.urandom(8), "big") & 0x7FFFFFFFFFFFFFFF
        self.counter = int.from_bytes(os.urandom(4), "big")

    def next(self) -> int:
        self.value = (self.value + 1) & 0x7FFFFFFFFFFFFFFF
        self.counter = (self.counter + 1) & 0xFFFFFFFF
        return self.value


def encrypt_scoped(key: bytes, protocol: str, scoped_pdu: bytes, engine_boots: int,
                   engine_time: int, salt: int) -> Tuple[bytes, bytes]:
    """Encrypt a scoped PDU. Returns `(ciphertext, msgPrivacyParameters)`."""
    kind, needed = _priv_spec(protocol)
    if len(key) < needed:
        raise SnmpV3Error(
            "%s needs a %d byte key and this one is %d — with a short hash use "
            "sha256 or longer, or pick a smaller cipher" % (protocol, needed, len(key)))
    key = key[:needed] if kind == "aes" else key[:16]

    if kind == "aes":
        if len(key) not in (16, 24, 32):
            raise SnmpV3Error("AES needs a 16, 24 or 32 byte key, not %d" % len(key))
        # RFC 3826 §3.1.2: IV = engineBoots ‖ engineTime ‖ local 64-bit integer, and the
        # integer travels in msgPrivacyParameters so the far end can rebuild it.
        priv_params = salt.to_bytes(8, "big")
        iv = (engine_boots & 0xFFFFFFFF).to_bytes(4, "big") \
            + (engine_time & 0xFFFFFFFF).to_bytes(4, "big") + priv_params
        return crypto.aes_cfb128(key, iv, scoped_pdu), priv_params

    # CBC-DES, RFC 3414 §8.1.1.1: the last 8 bytes of the key are the pre-IV, the salt
    # is engineBoots ‖ a counter, and the IV is their XOR.
    pre_iv = key[8:16]
    salt_bytes = (engine_boots & 0xFFFFFFFF).to_bytes(4, "big") \
        + (salt & 0xFFFFFFFF).to_bytes(4, "big")
    iv = crypto.xor_bytes(pre_iv, salt_bytes)
    padded = scoped_pdu + bytes(-len(scoped_pdu) % 8)      # the pad value is irrelevant;
    return crypto.des_cbc_encrypt(key[:8], iv, padded), salt_bytes   # BER says where it ends


def decrypt_scoped(key: bytes, protocol: str, ciphertext: bytes, priv_params: bytes,
                   engine_boots: int, engine_time: int) -> bytes:
    kind, needed = _priv_spec(protocol)
    if len(key) < needed:
        raise SnmpV3Error("%s needs a %d byte key and this one is %d"
                          % (protocol, needed, len(key)))
    if kind == "aes":
        key = key[:needed]
        iv = (engine_boots & 0xFFFFFFFF).to_bytes(4, "big") \
            + (engine_time & 0xFFFFFFFF).to_bytes(4, "big") + priv_params
        return crypto.aes_cfb128_decrypt(key, iv, ciphertext)
    if len(priv_params) != 8:
        raise SnmpV3Error("a DES message needs an 8 byte salt, not %d" % len(priv_params))
    iv = crypto.xor_bytes(key[8:16], priv_params)
    return crypto.des_cbc_decrypt(key[:8], iv, ciphertext)


# ----------------------------------------------------------------- the v3 message


@dataclass
class SecurityParameters:
    """RFC 3414 §2.4, in one place, because every field matters to somebody."""

    engine_id: bytes = b""
    engine_boots: int = 0
    engine_time: int = 0
    user: str = ""
    auth_params: bytes = b""
    priv_params: bytes = b""
    #: Where `auth_params` sat in the datagram it was decoded from — `(offset, length)`.
    #: Authentication is checked against the bytes that arrived, with that span zeroed,
    #: rather than against a message this code re-encoded: an agent that writes a
    #: BER length in a longer form than necessary is legal, and re-encoding would then
    #: produce different bytes and reject a perfectly honest answer.
    auth_span: Tuple[int, int] = (0, 0)

    def encode(self) -> bytes:
        return _tlv(SEQUENCE, encode_octets(self.engine_id) + encode_int(self.engine_boots)
                    + encode_int(self.engine_time) + encode_octets(self.user.encode("utf-8"))
                    + encode_octets(self.auth_params) + encode_octets(self.priv_params))

    @classmethod
    def decode(cls, payload: bytes, base: int = 0) -> "SecurityParameters":
        """`base` is where `payload` starts inside the datagram, for `auth_span`."""
        outer = Reader(payload)
        tag, body = outer.tlv()
        if tag != SEQUENCE:
            raise SnmpV3Error("the security parameters are not a SEQUENCE")
        reader = Reader(body)                 # the fields live *inside* the SEQUENCE
        body_start = base + outer.at - len(body)
        out = cls()
        _tag, out.engine_id = reader.tlv()
        _tag, boots = reader.tlv()
        out.engine_boots = int.from_bytes(boots, "big", signed=True)
        _tag, when = reader.tlv()
        out.engine_time = int.from_bytes(when, "big", signed=True)
        _tag, user = reader.tlv()
        out.user = user.decode("utf-8", "replace")
        _tag, auth = reader.tlv()
        out.auth_params = auth
        out.auth_span = (body_start + reader.at - len(auth), len(auth))
        _tag, priv = reader.tlv()
        out.priv_params = priv
        return out

    def zeroed_copy(self, datagram: bytes) -> bytes:
        """The datagram with the authentication field blanked, ready for the HMAC."""
        offset, length = self.auth_span
        if not length:
            return datagram
        return datagram[:offset] + b"\x00" * length + datagram[offset + length:]


@dataclass
class V3Message:
    """The three layers of an SNMPv3 message: header, security, scoped PDU."""

    msg_id: int = 0
    max_size: int = 65507
    flags: int = FLAG_REPORTABLE
    security_model: int = SECURITY_MODEL_USM
    security: SecurityParameters = field(default_factory=SecurityParameters)
    #: The scoped PDU, as `(contextEngineID, contextName, ber-encoded PDU)`.
    context_engine_id: bytes = b""
    context_name: str = ""
    pdu_bytes: bytes = b""
    encrypted: Optional[bytes] = None               # set instead of pdu_bytes when private
    #: Set by the session when the answer arrived without the authentication flag while
    #: the request asked for one. A REPORT is the only such answer worth reading.
    unauthenticated: bool = False

    def scoped_bytes(self) -> bytes:
        """The scoped PDU in the clear — what gets encrypted when privacy is in play."""
        return _tlv(SEQUENCE, encode_octets(self.context_engine_id)
                    + encode_octets(self.context_name.encode("utf-8")) + self.pdu_bytes)

    def encode(self) -> bytes:
        header = _tlv(SEQUENCE, encode_int(self.msg_id) + encode_int(self.max_size)
                      + encode_octets(bytes([self.flags]))
                      + encode_int(self.security_model))
        security = encode_octets(self.security.encode())
        if self.encrypted is not None:
            data = _tlv(OCTET_STRING, self.encrypted)
        else:
            data = self.scoped_bytes()
        return _tlv(SEQUENCE, encode_int(3) + header + security + data)

    @classmethod
    def decode(cls, blob: bytes) -> "V3Message":
        reader = Reader(blob)
        tag, payload = reader.tlv()
        if tag != SEQUENCE:
            raise SnmpV3Error("not an SNMP message")
        payload_start = reader.at - len(payload)
        inner = Reader(payload)
        _tag, version = inner.tlv()
        if int.from_bytes(version, "big", signed=True) != 3:
            raise SnmpV3Error("this is not an SNMPv3 message")
        out = cls()
        _tag, header = inner.tlv()
        head = Reader(header)
        _tag, msg_id = head.tlv()
        out.msg_id = int.from_bytes(msg_id, "big", signed=True)
        _tag, size = head.tlv()
        out.max_size = int.from_bytes(size, "big", signed=True)
        _tag, flags = head.tlv()
        out.flags = flags[0] if flags else 0
        _tag, model = head.tlv()
        out.security_model = int.from_bytes(model, "big", signed=True)
        if out.security_model != SECURITY_MODEL_USM:
            raise SnmpV3Error("security model %d is not USM" % out.security_model)
        _tag, security = inner.tlv()
        # The security parameters are an OCTET STRING wrapping a SEQUENCE. `base` is
        # where that OCTET STRING's *value* starts inside the datagram, which is what
        # turns the positions `Reader` reports into positions in what arrived.
        out.security = SecurityParameters.decode(security,
                                                 payload_start + inner.at - len(security))
        tag, data = inner.tlv()
        if tag == OCTET_STRING:
            out.encrypted = data
        elif tag == SEQUENCE:
            scoped = Reader(data)
            _tag, context_engine = scoped.tlv()
            out.context_engine_id = context_engine
            _tag, context_name = scoped.tlv()
            out.context_name = context_name.decode("utf-8", "replace")
            out.pdu_bytes = data[scoped.at:]       # whatever the PDU is, untouched
        else:
            raise SnmpV3Error("unexpected scoped PDU tag 0x%02x" % tag)
        return out


# ----------------------------------------------------------------------- session


class Session:
    """One v3 conversation with one engine: discovery, then request/response.

    The socket is shared with the `Client` that owns it, and the engine state lives here
    — an agent that reboots (boots goes up, time restarts) is noticed and re-discovered
    rather than answered into the void.
    """

    def __init__(self, agent: Agent, sock: Optional[socket.socket] = None,
                 timeout: float = 2.0, retries: int = 1):
        self.agent = agent
        self.timeout = timeout
        self.retries = max(0, retries)
        self._own_socket = sock is None
        self.sock = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self._own_socket:
            self.sock.settimeout(timeout)
        self._salt = _Salt()
        self._msg_id = int.from_bytes(os.urandom(3), "big") + 1
        self.last_latency = 0.0
        self.messages = 0
        self.discoveries = 0
        self.auth_protocol = (agent.auth or "").lower().strip()
        self.priv_protocol = (agent.priv or "").lower().strip()
        self.auth_key: bytes = b""
        self.priv_key: bytes = b""
        self.engine_id: bytes = b""
        self.engine_boots = 0
        self.engine_time = 0
        self._synced_at = 0.0

    # ------------------------------------------------------------------ helpers
    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        if self._own_socket:
            try:
                self.sock.close()
            except OSError:
                pass

    def keys(self) -> Tuple[bytes, bytes]:
        """The localized keys, derived once the engine id is known."""
        if not self.engine_id:
            raise SnmpV3Error("the keys cannot be derived before discovery")
        if not self.auth_key and self.auth_protocol:
            self.auth_key = (key_from_hex(self.agent.auth_key, self.auth_protocol)
                             if self.agent.keys_are_hex else
                             localize_key(self.agent.auth_key, self.engine_id,
                                          self.auth_protocol))
        if not self.priv_key and self.priv_protocol:
            # RFC 3826 §3.1.2.1 (and RFC 3414 §8.1.1.1 for DES): the privacy secret is
            # localised with the *authentication* protocol's hash, and the privacy
            # protocol only chooses the cipher and how many key bytes it uses.
            if not self.auth_protocol:
                raise SnmpV3Error("privacy needs an authentication protocol to derive "
                                  "its key from (RFC 3414 §3.2)")
            self.priv_key = (key_from_hex(self.agent.priv_key, self.auth_protocol)
                             if self.agent.keys_are_hex else
                             localize_key(self.agent.priv_key, self.engine_id,
                                          self.auth_protocol))
        return self.auth_key, self.priv_key

    def flags(self) -> int:
        value = FLAG_REPORTABLE
        if self.auth_protocol:
            value |= FLAG_AUTH
        if self.priv_protocol:
            if not self.auth_protocol:
                raise SnmpV3Error("privacy without authentication is not allowed "
                                  "(RFC 3414 §3.2): set an auth protocol and password")
            value |= FLAG_PRIV
        return value

    def engine_clock(self) -> int:
        """The agent's notion of its uptime in seconds, corrected for our own drift."""
        if not self._synced_at:
            return self.engine_time
        return self.engine_time + int(time.monotonic() - self._synced_at)

    # --------------------------------------------------------------- discovery
    def discover(self) -> None:
        """Ask an unknown engine who it is: empty engine id, empty user, a REPORT back."""
        message = V3Message(msg_id=self._next_id(), flags=FLAG_REPORTABLE,
                            security=SecurityParameters())
        # A GET with no varbinds is the classic discovery probe: it is legal, it is
        # cheap, and an agent answers it with usmStatsUnknownEngineIDs and its own id.
        probe = Message(pdu=GET_REQUEST, request_id=1)
        message.pdu_bytes = encode_pdu(probe)
        blob = message.encode()

        last: Optional[Exception] = None
        for _attempt in range(self.retries + 1):
            answer = self._send_and_receive(blob, message.msg_id)
            if answer is None:
                last = SnmpV3Error("%s:%d did not answer discovery in %.1fs"
                                   % (self.agent.host, self.agent.port, self.timeout))
                continue
            if not answer.security.engine_id:
                raise SnmpV3Error("the agent answered discovery without its engine id")
            self.engine_id = answer.security.engine_id
            self.engine_boots = answer.security.engine_boots
            self.engine_time = answer.security.engine_time
            self._synced_at = time.monotonic()
            self.discoveries += 1
            self.auth_key = b""                     # keys are engine-specific
            self.priv_key = b""
            return
        raise last if isinstance(last, SnmpV3Error) else SnmpV3Error(str(last))

    def _next_id(self) -> int:
        self._msg_id = (self._msg_id + 1) & 0x7FFFFFFF
        return max(1, self._msg_id)

    # ------------------------------------------------------------------ talking
    def _send_and_receive(self, blob: bytes, msg_id: int,
                          privacy: Optional[Tuple[bytes, bytes]] = None) -> Optional[V3Message]:
        """Send one datagram, wait for the answer that belongs to it."""
        started = time.time()
        try:
            self.sock.sendto(blob, (self.agent.host, self.agent.port))
        except OSError as exc:
            raise SnmpV3Error("cannot reach %s: %s" % (self.agent.host, exc)) from None
        deadline = started + self.timeout
        while True:
            left = deadline - time.time()
            if left <= 0:
                return None
            try:
                self.sock.settimeout(left)
                data, _peer = self.sock.recvfrom(65535)
            except socket.timeout:
                return None
            except OSError as exc:
                raise SnmpV3Error("socket error: %s" % exc) from None
            try:
                answer = V3Message.decode(data)
            except SnmpError:
                continue                            # not a v3 message, or not ours
            if answer.msg_id != msg_id:
                continue
            self.last_latency = time.time() - started
            answer.unauthenticated = False
            if answer.flags & FLAG_AUTH:
                if not self.auth_key:
                    raise SnmpV3Error("the agent authenticated its answer and no "
                                      "authentication password is configured")
                claimed = answer.security.auth_params
                expected = auth_digest(self.auth_key,
                                       answer.security.zeroed_copy(data),
                                       self.auth_protocol)
                if not hmac.compare_digest(expected, claimed):
                    raise SnmpV3Error("the agent's answer did not authenticate — the "
                                      "authentication password or protocol is wrong")
            elif self.auth_protocol:
                answer.unauthenticated = True
            if answer.encrypted is not None and not (answer.flags & FLAG_PRIV):
                raise SnmpV3Error("the agent sent an encrypted answer without the "
                                  "privacy flag")
            return answer

    def exchange(self, message: Message) -> Message:
        """One request, one answer, as a v1/v2c-shaped `Message` either side.

        A device that rebooted between two polls answers out of its new engine, and the
        honest response is to discover it again and ask once more — not to report the
        poll as failed. Anything else still surfaces as an error.
        """
        try:
            return self._exchange(message)
        except StaleEngine:
            self.engine_id = b""
            self.auth_key = self.priv_key = b""
            self._synced_at = 0.0
            self.discover()
            return self._exchange(message)

    def _exchange(self, message: Message) -> Message:
        if not self.engine_id:
            self.discover()
        self.keys()
        boots, when = self.engine_boots, self.engine_clock()

        security = SecurityParameters(engine_id=self.engine_id, engine_boots=boots,
                                      engine_time=when, user=self.agent.user,
                                      auth_params=b"\x00" * 12 if self.auth_protocol else b"")
        outgoing = V3Message(msg_id=self._next_id(), flags=self.flags(), security=security,
                             context_engine_id=self.engine_id,
                             context_name=self.agent.context,
                             pdu_bytes=encode_pdu(message))
        if self.priv_protocol:
            # The scoped PDU is the thing that gets encrypted; the message then carries
            # the ciphertext instead of it. One place builds it, so the two paths cannot
            # disagree about how many SEQUENCEs are involved.
            ciphertext, priv_params = encrypt_scoped(
                self.priv_key, self.priv_protocol, outgoing.scoped_bytes(), boots, when,
                self._salt.next())
            outgoing.encrypted = ciphertext
            outgoing.pdu_bytes = b""
            outgoing.security.priv_params = priv_params
        if self.auth_protocol:
            outgoing.security.auth_params = auth_digest(self.auth_key, outgoing.encode(),
                                                        self.auth_protocol)

        answer = self._send_and_receive(outgoing.encode(), outgoing.msg_id)
        if answer is None:
            raise SnmpV3Error("%s:%d did not answer in %.1fs (v3 %s)"
                              % (self.agent.host, self.agent.port, self.timeout,
                                 self.agent.describe()))
        self.messages += 1
        return self._unwrap(answer)

    def _unwrap(self, answer: V3Message) -> Message:
        """Turn an authenticated answer back into a plain `Message`."""
        # RFC 3414 §3.2.6: an authenticated request expects an authenticated answer.
        # The exception is a REPORT: an agent that rejects the *key* cannot sign with
        # it, so the report that says "your password is wrong" is necessarily unsigned
        # — and it is the one message a manager can still use. Read it, and say that it
        # came unsigned.
        if getattr(answer, "unauthenticated", False) or (self.auth_protocol
                                                        and not (answer.flags & FLAG_AUTH)):
            if answer.encrypted is not None:
                raise SnmpV3Error("the agent sent an encrypted answer it did not "
                                  "authenticate — refusing to trust it")
            reader = Reader(answer.pdu_bytes)
            try:
                pdu_tag, pdu_payload = reader.tlv()
            except SnmpError:
                raise SnmpV3Error("the agent's unsigned answer is not readable") from None
            if pdu_tag == REPORT:
                raise SnmpV3Error(self.explain_report(decode_pdu(pdu_tag, pdu_payload),
                                                      unsigned=True))
            raise SnmpV3Error("the agent answered an authenticated request without "
                              "authenticating its answer — refusing it")
        # Timeliness, RFC 3414 §3.2.7.a: a replayed message is a dead message. Only an
        # authenticated answer is worth checking: an unsigned one could not move our
        # clock even if it wanted to.
        if answer.security.engine_id and answer.security.engine_id != self.engine_id:
            raise SnmpV3Error("the answer came from a different engine (%s)"
                              % answer.security.engine_id.hex())
        if answer.security.engine_boots != self.engine_boots:
            raise StaleEngine("the agent restarted: boots %d, not %d"
                              % (answer.security.engine_boots, self.engine_boots))
        if abs(answer.security.engine_time - self.engine_clock()) > TIME_WINDOW:
            raise SnmpV3Error("the answer is outside the %d second time window "
                              "(ours %d, theirs %d) — one of the two clocks is wrong"
                              % (TIME_WINDOW, self.engine_clock(),
                                 answer.security.engine_time))

        if answer.encrypted is not None:
            if not self.priv_protocol:
                raise SnmpV3Error("the agent answered an unencrypted request with an "
                                  "encrypted answer")
            scoped = decrypt_scoped(self.priv_key, self.priv_protocol, answer.encrypted,
                                    answer.security.priv_params, self.engine_boots,
                                    answer.security.engine_time)
            scoped_reader = Reader(scoped)
            tag, payload = scoped_reader.tlv()
            if tag != SEQUENCE:
                raise SnmpV3Error("the decrypted answer is not a scoped PDU — the "
                                  "privacy password or protocol is wrong")
            inner = Reader(payload)
            inner.tlv()                                     # context engine id
            inner.tlv()                                     # context name
            pdu_tag, pdu_payload = inner.tlv()
            answer = V3Message(security=answer.security)
        else:
            scoped_reader = Reader(answer.pdu_bytes)
            pdu_tag, pdu_payload = scoped_reader.tlv()

        result = decode_pdu(pdu_tag, pdu_payload)
        if result.is_report():
            raise SnmpV3Error(self.explain_report(result))
        return result

    @staticmethod
    def explain_report(report: Message, unsigned: bool = False) -> str:
        """A REPORT is the agent telling us what it did not like. Say it in English."""
        tail = " · the REPORT itself was not authenticated" if unsigned else ""
        if not report.varbinds:
            return "the agent sent a REPORT with no explanation" + tail
        bind = report.varbinds[0]
        reason = USM_STATS.get(bind.oid)
        if reason:
            return "the agent refused the request: %s (%s)%s" % (reason, bind.oid, tail)
        return "the agent sent a REPORT about %s%s" % (bind.oid, tail)


# --------------------------------------------------------------------- self-test


def selftest() -> List[str]:
    """Three things this module promises, checked without a network.

    `nocdeck doctor` runs it: a wrong S-box or a mistaken key would show up here rather
    than as a mystery timeout against a customer's switch.
    """
    lines: List[str] = []
    engine = bytes.fromhex("000000000000000000000002")
    md5_key = hash_key("maplesyrup", engine, "md5")
    lines.append("MD5 localization: %s" % ("ok" if md5_key.hex() ==
                                           "526f5eed9fcce26f8964c2930787d82b"
                                           else "WRONG (%s)" % md5_key.hex()))
    sha_key = hash_key("maplesyrup", engine, "sha")
    lines.append("SHA localization: %s" % ("ok" if sha_key.hex() ==
                                           "6695febc9288e36282235fc7151f128497b38f3f"
                                           else "WRONG (%s)" % sha_key.hex()))
    block = crypto.aes_encrypt_block(bytes(range(16)), bytes.fromhex(
        "00112233445566778899aabbccddeeff")).hex()
    lines.append("AES-128: %s" % ("ok" if block == "69c4e0d86a7b0430d8cdb78070b4c55a"
                                  else "WRONG (%s)" % block))
    des = crypto.des_encrypt_block(bytes.fromhex("133457799bbcdff1"),
                                   bytes.fromhex("0123456789abcdef")).hex()
    lines.append("DES: %s" % ("ok" if des == "85e813540f0ab405" else "WRONG (%s)" % des))
    return lines


def hash_key(password: str, engine_id: bytes, protocol: str) -> bytes:
    """`localize_key`, named the way the RFC names the output."""
    return localize_key(password, engine_id, protocol)


#: Kept so the README's phrasing ("password to key") has a function to point at.
key_from_password = localize_key
