"""SNMPv3, tested against an agent that actually checks the crypto.

The tests that matter here are not "does the code run" but "does a wrong passphrase
fail, does a replayed clock get noticed, does a rebooted device get re-discovered".
So the fake agent verifies the digest, decrypts the scoped PDU, and signs its answers
exactly as a switch does — and the tests make it misbehave on purpose.
"""

from __future__ import annotations

import hashlib
import hmac
import subprocess

import pytest

from nocdeck import crypto, mibs, simv3, snmpv3
from nocdeck.model import Device
from nocdeck.simulate import SimNode
from nocdeck.snmp import (GET_REQUEST, INTEGER, Message, SnmpError, encode_pdu,
                          Message as _Message, VarBind)
from nocdeck.snmpv3 import (AUTH_PROTOCOLS, FLAG_AUTH, FLAG_PRIV, PRIV_PROTOCOLS,
                            SecurityParameters, Session, SnmpV3Error, V3Message,
                            auth_digest, decrypt_scoped, encrypt_scoped, localize_key,
                            stretch_password)

ENGINE = bytes.fromhex("000000000000000000000002")


# ------------------------------------------------------------------- the fixtures


@pytest.fixture()
def node():
    device = Device(name="core-sw-01", host="10.20.0.2", kind="switch", vendor="mikrotik",
                    group="dc")
    node = SimNode(device=device, seed=11)
    node.build()
    return node


@pytest.fixture()
def v3user():
    return simv3.V3User(name="nocmon", auth_protocol="sha", auth_password="auth-passphrase",
                        priv_protocol="aes", priv_password="priv-passphrase")


@pytest.fixture()
def agent(node, v3user):
    return simv3.V3Agent(node=node, users={v3user.name: v3user})


class Wire:
    """A socket straight into an agent, so the client is the real client."""

    def __init__(self, agent):
        self.agent = agent
        self.queue = []
        self.datagrams = []

    def sendto(self, blob, address):
        self.datagrams.append(blob)
        answer = self.agent.handle(blob)
        if answer is not None:
            self.queue.append(answer)

    def recvfrom(self, size):
        import socket

        if not self.queue:
            raise socket.timeout("no answer")
        return self.queue.pop(0), ("wire", 161)

    def settimeout(self, value):
        pass

    def close(self):
        pass


def client_for(agent, **overrides):
    """A real `snmp.Client` over the fake agent, with the credentials under test."""
    from nocdeck.snmp import Agent, Client

    fields = dict(host="10.0.0.1", port=161, version="3", user="nocmon", auth="sha",
                  auth_key="auth-passphrase", priv="aes", priv_key="priv-passphrase")
    fields.update(overrides)
    agent.agent = fields.pop("swap_agent", None) or agent
    return Client(Agent(**fields), timeout=1.0, retries=0, sock=Wire(agent.agent))


# ------------------------------------------------------- password to key (RFC 3414)


def test_the_password_to_key_samples_from_the_rfc_match():
    """RFC 3414 A.3.1/A.3.2: the vectors every SNMP implementation agrees on.

    `maplesyrup` against engine `000000000000000000000002`. If this drifts, nothing
    interoperates with anything, and the failure looks like a wrong password.
    """
    assert localize_key("maplesyrup", ENGINE, "md5").hex() == \
        "526f5eed9fcce26f8964c2930787d82b"
    assert localize_key("maplesyrup", ENGINE, "sha").hex() == \
        "6695febc9288e36282235fc7151f128497b38f3f"


def test_the_stretched_password_is_a_megabyte_of_repetition():
    """`Ku` is not a detail to optimise away: it is the same megabyte everywhere."""
    ku = stretch_password("maplesyrup", "md5")
    assert ku.hex() == "9faf3283884e92834ebc9847d8edd963"
    assert len(stretch_password("maplesyrup", "sha")) == 20


def test_a_long_password_and_an_empty_one_are_handled():
    assert len(stretch_password("x" * 100, "md5")) == 16
    with pytest.raises(SnmpV3Error):
        stretch_password("", "md5")
    with pytest.raises(SnmpV3Error):
        localize_key("maplesyrup", ENGINE, "sha3")


def test_the_sha2_family_is_available_for_authentication():
    """RFC 7860 added SHA-224/256/384/512; plenty of gear now defaults to SHA-256."""
    for protocol in ("sha224", "sha256", "sha384", "sha512"):
        key = localize_key("maplesyrup", ENGINE, protocol)
        assert len(key) == hashlib.new(AUTH_PROTOCOLS[protocol]).digest_size
    assert len(localize_key("maplesyrup", ENGINE, "sha256")) == 32


def test_the_digest_is_twelve_octets_of_hmac():
    key = localize_key("maplesyrup", ENGINE, "md5")
    digest = auth_digest(key, b"a message", "md5")
    assert len(digest) == 12
    assert digest == hmac.new(key, b"a message", "md5").digest()[:12]


# -------------------------------------------------------------- the ciphers


def test_the_published_cipher_vectors_still_hold():
    """FIPS-197 C.1/C.2/C.3 and the NBS DES vector: the reason to trust the rest."""
    block = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert crypto.aes_encrypt_block(bytes(range(16)), block).hex() == \
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert crypto.aes_encrypt_block(bytes(range(24)), block).hex() == \
        "dda97ca4864cdfe06eaf70a0ec0d7191"
    assert crypto.aes_encrypt_block(bytes(range(32)), block).hex() == \
        "8ea2b7ca516745bfeafc49904b496089"
    assert crypto.des_encrypt_block(bytes.fromhex("133457799bbcdff1"),
                                    bytes.fromhex("0123456789abcdef")).hex() == \
        "85e813540f0ab405"


def test_aes_cfb_round_trips_and_matches_openssl():
    """A CFB loop that encrypts correctly and decrypts incorrectly passes a
    encrypt-only check — so the check includes both directions and a long payload."""
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes(range(200))
    sealed = crypto.aes_cfb128(key, iv, plain)
    assert crypto.aes_cfb128_decrypt(key, iv, sealed) == plain
    assert crypto.aes_cfb128_decrypt(key, iv, crypto.aes_cfb128(key, iv, plain[:37])) \
        == plain[:37]
    try:
        openssl = subprocess.run(["openssl", "enc", "-aes-128-cfb", "-K", key.hex(),
                                  "-iv", iv.hex(), "-nopad"], input=plain,
                                 capture_output=True, timeout=20)
    except (OSError, subprocess.SubprocessError):        # openssl not installed: fine
        return
    if openssl.returncode == 0 and openssl.stdout:
        assert openssl.stdout == sealed


def test_des_round_trips_through_cbc():
    key = bytes.fromhex("133457799bbcdff1")
    iv = bytes.fromhex("0102030405060708")
    plain = b"a scoped PDU that is not a multiple of eight"
    sealed = crypto.des_cbc_encrypt(key, iv, plain + bytes(-len(plain) % 8))
    assert crypto.des_cbc_decrypt(key, iv, sealed).startswith(plain)


def test_a_short_key_is_refused_rather_than_silently_stretched():
    """AES-256 needs 32 key bytes and an MD5-localised key has 16: say so."""
    with pytest.raises(SnmpV3Error) as caught:
        encrypt_scoped(localize_key("p", ENGINE, "md5"), "aes256", b"x" * 16, 1, 1, 5)
    assert "32 byte key" in str(caught.value)


# ------------------------------------------------------------ the message layout


def test_a_v3_message_survives_a_round_trip():
    message = V3Message(msg_id=4242, flags=0x07,
                        security=SecurityParameters(engine_id=ENGINE, engine_boots=1,
                                                    engine_time=257, user="bert",
                                                    auth_params=bytes(range(12)),
                                                    priv_params=bytes.fromhex("0123456789abcdef")))
    message.pdu_bytes = encode_pdu(Message(pdu=GET_REQUEST, request_id=99))
    again = V3Message.decode(message.encode())
    assert (again.msg_id, again.flags, again.security.user) == (4242, 0x07, "bert")
    assert again.security.engine_id == ENGINE
    assert (again.security.engine_boots, again.security.engine_time) == (1, 257)
    assert again.security.priv_params == bytes.fromhex("0123456789abcdef")
    assert again.pdu_bytes == message.pdu_bytes


def test_the_authentication_field_is_located_where_it_really_is():
    """The digest is verified against the bytes that arrived, not against a message
    this code re-encoded: an agent may write lengths its own way, legally."""
    message = V3Message(msg_id=1, flags=0x01,
                        security=SecurityParameters(engine_id=ENGINE, engine_boots=0,
                                                    engine_time=0, user="bert",
                                                    auth_params=b"\xaa" * 12))
    message.pdu_bytes = encode_pdu(Message(pdu=GET_REQUEST, request_id=1))
    blob = message.encode()
    decoded = V3Message.decode(blob)
    offset, length = decoded.security.auth_span
    assert length == 12
    assert blob[offset:offset + length] == b"\xaa" * 12
    zeroed = decoded.security.zeroed_copy(blob)
    assert zeroed[offset:offset + length] == b"\x00" * 12
    assert len(zeroed) == len(blob)


def test_the_security_model_flag_says_what_it_means():
    session = Session(agent=_agent_for_flags(), sock=Wire(None))
    assert session.flags() == 0x04                                # reportable only
    session.auth_protocol = "sha"
    assert session.flags() == 0x05                                # + auth
    session.priv_protocol = "aes"
    assert session.flags() == 0x07                                # + priv
    session.auth_protocol = ""
    session.priv_protocol = "aes"
    with pytest.raises(SnmpV3Error) as caught:
        session.flags()
    assert "privacy without authentication" in str(caught.value)


def _agent_for_flags():
    from nocdeck.snmp import Agent

    return Agent(host="10.0.0.9", version="3")


# ------------------------------------------------------------ the conversation


def test_auth_priv_get_returns_the_value(agent):
    client = client_for(agent)
    got = client.get(["1.3.6.1.2.1.1.5.0"])
    assert got[0].as_text() == "core-sw-01"
    assert agent.requests >= 2                     # discovery, then the question
    assert agent.reports == 1                      # the discovery REPORT


def test_auth_priv_walk_returns_the_tables(agent):
    client = client_for(agent)
    rows = client.walk(mibs.IF["descr"])
    assert len(rows) == len(agent.node.ports)
    assert rows[0].as_text().startswith("Gi")


def test_a_v3_device_with_a_different_engine_id_is_rediscovered(node):
    """A rebooted device has a new clock and new localized keys; the session notices
    and asks again rather than reporting the poll as a failure."""
    user = simv3.V3User(name="nocmon", auth_protocol="sha", auth_password="auth-passphrase",
                        priv_protocol="aes", priv_password="priv-passphrase")
    agent = simv3.V3Agent(node=node, users={"nocmon": user})
    client = client_for(agent)
    assert client.get(["1.3.6.1.2.1.1.5.0"])[0].as_text() == "core-sw-01"
    agent.boots += 1                                   # the device restarted
    assert client.get(["1.3.6.1.2.1.1.5.0"])[0].as_text() == "core-sw-01"
    assert client._v3.discoveries == 2                 # discovered twice, not confused


def test_each_security_level_is_a_conversation_the_agent_accepts(node):
    users = {
        "noauth": simv3.V3User(name="noauth"),
        "authonly": simv3.V3User(name="authonly", auth_protocol="sha1",
                                 auth_password="auth-passphrase"),
        "des": simv3.V3User(name="des", auth_protocol="md5", auth_password="auth-passphrase",
                            priv_protocol="des", priv_password="priv-passphrase"),
        "sha512": simv3.V3User(name="sha512", auth_protocol="sha512",
                               auth_password="auth-passphrase", priv_protocol="aes",
                               priv_password="priv-passphrase"),
    }
    agent = simv3.V3Agent(node=node, users=users)
    cases = [("noauth", "", "", ""), ("authonly", "sha1", "auth-passphrase", ""),
             ("des", "md5", "auth-passphrase", "priv-passphrase")]
    for user, auth, auth_key, priv_key in cases:
        protocol = "des" if user == "des" else ("aes" if priv_key else "")
        client = client_for(agent, user=user, auth=auth, auth_key=auth_key, priv=protocol,
                            priv_key=priv_key)
        assert client.get(["1.3.6.1.2.1.1.5.0"])[0].as_text() == "core-sw-01"
    client = client_for(agent, user="sha512", auth="sha512", auth_key="auth-passphrase",
                        priv="aes", priv_key="priv-passphrase")
    assert client.get(["1.3.6.1.2.1.1.5.0"])[0].as_text() == "core-sw-01"


def test_a_bulk_walk_uses_getbulk_over_v3_too(agent):
    client = client_for(agent)
    batch = client.get_bulk(mibs.IF["descr"], repetitions=4)
    assert len(batch) == 4


def test_the_demo_answers_a_v3_device_through_the_real_stack(node, tmp_path):
    """The `demo` promise: an imaginary v3 device is not answered by a shortcut."""
    from nocdeck import simulate

    device = Device(name="fw-hq", host="10.20.0.10", kind="firewall", vendor="fortinet",
                    version="3", user="nocmon", auth="sha256", auth_key="demo-auth",
                    priv="aes", priv_key="demo-priv")
    nodes = {device.key(): SimNode(device=device, seed=3)}
    nodes[device.key()].build()
    simulator = simulate.Simulator(nodes, seed=1, outage=False)
    client = simulator.client_for(device)
    assert client.agent.version == "3"
    assert client.get(["1.3.6.1.2.1.1.5.0"])[0].as_text() == "fw-hq"
    wire = simulator.v3_wires[device.key()]
    assert wire.sent >= 2                                    # discovery + the question
    assert simulator.v3_agents[device.key()].reports == 1


# ------------------------------------------------------------------- the refusals


def test_a_wrong_authentication_passphrase_says_which_one_is_wrong(agent):
    client = client_for(agent, auth_key="not-the-passphrase")
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "authentication" in str(caught.value)
    assert "1.3.6.1.6.3.15.1.1.5.0" in str(caught.value)     # usmStatsWrongDigests


def test_a_wrong_privacy_passphrase_says_which_one_is_wrong(agent):
    client = client_for(agent, priv_key="not-the-passphrase")
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "privacy" in str(caught.value)


def test_an_unknown_user_is_reported_as_an_unknown_user(agent):
    client = client_for(agent, user="nobody")
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "no such user" in str(caught.value)


def test_privacy_without_authentication_is_refused_before_a_packet_is_sent(agent):
    client = client_for(agent, auth="", auth_key="", priv="aes", priv_key="p")
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "authentication" in str(caught.value)


def test_an_agent_that_lies_about_its_digest_is_caught(agent):
    agent.break_digest = True
    client = client_for(agent)
    with pytest.raises(SnmpV3Error):
        client.get(["1.3.6.1.2.1.1.5.0"])


def test_an_answer_outside_the_time_window_is_refused(node, v3user):
    """RFC 3414 §3.2.7.a: a message from an hour ago is a replay, not an answer."""
    agent = simv3.V3Agent(node=node, users={v3user.name: v3user})
    client = client_for(agent)
    assert client.get(["1.3.6.1.2.1.1.5.0"])[0].as_text() == "core-sw-01"

    real_answer = agent._answer

    def stale(*args, **kwargs):
        blob = real_answer(*args, **kwargs)
        message = V3Message.decode(blob)
        message.security.engine_time -= 900            # as if it were recorded earlier
        message.security.auth_params = b"\x00" * 12
        message.security.auth_params = auth_digest(client._v3.auth_key, message.encode(),
                                                  "sha")
        return message.encode()

    agent._answer = stale
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "time window" in str(caught.value)


def test_an_unsigned_answer_to_a_signed_question_is_refused(node, v3user):
    """RFC 3414 §3.2.6, and the reason it is a rule: an unsigned answer to a signed
    question could come from anyone on the path."""
    agent = simv3.V3Agent(node=node, users={v3user.name: v3user})
    client = client_for(agent)
    real_answer = agent._answer

    def unsigned(*args, **kwargs):
        blob = real_answer(*args, **kwargs)
        message = V3Message.decode(blob)
        message.flags = message.flags & ~FLAG_AUTH
        message.security.auth_params = b""
        return message.encode()

    agent._answer = unsigned
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "did not authenticate" in str(caught.value)


def test_a_silent_agent_is_a_timeout_not_a_wrong_password(agent):
    agent.silent = True
    client = client_for(agent)
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "did not answer" in str(caught.value)
    assert "password" not in str(caught.value)


def test_a_report_about_something_new_is_still_explained(agent):
    """An agent with a counter this tool has never seen must not crash the poll."""
    def weird(*args, **kwargs):
        return V3Message(
            msg_id=args[0].msg_id, flags=0,
            security=SecurityParameters(engine_id=agent.engine_id, engine_boots=agent.boots,
                                        engine_time=agent.engine_time()),
            pdu_bytes=encode_pdu(Message(pdu=0xA8, request_id=1, varbinds=[
                VarBind("1.3.6.1.6.3.15.1.1.9.0", 1, INTEGER)]))).encode()

    agent._answer = weird
    client = client_for(agent)
    with pytest.raises(SnmpV3Error) as caught:
        client.get(["1.3.6.1.2.1.1.5.0"])
    assert "REPORT" in str(caught.value)


# ------------------------------------------------- the device record and its secrets


def test_a_v3_device_record_with_a_missing_field_says_which_field():
    device = Device(name="sw", host="10.0.0.5", version="3", user="nocmon", auth="sha256",
                    priv="aes", priv_key="p")
    problems = device.validate()
    assert any("passphrase" in problem for problem in problems)
    assert device.validate() and not Device(name="sw", host="10.0.0.5", version="3",
                                            user="nocmon", auth="sha256",
                                            auth_key="p").validate()


def test_privacy_without_authentication_is_refused_in_the_record_too():
    device = Device(name="sw", host="10.0.0.5", version="3", user="nocmon", priv="aes",
                    priv_key="p")
    assert any("requires authentication" in problem for problem in device.validate())


def test_an_impossible_port_or_interval_is_refused():
    assert any("not a port" in problem
               for problem in Device(name="sw", host="10.0.0.5", port=0).validate())
    assert any("flood" in problem
               for problem in Device(name="sw", host="10.0.0.5", interval=1).validate())


def test_the_record_says_which_credentials_are_set_without_saying_them():
    """A dashboard is reachable from the network: passphrases stay out of the API."""
    device = Device(name="fw", host="10.0.0.9", version="3", user="nocmon", auth="sha",
                    auth_key="auth-secret", priv="aes", priv_key="priv-secret")
    public = device.public_dict()
    assert "auth-secret" not in str(public) and "priv-secret" not in str(public)
    assert public["auth_key_set"] and public["priv_key_set"]
    assert public["user"] == "nocmon"
    assert device.credentials() == "v3 user nocmon (sha/aes)"
    assert "community" in Device(name="x", host="1.1.1.1").credentials()


def test_a_community_string_formatting_never_leaks_more_than_two_characters():
    device = Device(name="x", host="1.1.1.1", community="s3cret-community")
    assert device.credentials().endswith("…ty")


def test_the_notes_about_v3_are_current():
    assert "v3 is detected" not in snmpv3.__doc__.lower()
    assert "not implemented" not in snmpv3.protocols_help()
    assert "md5" in snmpv3.protocols_help() and "aes" in snmpv3.protocols_help()
    assert snmpv3.available() is True


def test_the_selftest_that_doctor_runs_passes():
    lines = snmpv3.selftest()
    assert any("MD5 localization" in line for line in lines)
    assert all("ok" in line for line in lines), lines
    assert "WRONG" not in " ".join(lines)


def test_a_negative_integer_can_be_encoded():
    """An SFP reporting -6.50 dBm is a working optic, and INTEGER is signed."""
    from nocdeck.snmp import encode_value, decode_value

    encoded = encode_value(-650, INTEGER)
    assert decode_value(INTEGER, encoded[2:]) == -650
    assert decode_value(INTEGER, encode_value(650, INTEGER)[2:]) == 650


# ---------------------------------------------------- the demo as a test bench


def test_the_demo_estate_answers_as_itself_not_as_whatever_was_typed(monkeypatch):
    """The address decides which box answers, and the box knows its own credentials.

    A demo that accepts any passphrase teaches the wrong thing: somebody tries the flow
    on imaginary gear, sees "up", and then does the same thing on a real switch. Here the
    demo refuses exactly what a switch refuses, with the same explanation.
    """
    import tempfile
    import pathlib

    from nocdeck import config as config_mod, poller as poller_mod, simulate as sim_mod, web
    from nocdeck.store import Store

    root = pathlib.Path(tempfile.mkdtemp())
    store = Store(root / "nocdeck.db")
    config = config_mod.Config()
    nodes, simulator = sim_mod.build_simulator(store, config, size=4, seed=7, outage=False)
    poller = poller_mod.Poller(store, config, client_factory=simulator.client_for,
                              prober=simulator.prober, tcp_prober=simulator.tcp_prober,
                              http_prober=simulator.http_prober)
    dashboard = web.Dashboard(store, config, poller)

    right = dashboard.add_device({"name": "good", "host": "10.20.0.10", "version": "3",
                                  "kind": "firewall", "user": "nocmon", "auth": "sha256",
                                  "auth_key": "demo-auth-passphrase", "priv": "aes",
                                  "priv_key": "demo-priv-passphrase"})
    assert right["ok"] and right["status"] == "up"

    wrong = dashboard.add_device({"name": "bad", "host": "10.20.0.10", "version": "3",
                                  "kind": "firewall", "user": "nocmon", "auth": "sha256",
                                  "auth_key": "not-the-passphrase"})
    assert wrong["saved"] and wrong["status"] != "up"
    assert "authentication password (or protocol) is wrong" in wrong["message"]

    stranger = dashboard.add_device({"name": "stranger", "host": "10.20.0.10", "version": "3",
                                     "user": "someone-else", "auth": "sha256",
                                     "auth_key": "whatever"})
    assert "no such user" in stranger["message"]
    store.close()
