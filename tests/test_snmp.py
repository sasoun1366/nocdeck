"""SNMP from scratch: does the codec produce what a real agent expects?

These tests do not ask a device anything. They check the bytes, the way a compiler
test checks a compiler: encode a message, decode it back, and compare with the
hand-computed form from the RFC.
"""

from __future__ import annotations

import socket

import pytest

from nocdeck import snmp
from nocdeck.snmp import (GET_BULK_REQUEST, GET_REQUEST, INTEGER, NULL, OBJECT_ID,
                          OCTET_STRING, Message, SnmpError, Timeout, VarBind, encode_int,
                          encode_oid, decode_oid)

from conftest import FakeAgent, FakeClient


# ------------------------------------------------------------------- the codec


@pytest.mark.parametrize("value,expected", [
    (0, b"\x02\x01\x00"),
    (1, b"\x02\x01\x01"),
    (127, b"\x02\x01\x7f"),
    (128, b"\x02\x02\x00\x80"),        # a leading zero keeps a positive number positive
    (255, b"\x02\x02\x00\xff"),
    (256, b"\x02\x02\x01\x00"),
    (-1, b"\x02\x01\xff"),
    (-128, b"\x02\x01\x80"),
    (-129, b"\x02\x02\xff\x7f"),
])
def test_integers_are_encoded_the_way_the_standard_says(value, expected):
    assert encode_int(value) == expected


@pytest.mark.parametrize("oid,expected", [
    ("1.3.6.1.2.1.1.1.0", b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"),
    ("1.3.6.1.4.1.14988.1", b"\x06\x08\x2b\x06\x01\x04\x01\xf5\x0c\x01"),
    ("1.3.6.1.2.1.31.1.1.1.6.4", b"\x06\x0b\x2b\x06\x01\x02\x01\x1f\x01\x01\x01\x06\x04"),
])
def test_object_identifiers_match_the_hand_worked_examples(oid, expected):
    assert encode_oid(oid) == expected
    assert decode_oid(expected[2:]) == oid


def test_an_oid_that_cannot_be_encoded_says_so():
    with pytest.raises(SnmpError):
        encode_oid("1")
    with pytest.raises(SnmpError):
        encode_oid("1.3.6.one")


def test_a_long_oid_uses_the_base_128_form():
    oid = "1.3.6.1.4.1.14988.1.1.3.14.0"
    assert decode_oid(encode_oid(oid)[2:]) == oid


def test_a_long_length_gets_the_extended_form():
    text = "x" * 200
    encoded = snmp.encode_octets(text)
    assert encoded[1] & 0x80, "lengths over 127 need the long form"
    tag, payload = snmp.Reader(encoded).tlv()
    assert tag == OCTET_STRING and payload.decode() == text


def test_a_message_round_trips():
    sent = Message(version=1, community="public", pdu=GET_REQUEST, request_id=1234,
                   varbinds=[VarBind("1.3.6.1.2.1.1.1.0"), VarBind("1.3.6.1.2.1.1.3.0")])
    back = Message.decode(sent.encode())
    assert back.community == "public"
    assert back.request_id == 1234
    assert [bind.oid for bind in back.varbinds] == ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0"]


def test_a_get_bulk_names_its_repetitions():
    sent = Message(version=1, community="public", pdu=GET_BULK_REQUEST, request_id=9,
                   non_repeaters=0, max_repetitions=25,
                   varbinds=[VarBind("1.3.6.1.2.1.2.2.1.2")])
    back = Message.decode(sent.encode())
    assert back.pdu == GET_BULK_REQUEST
    assert back.non_repeaters == 0 and back.max_repetitions == 25
    assert back.varbinds[0].oid == "1.3.6.1.2.1.2.2.1.2"


def test_a_refusal_carries_its_reason():
    refused = Message(pdu=0xA2, request_id=1, error_status=2, error_index=1)
    decoded = Message.decode(refused.encode())
    assert decoded.error_status == 2
    with pytest.raises(SnmpError) as caught:
        decoded.raise_for_status()
    assert "no such name" in str(caught.value)


def test_an_answer_from_another_conversation_is_rejected_rather_than_guessed():
    with pytest.raises(SnmpError):
        Message.decode(b"\xff\x01\x00")


def test_an_snmpv3_answer_is_named_as_such():
    # SEQUENCE { INTEGER 3, OCTET STRING "public", [0xa8] … } — an SNMPv3 message, which
    # this tool detects and reports rather than mistaking for a broken device.
    body = (b"\x02\x01\x03" + snmp.encode_octets("public")
            + b"\xa8\x0a\x02\x01\x01\x02\x01\x00\x04\x00\x30\x00")
    v3 = b"\x30" + bytes([len(body)]) + body
    with pytest.raises(SnmpError) as caught:
        Message.decode(v3)
    assert "v3" in str(caught.value)


def test_the_value_decoders_agree_with_the_tags():
    assert snmp.decode_value(INTEGER, b"\x2a") == 42
    assert snmp.decode_value(INTEGER, b"\xff") == -1
    assert snmp.decode_value(OCTET_STRING, b"RouterOS") == "RouterOS"
    assert snmp.decode_value(OBJECT_ID, encode_oid("1.3.6.1.2.1")[2:]) == "1.3.6.1.2.1"
    assert snmp.decode_value(NULL, b"") is None
    assert snmp.decode_value(snmp.NO_SUCH_OBJECT, b"") is None
    assert snmp.decode_value(snmp.IP_ADDRESS, b"\x0a\x00\x00\x01") == "10.0.0.1"


def test_a_latin_1_description_does_not_crash_the_decoder():
    assert snmp.decode_value(OCTET_STRING, b"Caf\xe9 switch") == "Café switch"


# ------------------------------------------------------------------ the client


class ScriptedSocket:
    """A socket that answers the packet it was actually given, the way an agent does.

    `responder(asked_message)` returns the reply, or `None` for silence. Answers are
    built from the decoded request, so the request id always matches — which is what
    makes these tests about the client and not about the test.
    """

    def __init__(self, responder=None, silent: bool = False):
        self.responder = responder
        self.silent = silent
        self.sent = []
        self.rounds = 0

    def sendto(self, blob, address):
        self.sent.append((blob, address))

    def settimeout(self, value):
        pass

    def recvfrom(self, size):
        if self.silent or self.responder is None:
            raise socket.timeout()
        self.rounds += 1
        blob, _address = self.sent[-1]
        reply = self.responder(Message.decode(blob))
        if reply is None:
            raise socket.timeout()
        return reply.encode(), ("10.0.0.2", 161)

    def close(self):
        pass


def answer_for(blob: bytes, value=42, status: int = 0) -> bytes:
    """The answer a real agent would send to the request in `blob`, value `value`."""
    asked = Message.decode(blob)
    return Message(pdu=0xA2, request_id=asked.request_id, error_status=status,
                   varbinds=[VarBind(bind.oid, value, INTEGER)
                             for bind in asked.varbinds]).encode()


def test_a_request_gets_its_answer_back():
    def respond(asked):
        return Message(pdu=0xA2, request_id=asked.request_id,
                       varbinds=[VarBind(bind.oid, 42, INTEGER) for bind in asked.varbinds])

    client = snmp.Client(snmp.Agent("10.0.0.2", community="public"), timeout=0.2,
                         sock=ScriptedSocket(respond))
    got = client.get(["1.3.6.1.2.1.1.7.0"])
    assert got[0].value == 42
    assert client.requests == 1


def test_a_silent_device_raises_timeout_not_a_random_error():
    client = snmp.Client(snmp.Agent("10.0.0.2"), timeout=0.05, retries=0,
                         sock=ScriptedSocket(silent=True))
    with pytest.raises(Timeout):
        client.get(["1.3.6.1.2.1.1.1.0"])


def test_an_answer_to_someone_elses_question_is_ignored():
    """A busy network is full of SNMP packets; only the matching id counts."""
    def stranger(_asked):
        return Message(pdu=0xA2, request_id=999_999,
                       varbinds=[VarBind("1.3.6.1.2.1.1.1.0", "x", OCTET_STRING)])

    client = snmp.Client(snmp.Agent("10.0.0.2"), timeout=0.05, retries=0,
                         sock=ScriptedSocket(stranger))
    with pytest.raises(Timeout):
        client.get(["1.3.6.1.2.1.1.1.0"])


def test_the_client_refuses_to_pretend_about_v3():
    client = snmp.Client(snmp.Agent("10.0.0.2", version="3"), sock=ScriptedSocket())
    with pytest.raises(SnmpError) as caught:
        client.get(["1.3.6.1.2.1.1.1.0"])
    assert "v3" in str(caught.value)


def test_v1_uses_get_next_and_never_get_bulk():
    """GETBULK is a v2c invention; asking a v1 agent for one is a protocol error."""
    sock = ScriptedSocket(silent=True)                    # a device that will not answer
    client = snmp.Client(snmp.Agent("10.0.0.2", version="1"), timeout=0.05, retries=0,
                         sock=sock)
    with pytest.raises(Timeout):
        client.walk("1.3.6.1.2.1.2.2.1.2")
    sent = Message.decode(sock.sent[0][0])
    assert sent.pdu == snmp.GET_NEXT_REQUEST, "v1 walks one row at a time"
    assert sent.version == 0, "version field 0 means SNMPv1"


def test_a_walk_stops_when_the_agent_leaves_the_subtree():
    """The last row of a column is followed by the first row of the *next* column —
    which is the signal that the walk is finished, not a row to keep."""
    root = "1.3.6.1.2.1.2.2.1.2"
    rows = [root + ".1", root + ".2", root + ".3"]

    def walker(asked):
        cursor = asked.varbinds[0].oid
        if cursor in rows[:-1] or cursor == root:
            index = rows.index(cursor) + 1 if cursor in rows else 0
            return Message(pdu=0xA2, request_id=asked.request_id,
                           varbinds=[VarBind(rows[index], index + 1, INTEGER)])
        return Message(pdu=0xA2, request_id=asked.request_id,
                       varbinds=[VarBind("1.3.6.1.2.1.2.2.1.3.1", 6, INTEGER)])

    client = snmp.Client(snmp.Agent("10.0.0.2"), timeout=0.5,
                         sock=ScriptedSocket(walker))
    walked = client.walk(root, bulk=None)
    assert [bind.oid for bind in walked] == rows
    assert all(bind.oid.startswith(root) for bind in walked)


def test_a_walk_that_repeats_itself_ends_instead_of_spinning():
    """Some agents hand back the same row forever. The walk must stop, not fill the
    database with duplicates."""
    def stuck(asked):
        return Message(pdu=0xA2, request_id=asked.request_id,
                       varbinds=[VarBind(asked.varbinds[0].oid, 1, INTEGER)])

    sock = ScriptedSocket(stuck)
    client = snmp.Client(snmp.Agent("10.0.0.2"), timeout=0.5, sock=sock)
    walked = client.walk("1.3.6.1.2.1.2.2.1.2")
    assert len(walked) <= 1
    assert sock.rounds <= 3, "it stopped as soon as the same answer arrived twice"


def test_get_bulk_asks_for_a_column_at_a_time():
    seen_pdus = []

    def column(asked):
        seen_pdus.append((asked.pdu, asked.max_repetitions))
        if len(seen_pdus) > 1:
            return Message(pdu=0xA2, request_id=asked.request_id,
                           varbinds=[VarBind("1.3.6.1.2.1.2.2.1.3.1", 6, INTEGER)])
        return Message(pdu=0xA2, request_id=asked.request_id,
                       varbinds=[VarBind("1.3.6.1.2.1.2.2.1.2.1", "ether1", OCTET_STRING),
                                 VarBind("1.3.6.1.2.1.2.2.1.2.2", "ether2", OCTET_STRING)])

    client = snmp.Client(snmp.Agent("10.0.0.2"), timeout=0.5,
                         sock=ScriptedSocket(column))
    walked = client.walk("1.3.6.1.2.1.2.2.1.2", bulk=10)
    assert [bind.as_text() for bind in walked] == ["ether1", "ether2"]
    assert seen_pdus[0] == (GET_BULK_REQUEST, 10), "one GETBULK for ten rows"


def test_a_table_comes_back_as_columns():
    tables = {"1.3.6.1.2.1.2.2.1.2": {"1.3.6.1.2.1.2.2.1.2.1": "ether1"}}
    client = FakeClient(FakeAgent(tables=tables))
    columns = client.walk("1.3.6.1.2.1.2.2.1.2")
    assert columns[0].as_text() == "ether1"


def test_the_honest_note_about_v3_is_in_the_code():
    assert "v3" in snmp.v3_note() and "standard library" in snmp.v3_note()
