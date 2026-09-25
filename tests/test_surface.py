"""The surfaces a person actually touches: discovery, the dashboard, the CLI, the demo.

The web tests render the real pages and look for the things a person would look
for — a tile, a device name, a port table — rather than asserting on HTML shape.
The discovery tests replace the one function that goes to the network.
"""

from __future__ import annotations

import json
import socket
from datetime import timedelta

import pytest

from nocdeck import cli, discover as DI, mibs, simulate, web
from nocdeck.config import Config
from nocdeck.model import Device, Event, Reading, slug
from nocdeck.store import Store

from conftest import FakeClient, ago_iso, interface_table, mikrotik_agent, sensor_table


# ------------------------------------------------------------------- ranges


@pytest.mark.parametrize("target,expected", [
    ("10.0.0.5", ["10.0.0.5"]),
    ("10.0.0.0/30", ["10.0.0.1", "10.0.0.2"]),
    ("10.0.0.10-13", ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13"]),
    ("sw-core.example.net", ["sw-core.example.net"]),
])
def test_a_range_can_be_written_the_way_people_write_it(target, expected):
    assert DI.expand(target) == expected


def test_a_whole_subnet_expands_without_its_network_and_broadcast():
    hosts = DI.expand("192.168.1.0/24")
    assert len(hosts) == 254
    assert hosts[0] == "192.168.1.1" and hosts[-1] == "192.168.1.254"


def test_a_silly_range_is_capped_not_run_forever():
    assert len(DI.expand_all(["10.0.0.0/8"], ceiling=100)) == 100


def test_nonsense_expands_to_nothing_rather_than_exploding():
    assert DI.expand("") == []
    assert DI.expand("10.0.0.40-7") == []


# ---------------------------------------------------------------- liveness


def test_a_host_with_an_open_port_is_alive(monkeypatch):
    class Listener:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def close(self):
            pass

    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: Listener())
    is_up, how = DI.tcp_alive("10.0.0.9", ports=(161,))
    assert is_up and how == "tcp:161"


def test_a_host_that_refuses_everything_is_not_alive(monkeypatch):
    monkeypatch.setattr(socket, "create_connection",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("refused")))
    monkeypatch.setattr(DI, "fresh_port", lambda host, timeout=0.4: False)
    is_up, how = DI.alive("10.0.0.9", icmp=False)
    assert not is_up and how == ""


# -------------------------------------------------------------- snmp probe


def test_a_probe_tries_each_community_until_one_answers(monkeypatch):
    # the real probe is what we are testing, so drive its client instead of its host
    from nocdeck import snmp

    calls = []

    class FakeClient:
        def __init__(self, agent, **kwargs):
            self.agent = agent
            calls.append(agent.community)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, oids):
            if self.agent.community != "s3cret":
                raise snmp.SnmpError("no answer")
            from conftest import system_scalars
            scalars = system_scalars()
            from nocdeck.snmp import VarBind
            return [VarBind(oid, scalars.get(oid), 2) for oid in oids]

        def walk(self, root, ceiling=200, bulk=None):
            return []

    monkeypatch.setattr(DI, "Client", FakeClient)
    probe = DI.snmp_probe("10.0.0.2", communities=("public", "private", "s3cret"))
    assert probe.ok and probe.community == "s3cret"
    # tried in order and stopped at the one that answered; the second call is the
    # interface walk, which is why the last name appears twice
    assert calls[:3] == ["public", "private", "s3cret"]
    assert "core-sw-01" in probe.sys_name or "RouterOS" in probe.descr


def test_a_probe_that_answers_nothing_is_honest_about_it(monkeypatch):
    from nocdeck import snmp

    class Dead:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, oids):
            raise snmp.Timeout("did not answer")

    monkeypatch.setattr(DI, "Client", Dead)
    probe = DI.snmp_probe("10.0.0.2", communities=("public",))
    assert not probe.ok
    assert "did not answer" in probe.detail


# ------------------------------------------------------------ kind guessing


@pytest.mark.parametrize("descr,expected", [
    ("RouterOS core-sw by MikroTik", "router"),
    ("Cisco IOS Software, C2960S", "switch"),
    ("HP ProCurve Switch 2920-24G", "switch"),
    ("FortiGate-100F v7.4.1", "firewall"),
    ("Linux srv-dc-01 6.8.0-31-generic x86_64", "server"),
    ("APC Smart-UPS 3000", "ups"),
    ("HP LaserJet Enterprise M507 printer", "printer"),
    ("UniFi AP, Ubiquiti Inc.", "ap"),
    ("something nobody has seen", "generic"),
])
def test_the_kind_of_gear_is_guessed_from_what_it_says(descr, expected):
    assert DI.suggest_kind(descr=descr) == expected


def test_a_device_that_answers_becomes_a_candidate_with_its_own_name():
    candidate = DI.Candidate(host="10.0.0.2", alive_by="snmp", community="public",
                             sys_name="core-sw-01", descr="RouterOS core-sw-01",
                             vendor="mikrotik", kind="switch")
    device = candidate.to_device(group="dc")
    assert device.name == "core-sw-01"
    assert device.id == slug("core-sw-01")
    assert device.group == "dc"
    assert device.community == "public"


def test_a_host_that_only_answers_on_a_port_is_still_offered():
    candidate = DI.Candidate(host="10.0.0.9", alive_by="tcp:443", name="9")
    device = candidate.to_device()
    assert device.name == "9" and device.ping


# ------------------------------------------------------------------ the web


@pytest.fixture
def demo(store, config):
    """A store with two devices and a couple of readings each."""
    from nocdeck import poller as P

    first = Device(name="core-sw-01", host="10.0.0.2", id="core-sw-01", kind="switch",
                   group="dc", vendor="mikrotik", address="10.0.0.2")
    second = Device(name="ups-rack-a", host="10.0.0.9", id="ups-rack-a", kind="ups",
                    group="power", vendor="apc", address="10.0.0.9")
    store.save_device(first)
    store.save_device(second)
    store.add_sample(Reading(device_id="core-sw-01", at=ago_iso(minutes=2), status="up",
                             latency_ms=2.4, metrics={"cpu": 21.0, "temperature": 43.0},
                             facts={"uptime": 8640000}))
    store.add_sample(Reading(device_id="ups-rack-a", at=ago_iso(minutes=1), status="down",
                             latency_ms=None, metrics={"battery": 12.0}))
    store.save_interfaces("core-sw-01", [row for row in
                                         P.build_interfaces(_columns(interface_table(3)))])
    store.add_event(Event(at=ago_iso(minutes=1), device_id="ups-rack-a", kind="down",
                          severity="critical", message="ups-rack-a is down"))
    return web.Dashboard(store, config)


def _columns(table):
    from nocdeck.poller import match_columns
    return match_columns({root: [type("B", (), {"oid": oid, "value": value, "as_int":
                                                 (lambda self, d=None: self.value),
                                                 "as_text": (lambda self, d="": str(self.value))})()
                              for oid, value in column.items()]
                          for root, column in table.items()})


def test_the_fleet_page_shows_the_devices_and_their_state(demo):
    page = demo.index()
    assert "core-sw-01" in page and "ups-rack-a" in page
    assert 'class="card up"' in page and 'class="card down"' in page
    assert "devices" in page


def test_the_tiles_count_what_is_there(demo):
    tiles = demo.tiles_html()
    assert ">2<" in tiles                      # two devices
    assert ">1<" in tiles                      # one up, one down
    assert "unknown" in tiles


def test_a_device_page_shows_its_ports_and_its_history(demo):
    page = demo.detail("core-sw-01")
    assert page and "core-sw-01" in page
    assert "ether1" in page, "the port table"
    assert "<svg class=\"spark\"" in page, "a sparkline"
    assert "سلامت / health" in page


def test_a_device_that_does_not_exist_is_not_a_crash(demo):
    assert demo.detail("nope") is None


def test_the_wall_view_is_the_same_fleet_without_the_furniture(demo):
    wall = demo.wall()
    assert "core-sw-01" in wall and "wallcard" in wall
    assert "<header>" not in wall or "fleet" not in wall.split("<header>")[1][:200]


def test_the_events_page_lists_what_changed(demo):
    page = demo.events_html(hours=24)
    assert "ups-rack-a is down" in page and "sev-critical" in page


def test_the_api_is_json_and_says_the_same_thing(demo):
    summary = demo.api_summary()
    assert summary["by_status"] == {"up": 1, "down": 1}
    devices = demo.api_devices()
    assert {row["name"] for row in devices} == {"core-sw-01", "ups-rack-a"}
    one = demo.api_device("core-sw-01")
    assert one["device"]["kind"] == "switch" and one["interfaces"]


def test_filters_and_search_narrow_the_view(demo):
    assert [row["device"].name for row in demo.snapshot(kind="switch")] == ["core-sw-01"]
    assert [row["device"].name for row in demo.snapshot(group="power")] == ["ups-rack-a"]
    assert [row["device"].name for row in demo.snapshot(status="down")] == ["ups-rack-a"]
    assert [row["device"].name for row in demo.snapshot(query="10.0.0.2")] == ["core-sw-01"]


def test_nothing_remote_is_needed_to_draw_a_page(demo):
    """The dashboard runs on a machine with no internet; only the footer links out."""
    page = demo.index()
    for url in ("fonts.googleapis", "cdn.jsdelivr", "unpkg.com", "cdnjs"):
        assert url not in page


def test_the_server_answers_its_pages_without_touching_the_network(demo, config):
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    config.bind, config.port = "127.0.0.1", 0
    handler = web.make_handler(demo)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_address[1]
    try:
        for path, needle in (("/", "core-sw-01"), ("/wall", "wallcard"),
                             ("/events", "sev-critical"), ("/healthz", "ok"),
                             ("/_cards", "card "), ("/device/core-sw-01", "ether1")):
            with urllib.request.urlopen(base + path, timeout=5) as response:
                body = response.read().decode()
            assert needle in body, path
        with urllib.request.urlopen(base + "/api/summary", timeout=5) as response:
            assert json.loads(response.read().decode())["fleet"]["devices"] == 2
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------------ the CLI


def run(argv):
    return cli.main(argv)


def test_addition_then_listing(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Poller", lambda *a, **k: _SilentPoller())
    assert run(["add", "10.0.0.5", "--name", "edge-router", "--kind", "router",
                "--community", "public"]) == 0
    out = capsys.readouterr().out
    assert "edge-router" in out
    assert run(["list"]) == 0
    assert "edge-router" in capsys.readouterr().out


class _SilentPoller:
    def __init__(self, *args, **kwargs):
        pass

    def poll(self, device, force=False):
        from nocdeck.poller import PollOutcome
        return PollOutcome(device, Reading(device_id=device.key(), status="unknown"),
                           error="")


def test_a_device_can_be_shown_by_name_or_by_address(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Poller", lambda *a, **k: _SilentPoller())
    run(["add", "10.0.0.5", "--name", "edge-router"])
    assert run(["show", "10.0.0.5"]) == 0
    assert "edge-router" in capsys.readouterr().out


def test_removing_needs_to_be_meant(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Poller", lambda *a, **k: _SilentPoller())
    run(["add", "10.0.0.5", "--name", "edge-router"])
    assert run(["remove", "edge-router"]) == 1
    assert "add --yes" in capsys.readouterr().err
    assert run(["remove", "edge-router", "--yes"]) == 0


def test_export_and_import_round_trip(home, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "Poller", lambda *a, **k: _SilentPoller())
    run(["add", "10.0.0.5", "--name", "a-switch", "--kind", "switch"])
    out = tmp_path / "inventory.json"
    assert run(["export", "--out", str(out)]) == 0
    payload = json.loads(out.read_text())
    assert payload["devices"][0]["name"] == "a-switch"

    # a second home, a fresh database, and the inventory comes back
    monkeypatch.setenv("NOCDECK_HOME", str(tmp_path / "other"))
    assert run(["import", str(out)]) == 0
    assert Store(tmp_path / "other" / "nocdeck.db").devices()[0].name == "a-switch"


def test_importing_nonsense_says_so(home, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert run(["import", str(bad)]) == 1
    good = tmp_path / "good.json"
    good.write_text('{"devices": 5}')
    assert run(["import", str(good)]) == 1


def test_events_of_a_store_without_events_is_a_green_exit(home, capsys):
    assert run(["events"]) == 0
    assert "0 event" in capsys.readouterr().out


def test_the_file_in_the_way_is_reported(home, capsys):
    assert run(["show", "nothing-at-all"]) == 1
    assert "no device matches" in capsys.readouterr().err


def test_json_output_is_json(home, capsys):
    run(["version", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] and payload["python"]


def test_a_command_that_needs_an_argument_says_which(home, capsys):
    assert run(["add"]) == 1
    assert "give a host" in capsys.readouterr().err


def test_the_doctor_notices_an_empty_inventory(home, capsys):
    assert run(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "inventory" in out and "alerts" in out


def test_the_doctor_complains_when_devices_have_never_been_polled(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "Poller", lambda *a, **k: _SilentPoller())
    run(["add", "10.0.0.5", "--name", "x"])
    assert run(["doctor"]) == 1
    assert "no device has ever been polled" in capsys.readouterr().err


def test_an_alert_target_is_saved_and_listed(home, capsys, monkeypatch):
    monkeypatch.setattr(cli.AL, "test_target", lambda target, url="": "pretend sent")
    assert run(["alert", "add", "telegram", "ops", "--token", "1:a", "--chat", "-100"]) == 0
    assert run(["alert", "list"]) == 0
    out = capsys.readouterr().out
    assert "ops" in out and "telegram" in out


def test_an_alert_target_that_cannot_work_is_refused(home, capsys):
    assert run(["alert", "add", "telegram", "ops"]) == 1
    assert "needs --token and --chat" in capsys.readouterr().err


# ------------------------------------------------------------------- the demo


def test_the_demo_builds_an_estate_and_polls_it(home, config, capsys):
    store = Store(home / "nocdeck.db")
    nodes, simulator = simulate.build_simulator(store, config, size=4, seed=3)
    assert len(store.devices()) == 4
    from nocdeck.poller import Poller

    poller = Poller(store, config, client_factory=simulator.client_for,
                    prober=simulator.prober, tcp_prober=simulator.tcp_prober,
                    http_prober=simulator.http_prober)
    simulator.advance(60.0)
    outcomes = poller.run_once(force=True)
    assert len(outcomes) == 4
    assert all(outcome.reading.status in ("up", "down", "degraded") for outcome in outcomes)
    assert all(outcome.error == "" for outcome in outcomes)
    store.close()


def test_the_demo_devices_answer_like_real_ones(home, config):
    from nocdeck.poller import collect_snmp

    store = Store(home / "nocdeck.db")
    nodes, simulator = simulate.build_simulator(store, config, size=4, seed=5)
    for key, node in nodes.items():
        device = store.get_device(key)
        reading = collect_snmp(device, client=simulator.client_for(device))
        assert reading.ok, device.name
        assert reading.vendor == device.vendor
        assert reading.interfaces, "every imaginary device has ports"
        if device.kind in ("switch", "router", "firewall"):
            assert "temperature" in reading.metrics
            assert "optical" in reading.metrics
    store.close()


def test_the_demo_tells_a_story_if_you_let_it(home, config):
    """Two minutes in, an access point loses power; four minutes in, a port drops."""
    store = Store(home / "nocdeck.db")
    nodes, simulator = simulate.build_simulator(store, config, size=0, seed=7)
    from nocdeck.poller import Poller

    poller = Poller(store, config, client_factory=simulator.client_for,
                    prober=simulator.prober, tcp_prober=simulator.tcp_prober,
                    http_prober=simulator.http_prober)
    for step in range(12):
        simulator.advance(60.0, elapsed=step * 30.0)
        poller.run_once(force=True)
    kinds = {event.kind for event in store.events(hours=24)}
    assert "down" in kinds, "the outage happened"
    assert len([e for e in store.events(hours=24) if e.kind == "down"]) == 1, "and was said once"
    store.close()


def test_the_simulator_never_reaches_the_real_world(home, config, monkeypatch):
    """If anything here tried a socket, this test would fail loudly."""
    import socket as real_socket

    def forbidden(*args, **kwargs):
        raise AssertionError("the demo tried to open a socket")

    monkeypatch.setattr(real_socket, "create_connection", forbidden)
    store = Store(home / "nocdeck.db")
    nodes, simulator = simulate.build_simulator(store, config, size=3, seed=9)
    from nocdeck.poller import Poller

    poller = Poller(store, config, client_factory=simulator.client_for,
                    prober=simulator.prober, tcp_prober=simulator.tcp_prober,
                    http_prober=simulator.http_prober)
    simulator.advance(60.0)
    poller.run_once(force=True)
    assert store.devices()
    store.close()


# ------------------------------------------------------------------ the mibs


def test_the_vendor_table_is_data_and_can_be_extended(home):
    folder = home / "mibs"
    folder.mkdir()
    (folder / "our-gear.json").write_text(json.dumps({
        "metrics": [{"key": "temperature", "label": "Our sensor", "oid": "1.3.6.1.4.1.9999.1",
                     "unit": "°C", "vendor": ""},
                    {"key": "broken", "label": "no oid"}], }), encoding="utf-8")
    rows = mibs.custom_rows(home)
    assert len(rows) == 1 and rows[0].key == "temperature"
    assert rows[0].value_of(4300) == 4300.0


def test_a_custom_row_with_a_divisor_scales_the_raw_number(home):
    folder = home / "mibs"
    folder.mkdir()
    (folder / "tenths.json").write_text(json.dumps([
        {"key": "temperature", "label": "tenths", "oid": "1.3.6.1.4.1.1.1", "divisor": 10}]
    ), encoding="utf-8")
    assert mibs.custom_rows(home)[0].value_of(430) == 43.0


def test_every_vendor_the_tool_claims_to_know_has_rows():
    for family in ("mikrotik", "cisco", "hpe", "fortinet", "ubiquiti", "apc", "vmware",
                   "huawei", "juniper", "dell", "printer"):
        rows = [row for row in mibs.VENDOR_METRICS if row.vendor == family]
        assert rows, family


def test_the_fingerprint_beats_the_generic_case():
    assert mibs.fingerprint("RouterOS RB4011") == "mikrotik"
    assert mibs.fingerprint("", "1.3.6.1.4.1.9.1.1208") == "cisco"
    assert mibs.fingerprint("nothing familiar") == "generic"
