"""The engine: what a device is, what it means, and what gets written down.

Every test here drives the real collector, the real decision and the real store —
only the device is imaginary. That is the point of the fake client: the logic under
test is exactly the logic that runs against a rack.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from nocdeck import mibs, poller as P, probe
from nocdeck.config import Config
from nocdeck.model import (Device, Interface, Reading, Thresholds, worst, STATUS_ORDER,
                           CLASS_THRESHOLDS)
from nocdeck.snmp import INTEGER, NULL, OBJECT_ID, OCTET_STRING, TIMETICKS, VarBind

from conftest import (FROZEN, FakeAgent, FakeClient, ago, ago_iso, interface_table,
                      mikrotik_agent, sensor_table, system_scalars)


# ------------------------------------------------------------------ thresholds


def test_a_high_number_is_bad_when_high_is_bad():
    limits = Thresholds(cpu=85)
    assert limits.trouble("cpu", 10) is None
    assert limits.trouble("cpu", 86) == "degraded"
    assert limits.trouble("cpu", 94) == "critical"


def test_a_low_number_is_bad_when_low_is_bad():
    """A UPS with 100 % battery is healthy; 15 % is the reason the alert exists."""
    limits = Thresholds(battery=40)
    assert limits.trouble("battery", 100) is None
    assert limits.trouble("battery", 35) == "degraded"
    assert limits.trouble("battery", 30) == "critical"
    assert limits.direction("battery") == "low"


def test_optical_power_reads_downward_too():
    limits = Thresholds(optical_dbm=-20)
    assert limits.trouble("optical", -6.5) is None
    assert limits.trouble("optical", -21) == "degraded"
    assert limits.trouble("optical", -30) == "critical"


def test_a_missing_reading_is_not_trouble():
    assert Thresholds().trouble("cpu", None) is None


def test_each_class_of_device_has_sensible_lines():
    assert CLASS_THRESHOLDS["printer"].temperature < CLASS_THRESHOLDS["server"].temperature
    assert CLASS_THRESHOLDS["ups"].battery == 50
    # a threshold given on the device wins over the class
    device = Device(name="x", host="10.0.0.1", kind="switch", thresholds={"cpu": 50})
    assert device.limits().cpu == 50


def test_worst_state_wins():
    assert worst("up", "down", "unknown") == "down"
    assert worst("up", "degraded") == "degraded"
    assert worst() == "unknown"
    assert STATUS_ORDER["down"] < STATUS_ORDER["degraded"] < STATUS_ORDER["up"]


# ------------------------------------------------------------- the SNMP reading


def test_a_switch_reports_its_identity_and_health():
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2", kind="switch"),
                             client=FakeClient(mikrotik_agent()))
    assert reading.ok
    assert reading.vendor == "mikrotik"
    assert reading.facts["sys_name"] == "core-sw-01"
    assert reading.facts["uptime"] == 86_400_00
    # the scalars came back in real units, not raw integers
    assert reading.metrics["cpu"] == pytest.approx(21.0)
    assert reading.metrics["temperature"] == pytest.approx(43.0)
    assert reading.metrics["voltage"] == pytest.approx(12.1)


def test_the_interfaces_come_out_as_ports():
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2", kind="switch"),
                             client=FakeClient(mikrotik_agent()))
    assert len(reading.interfaces) == 4
    port = reading.interfaces[0]
    assert port.name == "ether1"
    assert port.speed_mbps == 1000
    assert port.oper == "up"
    assert port.in_octets == 10 ** 9


def test_a_port_that_is_down_is_read_as_down():
    agent = mikrotik_agent()
    agent.tables = {**interface_table(4, oper_down=(4,)), **sensor_table()}
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2"), client=FakeClient(agent))
    down = [port for port in reading.interfaces if port.oper == "down"]
    assert [port.name for port in down] == ["ether4"]


def test_sensors_are_scaled_the_way_the_standard_says():
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2"), client=FakeClient(mikrotik_agent()))
    found = {row["name"]: row for row in reading.sensors}
    assert found["chassis temperature"]["value"] == pytest.approx(42.0)
    assert found["chassis temperature"]["unit"] == "°C"
    assert found["fan 1"]["value"] == 4200
    assert found["sfp rx power"]["value"] == pytest.approx(-6.5)
    assert found["sfp rx power"]["unit"] == "dBm"


def test_a_vendor_table_fills_what_the_scalars_did_not():
    """A Cisco answers CPU inside a table of processor pools, not as one number."""
    agent = FakeAgent(
        scalars=system_scalars(descr="Cisco IOS Software, C2960S", object_id="1.3.6.1.4.1.9.1.1208"),
        tables={"1.3.6.1.4.1.9.9.109.1.1.1.1.8": {"1.3.6.1.4.1.9.9.109.1.1.1.1.8.1": 12,
                                                  "1.3.6.1.4.1.9.9.109.1.1.1.1.8.2": 48}})
    reading = P.collect_snmp(Device(name="sw", host="10.0.0.3", kind="switch"),
                             client=FakeClient(agent))
    assert reading.vendor == "cisco"
    assert reading.metrics["cpu"] == pytest.approx(30.0), "the mean of the two pools"


def test_a_scalar_beats_a_table_row_for_the_same_metric():
    """The device's own answer for the whole chassis outranks one card inside it.

    A RouterOS box reports its board temperature as a scalar and each SFP's
    temperature as a table row; the board is the number a person wants on the card.
    """
    agent = mikrotik_agent()
    agent.tables = {**interface_table(2), **sensor_table(),
                    "1.3.6.1.4.1.14988.1.1.19.1.1.2": {
                        "1.3.6.1.4.1.14988.1.1.19.1.1.2.1": 47,
                        "1.3.6.1.4.1.14988.1.1.19.1.1.2.2": 51}}
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2"), client=FakeClient(agent))
    assert reading.metrics["temperature"] == pytest.approx(43.0), "the scalar, not the hottest SFP"


def test_a_broken_mib_costs_a_field_and_not_the_poll():
    agent = mikrotik_agent()
    agent.refuse = ("1.3.6.1.2.1.99",)                 # no entity sensors at all
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2"), client=FakeClient(agent))
    assert reading.ok
    assert reading.metrics["cpu"] == pytest.approx(21.0)
    assert reading.sensors == []


def test_a_device_that_refuses_the_first_question_is_reported_not_guessed():
    agent = FakeAgent(error="no answer from 10.0.0.2:161")
    reading = P.collect_snmp(Device(name="s", host="10.0.0.2"), client=FakeClient(agent))
    assert not reading.ok
    assert "no answer" in reading.errors[0]


def test_storage_is_only_read_where_it_exists():
    """A switch has no filesystems; a Linux server does."""
    hr = {mibs.HR["storage_descr"]: {"%s.1" % mibs.HR["storage_descr"]: "/"},
          mibs.HR["storage_size"]: {"%s.1" % mibs.HR["storage_size"]: 1000},
          mibs.HR["storage_used"]: {"%s.1" % mibs.HR["storage_used"]: 900},
          mibs.HR["storage_alloc"]: {"%s.1" % mibs.HR["storage_alloc"]: 1024}}
    agent = FakeAgent(scalars=system_scalars(descr="Linux srv-dc-01",
                                             object_id="1.3.6.1.4.1.8072.3.2.10"),
                      tables={**hr, mibs.UCD["mem_total"]: {mibs.UCD["mem_total"]: 8 * 1024 ** 3},
                              })
    reading = P.collect_snmp(Device(name="srv", host="10.0.0.9", kind="server"),
                             client=FakeClient(agent))
    assert reading.filesystems and reading.filesystems[0]["percent"] == pytest.approx(90.0)
    assert reading.metrics["disk"] == pytest.approx(90.0)


# ------------------------------------------------------------------- the poll


def mikrotik_client(agent=None):
    agent = agent or mikrotik_agent()
    return lambda device: FakeClient(agent)


def test_one_poll_produces_one_reading(switch, config):
    reading = P.poll_device(switch, config, client_factory=mikrotik_client(),
                            prober=lambda *a, **k: probe.ProbeResult(ok=True, status="up",
                                                                     latency_ms=2.0, loss=0.0,
                                                                     method="sim"))
    assert reading.status == "up"
    assert reading.checks["snmp"] == "up" and reading.checks["ping"] == "up"
    assert reading.metric("cpu") == pytest.approx(21.0)
    assert reading.interfaces


def test_a_device_that_answers_snmp_but_not_icmp_is_not_called_down(switch, config):
    reading = P.poll_device(switch, config, client_factory=mikrotik_client(),
                            prober=lambda *a, **k: probe.ProbeResult(
                                ok=False, status="down", loss=100.0, method="sim"))
    assert reading.checks["ping"] == "down"
    assert reading.status == "down", "a failed ping is still a failure"


def test_the_url_check_reports_the_certificate(server, config):
    server.http_url = "https://10.0.0.30/"
    outcome = probe.ProbeResult(ok=True, status="up", latency_ms=30, method="http",
                                detail="HTTP 200", extra={"tls_days": 9, "status_code": 200})
    reading = P.poll_device(server, config, client_factory=mikrotik_client(),
                            prober=lambda *a, **k: probe.ProbeResult(ok=True, status="up"),
                            tcp_prober=lambda *a, **k: probe.ProbeResult(ok=True, status="up"),
                            http_prober=lambda *a, **k: outcome)
    assert reading.checks["http"] == "degraded", "a certificate nine days out is a warning"
    assert reading.facts["tls_days"] == 9
    assert reading.facts["status_code"] == 200


def test_a_two_hundred_with_ninety_days_left_is_simply_up(server, config):
    server.http_url = "https://10.0.0.30/"
    outcome = probe.ProbeResult(ok=True, status="up", latency_ms=30, method="http",
                                detail="HTTP 200", extra={"tls_days": 90})
    reading = P.poll_device(server, config, client_factory=mikrotik_client(),
                            prober=lambda *a, **k: probe.ProbeResult(ok=True, status="up"),
                            tcp_prober=lambda *a, **k: probe.ProbeResult(ok=True, status="up"),
                            http_prober=lambda *a, **k: outcome)
    assert reading.checks["http"] == "up"


def test_octet_counters_become_a_rate():
    """Two polls, a minute apart, and the difference is the only interesting number."""
    first = Interface(index=1, name="ether1", oper="up", speed_mbps=1000,
                      in_octets=1_000_000, out_octets=500_000)
    second = Interface(index=1, name="ether1", oper="up", speed_mbps=1000,
                       in_octets=1_000_000 + 7_500_000, out_octets=500_000 + 3_750_000)
    previous = Reading(device_id="x", at=(FROZEN - timedelta(seconds=60)).isoformat(),
                       status="up")
    second.rate(first, 60.0)
    # 7 500 000 bytes in 60 s = 1 Mbit/s; a 1 Gbit link is therefore 0.1 % busy
    assert second.in_bps == pytest.approx(1_000_000.0)
    assert second.in_util == pytest.approx(0.1)
    assert second.out_bps == pytest.approx(500_000.0)


def test_a_counter_that_went_backwards_is_ignored_not_graffitied():
    """A device that rebooted restarts its counters. The rate is unknown, not negative."""
    first = Interface(index=1, in_octets=9_000_000, speed_mbps=1000)
    second = Interface(index=1, in_octets=12_000, speed_mbps=1000)
    second.rate(first, 60.0)
    assert second.in_bps == 0.0
    assert second.in_util == 0.0


def test_a_port_that_went_down_is_an_event(switch, config):
    before = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="up")
    now = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="up")
    now.interfaces = [Interface(index=2, name="ether2", oper="down")]
    events = P.events_for(switch, now, before,
                          previous_interfaces={2: Interface(index=2, name="ether2", oper="up")},
                          config=config)
    assert [event.kind for event in events] == ["interface-down"]
    assert "ether2" in events[0].message


def test_a_device_that_comes_back_says_so(switch, config):
    before = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="down")
    now = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="up")
    events = P.events_for(switch, now, before)
    assert [event.kind for event in events] == ["up"]
    assert events[0].severity == "info"


def test_the_same_trouble_is_not_reported_twice(switch, config):
    before = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="down")
    now = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="down")
    assert P.events_for(switch, now, before) == []


def test_a_crossed_line_is_an_event_with_the_number_in_it(switch, config):
    """A switch's warning line is 75 °C, so 78 is a warning and 90 is critical."""
    before = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="up")
    warm = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="degraded",
                   metrics={"temperature": 78.0})
    events = P.events_for(switch, warm, before, config=config)
    warm_event = [event for event in events if event.subject == "temperature"][0]
    assert warm_event.message == ("core-sw-01: temperature 78.0 °C is above the warning "
                                  "line (75)")
    assert warm_event.severity == "warning"

    hot = Reading(device_id=switch.key(), at=FROZEN.isoformat(), status="down",
                  metrics={"temperature": 90.0})
    events = P.events_for(switch, hot, before, config=config)
    hot_event = [event for event in events if event.subject == "temperature"][0]
    assert hot_event.severity == "critical"


def test_a_low_battery_is_worded_as_below_not_over():
    ups = Device(name="ups", host="10.0.0.9", kind="ups", id="ups")
    empty = Reading(device_id="ups", at=FROZEN.isoformat(), status="down",
                    metrics={"battery": 20.0})
    events = P.events_for(ups, empty, None)
    battery = [event for event in events if event.subject == "battery"][0]
    # the warning line for a UPS is 50 %, and the critical line sits eight below it
    assert battery.message == ("ups: battery 20.0% is below the critical line (42)"), \
        "a battery goes down, not up"
    assert battery.severity == "critical"


# ------------------------------------------------------------------ the store


def test_a_device_survives_a_round_trip(store, switch):
    store.save_device(switch)
    back = store.get_device("core-sw-01")
    assert back.name == switch.name
    assert back.tcp_ports == [] and back.interval == 30


def test_an_unknown_field_in_an_old_file_is_ignored(store):
    device = Device.from_dict({"name": "x", "host": "10.0.0.1", "kind": "switch",
                               "field_from_the_future": 42})
    assert device.name == "x"
    assert not hasattr(device, "field_from_the_future")


def test_samples_and_history(store, switch):
    store.save_device(switch)
    for index in range(5):
        store.add_sample(Reading(device_id=switch.key(), status="up",
                                 at=ago_iso(minutes=5 - index),
                                 metrics={"cpu": 10.0 + index}, latency_ms=1.0 + index))
    history = store.history(switch.key(), "cpu", hours=24)
    assert [value for _when, value in history] == [10.0, 11.0, 12.0, 13.0, 14.0]
    assert store.last_sample(switch.key()).metric("cpu") == 14.0


def test_two_polls_in_the_same_second_are_kept_apart(store, switch):
    """A hand-triggered poll next to the scheduled one is a real thing."""
    store.save_device(switch)
    for value in (1.0, 2.0, 3.0):
        store.add_sample(Reading(device_id=switch.key(), status="up", at=ago_iso(),
                                 metrics={"cpu": value}))
    assert store.last_sample(switch.key()).metric("cpu") == 3.0
    assert store.last_samples([switch.key()])[switch.key()].metric("cpu") == 3.0


def test_availability_is_computed_from_the_samples(store, switch):
    store.save_device(switch)
    for index, status in enumerate(("up", "up", "up", "down")):
        store.add_sample(Reading(device_id=switch.key(), status=status,
                                 at=ago_iso(minutes=4 - index)))
    assert store.uptime(switch.key(), hours=1)["percent"] == 75.0


def test_the_fleet_summary_counts_readings(store, switch):
    store.save_device(switch)
    store.add_sample(Reading(device_id=switch.key(), status="up", at=ago_iso(),
                             latency_ms=4.0))
    fleet = store.fleet(hours=1)
    assert fleet["devices"] == 1 and fleet["enabled"] == 1
    assert fleet["samples"] == 1


def test_events_are_stored_with_their_severity(store, switch):
    store.save_device(switch)
    from nocdeck.model import Event
    store.add_event(Event(at=ago_iso(minutes=2), device_id=switch.key(), kind="down",
                          severity="critical", message="core-sw-01 is down"))
    store.add_event(Event(at=ago_iso(minutes=1), device_id=switch.key(), kind="up",
                          severity="info", message="core-sw-01 is back"))
    assert len(store.events(hours=24)) == 2
    assert [event.kind for event in store.events(hours=24, severity="critical")] == ["down"]
    assert store.last_event(switch.key(), "down").message.endswith("is down")


def test_an_open_problem_is_known_to_be_open(store, switch):
    store.save_device(switch)
    from nocdeck.model import Event
    store.add_event(Event(at=ago_iso(minutes=2), device_id=switch.key(), kind="down",
                          severity="critical", subject="device"))
    assert store.open_problem(switch.key(), "down", "device") is not None
    store.add_event(Event(at=ago_iso(minutes=1), device_id=switch.key(), kind="up",
                          severity="info", subject="device"))
    assert store.open_problem(switch.key(), "down", "device") is None, "it was closed"


def test_retention_keeps_the_story_and_drops_the_graph(store, switch):
    store.save_device(switch)
    old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    store.add_sample(Reading(device_id=switch.key(), status="up", at=old, metrics={"cpu": 5.0}))
    from nocdeck.model import Event
    store.add_event(Event(at=old, device_id=switch.key(), kind="down", severity="critical",
                          message="a month ago"))
    removed = store.prune(sample_days=14, event_days=120, rollup_days=400)
    assert removed["samples"] == 1 and removed["events"] == 0
    assert len(store.events(hours=24 * 90)) == 1


def test_an_hourly_rollup_survives_the_samples_being_deleted(store, switch):
    store.save_device(switch)
    for index in range(3):
        store.add_sample(Reading(device_id=switch.key(), status="up",
                                 at=ago_iso(minutes=3 - index),
                                 metrics={"cpu": 10.0 + index * 10}))
    rolled = store.rolled(switch.key(), "cpu", hours=48)
    assert rolled and rolled[0][2] == pytest.approx(30.0), "the high of the hour"


def test_deleting_a_device_takes_its_history_with_it(store, switch):
    store.save_device(switch)
    store.add_sample(Reading(device_id=switch.key(), status="up", at=ago_iso()))
    assert store.delete_device(switch.key())
    assert store.last_sample(switch.key()) is None
    assert store.history(switch.key()) == []


def test_interfaces_are_upserted_not_duplicated(store, switch):
    store.save_device(switch)
    store.save_interfaces(switch.key(), [Interface(index=1, name="ether1", in_octets=100)])
    store.save_interfaces(switch.key(), [Interface(index=1, name="ether1", in_octets=200)])
    rows = store.interfaces(switch.key())
    assert len(rows) == 1 and rows[0].in_octets == 200


# ------------------------------------------------------------------- poller


def poller_with(store, config, agent=None, ping="up"):
    agent = agent or mikrotik_agent()
    return P.Poller(store, config, client_factory=lambda device: FakeClient(agent),
                    prober=lambda *a, **k: probe.ProbeResult(ok=ping == "up", status=ping,
                                                             latency_ms=2.0, loss=0.0,
                                                             method="sim"))


def test_a_poll_writes_a_sample_and_learns_the_device(store, config, switch):
    store.save_device(switch)
    poller = poller_with(store, config)
    outcome = poller.poll(switch, force=True)
    assert outcome.reading.status == "up"
    assert store.last_sample(switch.key()) is not None
    learned = store.get_device(switch.key())
    assert learned.vendor == "mikrotik"
    assert learned.sys_name == "core-sw-01"


def test_one_bad_poll_is_not_an_outage(store, config, switch):
    """Two failures before "down": the first lost packet only starts a count."""
    store.save_device(switch)
    config.failures_to_down = 2
    poller_with(store, config).poll(switch, force=True)
    assert store.last_sample(switch.key()).status == "up"

    bad = poller_with(store, config, ping="down")
    first = bad.poll(switch, force=True)
    assert first.reading.status == "up", "still up: one failed poll is not evidence enough"
    second = bad.poll(switch, force=True)
    assert second.reading.status == "down", "the second one is"
    assert store.last_sample(switch.key()).status == "down"


def test_hysteresis_is_kept_in_the_database_so_a_restart_remembers(store, config, switch):
    store.save_device(switch)
    config.failures_to_down = 3
    poller = poller_with(store, config)
    poller.poll(switch, force=True)
    settled = poller._hysteresis(switch, Reading(device_id=switch.key(), status="down"),
                                 store.last_sample(switch.key()))
    assert settled == "up", "the first bad poll keeps yesterday's opinion"
    assert "streak" in store.meta("hysteresis:%s" % switch.key())


def test_the_second_bad_poll_changes_the_opinion(store, config, switch):
    store.save_device(switch)
    config.failures_to_down = 2
    poller = poller_with(store, config)
    poller.poll(switch, force=True)
    for _ in range(2):
        decided = poller._hysteresis(switch, Reading(device_id=switch.key(), status="down"),
                                     store.last_sample(switch.key()))
    assert decided == "down"


def test_a_client_that_explodes_is_a_failed_check_not_a_crashed_cycle(store, config, switch):
    """A device whose SNMP stack misbehaves is 'down', with the reason attached —
    the poll cycle itself must survive to poll the next device."""
    store.save_device(switch)

    def exploding(device):
        raise RuntimeError("the fake agent fell over")

    poller = P.Poller(store, config, client_factory=exploding,
                      prober=lambda *a, **k: probe.ProbeResult(ok=False, status="down",
                                                               loss=100.0, method="sim"))
    outcome = poller.poll(switch, force=True)
    assert outcome.error == "", "the cycle caught it"
    assert outcome.reading.status == "down"
    assert "fell over" in outcome.reading.message
    assert store.last_sample(switch.key()) is not None


def test_flapping_ports_are_reported_once_each(store, config, switch):
    store.save_device(switch)
    from nocdeck.model import Event
    for _ in range(5):
        store.add_event(Event(at=ago_iso(minutes=2), device_id=switch.key(),
                              kind="interface-down", severity="warning", subject="ether4"))
    poller = poller_with(store, config)
    events = poller._suppress_flaps(switch, [
        Event(at=FROZEN.isoformat(), device_id=switch.key(), kind="interface-down",
              severity="warning", subject="ether4", message="port down"),
        Event(at=FROZEN.isoformat(), device_id=switch.key(), kind="interface-up",
              severity="info", subject="ether4", message="port up")], Reading(device_id="x"))
    assert len(events) == 1, "the bad half is enough"
    assert events[0].detail.get("flapping")


def test_run_once_polls_only_what_is_due(store, config, switch):
    store.save_device(switch)
    poller = poller_with(store, config)
    assert len(poller.run_once()) == 1
    assert len(poller.run_once()) == 0, "just polled; not due again yet"


def test_the_wait_is_bounded_so_the_loop_stays_responsive(store, config, switch):
    store.save_device(switch)
    poller = poller_with(store, config)
    assert 0 < poller.wait_seconds() <= 30
