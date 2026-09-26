"""Adding a device: the model rules, the dashboard's endpoint, and the command line.

This is the feature a person meets first, and the one where a bug is most expensive: a
device that was saved with a mistyped passphrase is a red card nobody understands, and a
form that wipes a working credential costs an outage. So the tests here are about what
gets *stored*, what gets *shown*, and what gets *refused* — not about HTML.
"""

from __future__ import annotations

import json

import pytest

from nocdeck import cli, mibs, probe, web
from nocdeck.config import Config
from nocdeck.model import Device, Reading
from nocdeck.poller import Poller
from nocdeck.store import Store

from conftest import FakeClient, mikrotik_agent


# --------------------------------------------------------------------- the record


def test_a_device_typed_into_a_form_becomes_a_record():
    device = Device.from_payload({"name": "edge-rtr", "host": "10.0.0.1", "kind": "router",
                                  "group": "core", "tags": "wan, rack1",
                                  "tcp_ports": "22, 443, nonsense", "interval": "30"})
    assert (device.name, device.host, device.id) == ("edge-rtr", "10.0.0.1", "edge-rtr")
    assert device.tags == ["wan", "rack1"]
    assert device.tcp_ports == [22, 443]
    assert device.interval == 30
    assert device.validate() == []


def test_an_address_with_no_name_names_itself():
    device = Device.from_payload({"host": "10.0.0.7"})
    assert device.name == "10.0.0.7" and device.id == "10-0-0-7"


def test_a_blank_passphrase_keeps_the_one_already_stored():
    """A form always submits its fields. Empty means "I did not retype it"."""
    stored = Device(name="sw", host="10.0.0.5", version="3", user="nocmon", auth="sha256",
                    auth_key="old-auth", priv="aes", priv_key="old-priv",
                    community="s3cret")
    edited = Device.from_payload({"name": "sw", "host": "10.0.0.6", "auth_key": "",
                                  "priv_key": ""}, existing=stored)
    assert (edited.auth_key, edited.priv_key, edited.community) == ("old-auth", "old-priv",
                                                                   "s3cret")
    assert edited.host == "10.0.0.6"


def test_a_retyped_passphrase_replaces_the_stored_one():
    stored = Device(name="sw", host="10.0.0.5", version="3", user="nocmon",
                    auth_key="old-auth")
    edited = Device.from_payload({"auth_key": "new-auth"}, existing=stored)
    assert edited.auth_key == "new-auth"


def test_a_form_that_does_not_mention_a_field_does_not_wipe_it():
    """The web form knows about fifteen fields; the record has forty."""
    stored = Device(name="sw", host="10.0.0.5", notes="in the noisy rack",
                    tls_warn_days=45, expect_status=204, enabled=False)
    edited = Device.from_payload({"name": "sw", "host": "10.0.0.5"}, existing=stored)
    assert (edited.notes, edited.tls_warn_days, edited.expect_status) == (
        "in the noisy rack", 45, 204)


def test_a_device_with_no_address_is_refused_by_name():
    assert any("address is required" in problem
               for problem in Device.from_payload({"name": "x"}).validate())


# ------------------------------------------------------------- add via the dashboard


@pytest.fixture()
def dashboard(store, config):
    """A dashboard whose poller answers like a RouterOS switch, never the network."""
    poller = Poller(store, config)
    poller.client_factory = lambda device: FakeClient(mikrotik_agent())
    poller.prober = lambda *a, **k: probe.ProbeResult(ok=True, status="up", latency_ms=1.2,
                                                      loss=0.0, method="test")
    poller.tcp_prober = lambda *a, **k: probe.ProbeResult(ok=True, status="up", method="test")
    poller.http_prober = lambda *a, **k: probe.ProbeResult(ok=True, status="up", method="test")
    return web.Dashboard(store, config, poller)


def test_adding_a_device_saves_it_and_looks_at_it_once(dashboard, store):
    result = dashboard.add_device({"name": "new-sw", "host": "10.20.0.2", "kind": "switch"})
    assert result["ok"] and result["saved"]
    assert store.get_device("new-sw") is not None
    assert result["status"] == "up"
    assert result["message"].startswith("saved — up")
    assert "cpu" in result["message"]
    # the first look is a real reading, kept, so the dashboard is not empty
    assert store.last_sample("new-sw") is not None
    assert store.last_sample("new-sw").metric("cpu") is not None


def test_the_add_result_never_carries_a_passphrase(dashboard):
    result = dashboard.add_device({"name": "fw", "host": "10.20.0.10", "kind": "firewall",
                                   "version": "3", "user": "nocmon", "auth": "sha256",
                                   "auth_key": "auth-secret", "priv": "aes",
                                   "priv_key": "priv-secret"})
    assert result["ok"]
    blob = json.dumps(result)
    assert "auth-secret" not in blob and "priv-secret" not in blob
    assert result["device"]["auth_key_set"] and result["device"]["priv_key_set"]
    assert result["credentials"] == "v3 user nocmon (sha256/aes)"


def test_a_device_that_is_already_there_is_not_silently_overwritten(dashboard, store):
    store.save_device(Device(name="core-sw", host="10.0.0.1", community="private"))
    result = dashboard.add_device({"name": "core-sw", "host": "10.0.0.9"})
    assert not result["ok"] and result["conflict"] == "core-sw"
    assert store.get_device("core-sw").host == "10.0.0.1"          # untouched
    again = dashboard.add_device({"name": "core-sw", "host": "10.0.0.9", "force": True})
    assert again["ok"] and store.get_device("core-sw").host == "10.0.0.9"


def test_testing_credentials_saves_nothing_at_all(dashboard, store):
    count = len(store.devices())
    result = dashboard.add_device({"name": "ghost", "host": "10.20.0.2", "test_only": True})
    assert result["ok"] and not result["saved"]
    assert "not saved" in result["message"]
    assert len(store.devices()) == count
    assert store.last_sample("ghost") is None
    assert store.devices(group="") == [device for device in store.devices()
                                       if device.key() != "ghost"]


def test_a_v3_device_can_be_added_with_a_username_and_passphrases(dashboard, store):
    result = dashboard.add_device({"name": "v3-fw", "host": "10.20.0.10", "version": "3",
                                   "user": "nocmon", "auth": "sha256",
                                   "auth_key": "auth-secret", "priv": "aes",
                                   "priv_key": "priv-secret", "kind": "firewall"})
    assert result["ok"]
    saved = store.get_device("v3-fw")
    assert (saved.version, saved.user, saved.auth, saved.priv) == ("3", "nocmon", "sha256",
                                                                  "aes")
    assert saved.auth_key == "auth-secret" and saved.priv_key == "priv-secret"
    assert saved.credentials() == "v3 user nocmon (sha256/aes)"


def test_a_device_that_refuses_the_credentials_says_so_and_is_still_saved(dashboard,
                                                                         store):
    """The reading is the diagnosis: the device is kept, the reason is shown."""
    dashboard.poller.client_factory = lambda device: FakeClient(
        mikrotik_agent(refuse=(mibs.SYS["descr"],)))
    result = dashboard.add_device({"name": "mute", "host": "10.20.0.9"})
    assert result["ok"] and result["saved"]
    assert store.get_device("mute") is not None
    assert result["status"] in ("up", "down", "unknown")
    assert result["message"]


def test_a_missing_field_is_answered_with_words_not_a_traceback(dashboard):
    result = dashboard.add_device({"name": "x", "host": "10.0.0.1", "version": "3"})
    assert not result["ok"]
    assert any("username" in problem for problem in result["problems"])


def test_a_device_can_be_removed_from_the_dashboard(dashboard, store):
    dashboard.add_device({"name": "typo", "host": "10.0.0.1"})
    assert store.get_device("typo") is not None
    assert dashboard.remove_device("typo")["ok"]
    assert store.get_device("typo") is None
    assert not dashboard.remove_device("typo")["ok"]


# --------------------------------------------------------------------- the web form


def test_the_form_page_offers_both_kinds_of_credentials(dashboard):
    html = dashboard.add_form()
    for needle in ("SNMPv3", "community string", "v1/v2c", "authentication passphrase",
                   "privacy passphrase", "add device", "nocdeck add 10.20.0.2"):
        assert needle in html, needle
    # and it says out loud where those passphrases are going
    assert "anyone on the path" in html


def test_the_form_page_says_what_the_device_record_says(dashboard):
    html = dashboard.add_form({"host": "10.0.0.9", "version": "3", "auth": "sha512"})
    assert 'value="10.0.0.9"' in html
    assert 'value="sha512" selected' in html


def test_the_device_api_never_returns_a_stored_secret(store, config):
    store.save_device(Device(name="sw", host="10.0.0.5", version="3", user="nocmon",
                             auth="sha", auth_key="auth-secret", priv="aes",
                             priv_key="priv-secret", community="public"))
    payload = web.Dashboard(store, config).api_device("sw")
    blob = json.dumps(payload)
    assert "auth-secret" not in blob and "priv-secret" not in blob
    assert payload["device"]["auth_key_set"] is True
    assert payload["device"]["community"] == ""


def test_the_dashboard_offers_a_way_to_add_and_to_remove(dashboard):
    assert 'href="/add"' in dashboard.index()

def test_the_fleet_page_links_to_the_form(dashboard):
    assert 'href="/add"' in dashboard.index()


# ------------------------------------------------------------------ the command line


def test_the_cli_adds_a_v3_device_with_its_passphrases(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda args: Config())
    code = cli.main(["add", "10.9.9.9", "--name", "cli-fw", "--version", "3",
                     "--user", "nocmon", "--auth", "sha256", "--auth-key", "auth-pass",
                     "--priv", "aes", "--priv-key", "priv-pass", "--kind", "firewall",
                     "--no-snmp", "--no-ping"])
    captured = capsys.readouterr()
    assert "added" in captured.out + captured.err
    store = Store(home / "nocdeck.db")
    try:
        saved = store.get_device("cli-fw")
    finally:
        store.close()
    assert saved is not None
    assert saved.credentials() == "v3 user nocmon (sha256/aes)"
    assert saved.auth_key == "auth-pass" and saved.priv_key == "priv-pass"
    assert code == 0


def test_the_cli_refuses_a_v3_device_with_no_username(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda args: Config())
    code = cli.main(["add", "10.9.9.9", "--version", "3", "--no-snmp", "--no-ping"])
    captured = capsys.readouterr()
    assert code == 1
    assert "username" in captured.out + captured.err
    store = Store(home / "nocdeck.db")
    try:
        assert store.get_device("10-9-9-9") is None      # nothing was saved
    finally:
        store.close()


def test_the_cli_refuses_privacy_without_authentication(home, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda args: Config())
    code = cli.main(["add", "10.9.9.8", "--version", "3", "--user", "nocmon",
                     "--priv", "aes", "--priv-key", "p", "--no-snmp", "--no-ping"])
    captured = capsys.readouterr()
    assert code == 1
    assert "requires authentication" in captured.out + captured.err


def test_the_cli_add_help_lists_the_v3_flags(capsys):
    """`--help` is documentation; if the flags are not on it they do not exist.

    `add --help` exits through SystemExit, which is what argparse does and what a
    shell expects, so the test expects it too rather than fighting it.
    """
    with pytest.raises(SystemExit) as caught:
        cli.main(["add", "--help"])
    assert caught.value.code == 0
    text = capsys.readouterr().out
    for flag in ("--user", "--auth", "--auth-key", "--priv", "--priv-key", "--context",
                 "--keys-are-hex", "--version"):
        assert flag in text, flag
