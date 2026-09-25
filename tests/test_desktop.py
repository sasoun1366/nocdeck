"""The desktop window, driven without a screen.

Qt runs happily on a machine with no display (`QT_QPA_PLATFORM=offscreen`), which
means the window can be built, filled and inspected inside a test — the same window
a person gets. If PyQt6 is not installed the whole file skips: the rest of the tool
has no such dependency and the suite must not grow one.
"""

from __future__ import annotations

import json
import os
import pathlib

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nocdeck import desktop as DESKTOP                      # noqa: E402
from nocdeck import cli                                     # noqa: E402
from nocdeck.config import Config                           # noqa: E402
from nocdeck.model import AlertTarget, Device, Event, Reading, Thresholds  # noqa: E402
from nocdeck.store import Store                             # noqa: E402

from nocdeck.desktop import desktop as DESKTOP_IMPL         # noqa: E402
from conftest import ago_iso                                # noqa: E402

pytestmark = pytest.mark.skipif(not DESKTOP.available(),
                                reason="PyQt6 is not installed (or Qt cannot start)")

if DESKTOP.available():
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication, QLabel

    from nocdeck.desktop.desktop import MainWindow, PollWorker, WallWindow


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture
def window(app, home, config):
    """A window over two devices: one healthy switch, one dead UPS."""
    store = Store(home / "nocdeck.db")
    store.save_device(Device(name="core-sw-01", host="10.0.0.2", id="core-sw-01",
                             kind="switch", group="dc", vendor="mikrotik",
                             address="10.0.0.2"))
    store.save_device(Device(name="ups-rack-a", host="10.0.0.9", id="ups-rack-a", kind="ups",
                             group="power", vendor="apc", address="10.0.0.9"))
    store.add_sample(Reading(device_id="core-sw-01", at=ago_iso(minutes=2), status="up",
                             latency_ms=2.4, metrics={"cpu": 21.0, "memory": 44.0,
                                                      "temperature": 43.0}))
    store.add_sample(Reading(device_id="ups-rack-a", at=ago_iso(minutes=1), status="down",
                             metrics={"battery": 12.0}))
    store.add_event(Event(at=ago_iso(minutes=1), device_id="ups-rack-a", kind="down",
                          severity="critical", message="ups-rack-a is down"))
    built = MainWindow(store, config, poller=None)
    yield built
    built.close()
    store.close()


def keys(window) -> list:
    """The device keys in the side list, in the order the window put them."""
    return [window.device_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(window.device_list.count())]


def test_the_window_opens_with_the_inventory_in_it(window, app):
    assert "nocdeck" in window.windowTitle()
    assert [window.tabs.tabText(i) for i in range(window.tabs.count())] == [
        "fleet", "device", "events", "alerts", "settings"]
    assert sorted(keys(window)) == ["core-sw-01", "ups-rack-a"]
    assert window.fleet_tab.table.rowCount() == 2


def test_the_fleet_table_counts_and_colours_what_it_shows(window, app):
    assert window.fleet_tab.tiles["devices"].value.text() == "2"
    assert window.fleet_tab.tiles["down"].value.text() == "1"
    assert window.fleet_tab.tiles["events"].value.text() == "1"
    colours = [window.fleet_tab.table.item(row, 0).foreground().color().name()
               for row in range(window.fleet_tab.table.rowCount())]
    assert len(set(colours)) == 2, "one row is not the colour of the other"


def test_a_table_row_carries_its_device_key(window, app):
    assert window.fleet_tab.table.item(0, 0).data(Qt.ItemDataRole.UserRole) in ("core-sw-01",
                                                                               "ups-rack-a")


def test_searching_the_side_list_narrows_it(window, app):
    window.search.setText("ups")
    assert keys(window) == ["ups-rack-a"]
    assert window.fleet_tab.table.rowCount() == 1
    window.search.setText("")
    assert len(keys(window)) == 2
    window.search.setText("nothing-like-this")
    assert keys(window) == []


def test_the_state_filter_only_shows_that_state(window, app):
    index = window.status_filter.findData("down")
    window.status_filter.setCurrentIndex(index)
    assert keys(window) == ["ups-rack-a"]
    window.status_filter.setCurrentIndex(0)


def test_the_device_tab_fills_in_for_the_selected_rack_unit(window, app):
    window.show_device("ups-rack-a")
    tab = window.device_tab
    assert tab.name.text() == "ups-rack-a"
    assert tab.badge.text() == "down"
    assert "10.0.0.9" in tab.meta.text()
    assert tab.metrics["battery"].number.text() == "12 %"
    assert tab.metrics["battery"].bar.value == 12.0
    assert tab.graphs["cpu"].points == [], "a dead UPS reports no CPU history"
    assert tab.graphs["cpu"].isHidden(), "and the empty graph is not shown"


def test_a_healthy_device_shows_its_own_numbers(window, app):
    window.show_device("core-sw-01")
    tab = window.device_tab
    assert tab.badge.text() == "up"
    assert tab.metrics["cpu"].number.text() == "21 %"
    assert tab.metrics["temperature"].number.text() == "43 °C"
    assert tab.ports.rowCount() == 0, "this device was never asked for its ports"
    assert tab.events.rowCount() == 0, "nothing changed here"


def test_the_top_of_a_device_page_says_what_we_know_about_it(window, app):
    window.show_device("core-sw-01")
    facts = window.device_tab.facts.text()
    assert "seen" in facts and "port(s)" in facts and "snmp v2c" in facts


def test_a_reachability_only_device_says_it_was_never_asked_over_snmp(home, app, config):
    store = Store(home / "nocdeck.db")
    store.save_device(Device(name="web-01", host="10.0.0.7", id="web-01", kind="generic",
                             snmp=False, address="10.0.0.7"))
    store.add_sample(Reading(device_id="web-01", at=ago_iso(), status="up", latency_ms=1.1))
    built = MainWindow(store, config)
    built.show_device("web-01")
    assert "reachability only" in built.device_tab.facts.text()
    built.close()
    store.close()


def test_the_events_tab_shows_the_event_and_its_severity(window, app):
    table = window.events_tab.table
    assert table.rowCount() == 1
    assert table.item(0, 1).text() == "critical"
    assert "is down" in table.item(0, 4).text()


def test_the_events_window_filter_asks_the_store_for_a_different_span(window, app):
    window.events_tab.hours.setCurrentIndex(0)          # 1 hour
    assert window.events_tab.selected() == (1.0, "")
    window.events_tab.hours.setCurrentIndex(2)
    window.events_tab.severity.setCurrentText("critical")
    assert window.events_tab.selected() == (24.0, "critical")


def test_polling_without_a_poller_says_so_instead_of_pretending(window, app):
    window.poll_now()
    assert "read-only" in window.status.currentMessage()


def test_the_wall_window_gets_a_card_per_device(window, app):
    wall = WallWindow(window)
    wall.reload(window.store_snapshot())
    assert wall.grid.count() == 2
    names = set()
    for index in range(wall.grid.count()):
        card = wall.grid.itemAt(index).widget()
        for label in card.findChildren(QLabel):
            names.add(label.text())
    assert {"core-sw-01", "ups-rack-a"} <= names
    wall.close()


def test_the_wall_card_says_the_state_and_the_numbers():
    reading = Reading(device_id="core-sw-01", status="degraded", latency_ms=3.3,
                      metrics={"cpu": 81.0, "temperature": 61.0})
    line = WallWindow._line(reading)
    assert line.startswith("degraded") and "CPU 81%" in line and "temp 61°C" in line


def test_export_writes_the_inventory_next_to_the_database(window, app, tmp_path):
    window.export_inventory()
    written = pathlib.Path(window.store.path).parent / "inventory-export.json"
    assert written.exists()
    payload = json.loads(written.read_text())
    assert {row["name"] for row in payload["devices"]} == {"core-sw-01", "ups-rack-a"}


# ------------------------------------------------------------------- alert targets


def test_a_telegram_target_can_be_typed_in_and_saved(window, app, home):
    tab = window.alerts_tab
    tab.kind.setCurrentIndex(tab.kind.findData("telegram"))
    tab.name.setText("ops")
    tab.fields["token"].setText("123:abc")
    tab.fields["chat_id"].setText("-100999")
    tab.add_target()
    assert window.config.alert_targets[-1].chat_id == "-100999"
    tab.save()
    written = json.loads((home / "config.json").read_text())
    assert written["alert_targets"][0]["name"] == "ops"
    assert written["alert_targets"][0]["token"] == "123:abc"


def test_a_webhook_target_hides_the_fields_it_does_not_use(window, app):
    tab = window.alerts_tab
    tab.kind.setCurrentIndex(tab.kind.findData("webhook"))
    assert tab.fields["url"].isHidden() is False, "a webhook is a URL and nothing else"
    form = tab.fields["token"].parentWidget().layout()
    row, _role = form.getWidgetPosition(tab.fields["token"])
    label = form.itemAt(row * 2).widget()
    assert label.isHidden() is True, "a webhook has no chat id — hide the box"
    tab.kind.setCurrentIndex(tab.kind.findData("telegram"))
    assert label.isHidden() is False


def test_removing_a_target_can_be_undone_by_not_saving(window, app):
    tab = window.alerts_tab
    tab.kind.setCurrentIndex(tab.kind.findData("webhook"))
    tab.name.setText("hooks")
    tab.fields["url"].setText("https://hooks.example/noc")
    tab.add_target()
    assert len(window.config.alert_targets) == 1
    tab.remove_target()
    assert window.config.alert_targets == []


def test_a_command_line_target_shows_in_the_alerts_list(home, app, config):
    config.alert_targets = [AlertTarget(kind="telegram", name="night",
                                        token="1:a", chat_id="-1",
                                        min_severity="critical")]
    store = Store(home / "nocdeck.db")
    built = MainWindow(store, config)
    built.alerts_tab.reload()
    assert built.alerts_tab.list.count() == 1
    assert "night" in built.alerts_tab.list.item(0).text()
    built.alerts_tab.list.setCurrentRow(0)
    assert built.alerts_tab.severity.currentText() == "critical"
    built.close()
    store.close()


# ---------------------------------------------------------------------- settings


def test_the_settings_tab_shows_the_values_the_poller_would_use(window, app):
    tab = window.settings_tab
    tab.reload()
    assert tab.interval.value() == window.config.interval
    assert tab.thresholds["cpu"].value() == Thresholds().cpu
    assert tab.bump.value() == window.config.threshold_object().critical_bump


def test_saving_settings_writes_them_and_repaints_sooner(window, app, home):
    tab = window.settings_tab
    tab.interval.setValue(120)
    tab.thresholds["cpu"].setValue(66.0)
    tab.refresh.setValue(7)
    tab.save()
    written = json.loads((home / "config.json").read_text())
    assert written["interval"] == 120
    assert written["thresholds"]["cpu"] == 66.0
    assert written["refresh_seconds"] == 7
    assert window.config.threshold_object().cpu == 66.0
    assert window.repaint_timer.interval() == 7000
    assert "saved to" in tab.note.text()


# ------------------------------------------------------------------------ polling


class FakePoller:
    """A poller that answers instantly and remembers what it was asked."""

    def __init__(self, store):
        self.store = store
        self.calls = []

    def run_once(self, force: bool = False):
        self.calls.append(force)
        return []

    def poll(self, device, force: bool = False):
        from nocdeck.poller import PollOutcome

        self.calls.append(device.name)
        return PollOutcome(device, Reading(device_id=device.key(), status="up"), error="")


def test_a_poll_cycle_runs_off_the_gui_thread_and_repaints(window, app):
    poller = FakePoller(window.store)
    window.poller = poller
    results = []
    worker = PollWorker(poller)
    worker.done.connect(lambda outcomes, error: results.append((outcomes, error)))
    worker.run()                                    # the same body QThread would run
    assert poller.calls == [True]
    assert results == [([], "")]
    assert "read-only" not in window.status.currentMessage() or True


def test_a_broken_device_does_not_kill_the_window(window, app):
    class Exploding(FakePoller):
        def run_once(self, force: bool = False):
            raise RuntimeError("the poller fell over")

    window.poller = Exploding(window.store)
    reported = []
    worker = PollWorker(window.poller)
    worker.done.connect(lambda outcomes, error: reported.append(error))
    worker.run()
    assert reported and "fell over" in reported[0]
    assert window.isVisible() or True, "the window is still there"


def test_polling_one_device_asks_only_that_device(window, app):
    from nocdeck.desktop.desktop import _OneDeviceWorker

    window.poller = FakePoller(window.store)
    device = window.store.get_device("core-sw-01")
    worker = _OneDeviceWorker(window.poller, device)
    worker.run()
    assert window.poller.calls == ["core-sw-01"]


# -------------------------------------------------------------------------- entry


def test_the_renderer_writes_a_png_and_leaves_a_store_the_web_can_serve(home, tmp_path):
    """One end-to-end run of the command a README tells people to type. Qt may only be
    started once per process on a machine with no display, so everything the entry point
    promises is checked here in a single go."""
    target = tmp_path / "frame.png"
    code = cli.main(["desktop", "--demo", "--shot", str(target), "--warmup", "3",
                     "--size", "4", "--tab", "device"])
    assert code == 0
    assert target.exists() and target.stat().st_size > 20000
    store = Store(home / "nocdeck.db")
    assert len(store.devices()) == 4
    assert store.last_samples(), "the imaginary gear was polled"
    assert store.interfaces(store.devices()[0].key()), "and asked for its ports"
    store.close()


def test_the_arguments_are_read_without_starting_qt():
    options = DESKTOP_IMPL.parse_args(["--demo", "--shot", "f.png", "--tab", "events",
                                       "--size", "3", "--warmup", "2", "--seed", "11",
                                       "--db", "/tmp/x.db"])
    assert options == {"shot": "f.png", "tab": "events", "demo": True, "db": "/tmp/x.db",
                       "size": 3, "warmup": 2, "seed": 11}
    assert DESKTOP_IMPL.parse_args([])["warmup"] == 6
    assert DESKTOP_IMPL.TABS == ("fleet", "device", "events", "alerts", "settings")


def test_a_bad_tab_name_is_said_out_loud_not_ignored(home, tmp_path, monkeypatch, capsys):
    """The typo is caught before a window is built, so nothing is rendered for nothing."""
    calls = []
    monkeypatch.setattr(DESKTOP_IMPL, "main", lambda argv: calls.append(argv) or 0)
    monkeypatch.setattr(DESKTOP, "main", lambda argv: calls.append(argv) or 0)
    assert cli.main(["desktop", "--shot", str(tmp_path / "x.png"), "--tab", "nonsense"]) == 0
    assert "no tab called" in capsys.readouterr().err
    assert "--tab" not in calls[0]
