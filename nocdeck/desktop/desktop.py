"""The desktop window — the same engine as the web dashboard, in a window.

Why both? Because a NOC has two moods. The web dashboard is for "show me from
anywhere, on any screen"; this is for "sit in front of it, keep it open all day,
and have it be the thing on the wall." They share every line of the pipeline —
the store, the poller, the thresholds, the alerts — so a device looks identical
in both, and there is only one place to fix a bug.

Run it:

    nocdeck desktop                 # your inventory, your database
    nocdeck desktop --demo          # imaginary estate, no network at all
    nocdeck desktop --demo --shot out.png   # render one frame and exit
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QColor, QFont, QKeySequence
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QDoubleSpinBox,
                             QFormLayout, QFrame, QGridLayout, QGroupBox, QHBoxLayout,
                             QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                             QMainWindow, QPushButton, QScrollArea, QSpinBox, QSplitter,
                             QStatusBar, QTableWidget, QTableWidgetItem, QTabWidget,
                             QToolBar, QVBoxLayout, QWidget)

from .. import __version__, alerts as AL, mibs
from . import TABS
from ..config import Config, db_path
from ..model import (AlertTarget, Device, Event, Reading, human_bps, human_bytes,
                     human_seconds, parse_iso, now_utc)
from ..poller import Poller
from ..store import Store
from .widgets import (BLUE, DEGRADED, DIM, DOWN, LINE, PANEL, TEXT, UNKNOWN, UP, Badge,
                      MetricRow, Sparkline, Tile, status_colour)

STYLESHEET = """
QWidget { background: %(ink)s; color: %(text)s; font-size: 12px; }
QMainWindow, QTabWidget::pane { border: none; }
QTabBar::tab { background: %(panel)s; padding: 6px 14px; border: 1px solid %(line)s;
               border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; }
QTabBar::tab:selected { background: %(line)s; color: white; }
QTableWidget, QListWidget { background: %(panel)s; alternate-background-color: %(ink)s;
                            gridline-color: %(line)s; border: 1px solid %(line)s; }
QTableWidget::item:selected, QListWidget::item:selected { background: %(blue)s;
                                                          color: #04121f; }
QHeaderView::section { background: %(line)s; padding: 4px 6px; border: none; color: %(dim)s; }
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox { background: %(panel)s;
               border: 1px solid %(line)s; border-radius: 4px; padding: 3px 6px; }
QPushButton { background: %(panel)s; border: 1px solid %(line)s; border-radius: 4px;
              padding: 5px 12px; }
QPushButton:hover { border-color: %(blue)s; }
QPushButton#primary { background: %(blue)s; color: #04121f; border: none; font-weight: 600; }
QGroupBox { border: 1px solid %(line)s; border-radius: 6px; margin-top: 10px;
            padding: 10px 8px 8px 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: %(dim)s; }
QLabel#h1 { font-size: 18px; font-weight: 600; }
QLabel#h2 { font-size: 13px; color: %(dim)s; text-transform: uppercase; letter-spacing: 1px; }
QLabel#tileValue { font-size: 20px; font-weight: 600; }
QLabel#tileLabel { color: %(text)s; }
QLabel#tileNote, QLabel#dim { color: %(dim)s; font-size: 11px; }
QLabel#mono { font-family: "DejaVu Sans Mono", monospace; }
QFrame#tile { background: %(panel)s; border: 1px solid %(line)s; border-radius: 6px; }
QFrame#panel { background: %(panel)s; border: 1px solid %(line)s; border-radius: 6px; }
QToolBar { background: %(panel)s; border-bottom: 1px solid %(line)s; spacing: 6px;
           padding: 4px; }
QStatusBar { background: %(panel)s; color: %(dim)s; }
QSplitter::handle { background: %(line)s; }
""" % {"ink": "#0d1117", "panel": PANEL, "line": LINE, "text": TEXT, "dim": DIM,
       "blue": BLUE}


def when_text(when: str, now: Optional[datetime] = None) -> str:
    """`34 s ago` / `12 min ago` — relative, because absolute times need mental maths."""
    moment = parse_iso(when)
    if not moment:
        return "never"
    seconds = ((now or now_utc()) - moment).total_seconds()
    if seconds < 0:
        return moment.strftime("%H:%M:%S")
    if seconds < 90:
        return "%.0f s ago" % seconds
    if seconds < 5400:
        return "%.0f min ago" % (seconds / 60.0)
    if seconds < 172800:
        return "%.1f h ago" % (seconds / 3600.0)
    return moment.strftime("%m-%d %H:%M")


# --------------------------------------------------------------------------- work


class PollWorker(QThread):
    """Polling happens here, never on the GUI thread — a device that times out at
    four seconds must not make the window stop repainting."""

    done = pyqtSignal(object, str)

    def __init__(self, poller: Poller, simulator=None, parent=None):
        super().__init__(parent)
        self.poller = poller
        self.simulator = simulator
        self.started_at = time.time()

    def run(self) -> None:                               # noqa: D102 — QThread's entry
        try:
            if self.simulator is not None:
                self.simulator.advance(60.0, elapsed=time.time() - self.started_at)
            outcomes = self.poller.run_once(force=True)
            self.done.emit(outcomes, "")
        except Exception as exc:                         # noqa: BLE001
            import traceback

            traceback.print_exc()
            self.done.emit([], str(exc))


class AlertWorker(QThread):
    """The test message. Network, therefore not on the GUI thread."""

    done = pyqtSignal(str, str)

    def __init__(self, target: AlertTarget, parent=None):
        super().__init__(parent)
        self.target = target

    def run(self) -> None:                               # noqa: D102
        try:
            detail = AL.test_target(self.target)
            self.done.emit(detail, "")
        except Exception as exc:                         # noqa: BLE001
            self.done.emit("", str(exc))


# ---------------------------------------------------------------------- the panes


class FleetTab(QWidget):
    """The one screen to leave open: every device, worst first."""

    COLUMNS = ("device", "address", "kind", "group", "status", "latency", "cpu", "temp",
               "up 24h", "ports down", "last seen")

    def __init__(self, window: "MainWindow"):
        super().__init__()
        self.window = window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        self.tiles: Dict[str, Tile] = {}
        tile_row = QHBoxLayout()
        for key, label, note in (("devices", "devices", "in the inventory"),
                                 ("up", "up", "answering"),
                                 ("degraded", "degraded", "over a warning line"),
                                 ("down", "down", "not answering"),
                                 ("latency", "avg latency", "across the fleet"),
                                 ("events", "events 24h", "warnings + critical"),
                                 ("samples", "readings", "stored, last 24 h")):
            tile = Tile(label, note, colour=status_colour(key) if key in
                        ("up", "degraded", "down") else "")
            self.tiles[key] = tile
            tile_row.addWidget(tile)
        tile_row.addStretch(1)
        layout.addLayout(tile_row)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSortingEnabled(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for column in range(1, len(self.COLUMNS)):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self._row_picked)
        self.table.doubleClicked.connect(self._row_activated)
        layout.addWidget(self.table, 1)

    def _row_picked(self) -> None:
        key = self.selected_key()
        if key:
            self.window.show_device(key)

    def _row_activated(self, _index) -> None:
        key = self.selected_key()
        if key:
            self.window.show_device(key)
            self.window.tabs.setCurrentIndex(1)

    def selected_key(self) -> str:
        rows = self.table.selectionModel().selectedRows() if self.table.selectionModel() else []
        if not rows:
            return ""
        item = self.table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else ""

    def select(self, key: str) -> None:
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item and item.data(Qt.ItemDataRole.UserRole) == key:
                self.table.selectRow(row)
                return

    def reload(self, rows: List[dict], fleet: Dict[str, object], events: int) -> None:
        counts = {"up": 0, "degraded": 0, "down": 0, "unknown": 0}
        for row in rows:
            counts[row["reading"].status] = counts.get(row["reading"].status, 0) + 1
        self.tiles["devices"].set_value(str(len(rows)))
        self.tiles["up"].set_value(str(counts["up"]), UP)
        self.tiles["degraded"].set_value(str(counts["degraded"]), DEGRADED)
        self.tiles["down"].set_value(str(counts["down"]), DOWN)
        self.tiles["latency"].set_value("%.0f ms" % fleet["latency"] if fleet["latency"]
                                        else "—")
        self.tiles["events"].set_value(str(events), DOWN if events else "")
        self.tiles["samples"].set_value(str(fleet["samples"]))

        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            device: Device = row["device"]
            reading: Reading = row["reading"]
            limits = device.limits()
            cells = [
                (device.name, status_colour(reading.status), device.key()),
                (device.address or device.host, "", None),
                (device.kind, "", None),
                (device.group, "", None),
                (reading.status, status_colour(reading.status), None),
                ("%.0f ms" % reading.latency_ms if reading.latency_ms is not None else "—",
                 "", None),
                (self._number(reading.metric("cpu")), self._metric_colour(limits, "cpu",
                                                                          reading), None),
                (self._number(reading.metric("temperature"), "°C"),
                 self._metric_colour(limits, "temperature", reading), None),
                ("%.1f%%" % float(row["uptime"]["percent"]), "", None),
                (str(len(row["ports_down"])), DOWN if row["ports_down"] else "", None),
                (when_text(reading.at), "", None),
            ]
            for column, (text, colour, user_data) in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if colour:
                    item.setForeground(QColor(colour))
                if user_data:
                    item.setData(Qt.ItemDataRole.UserRole, user_data)
                if column == 0:
                    item.setFont(QFont(item.font().family(), item.font().pointSize(),
                                       QFont.Weight.DemiBold))
                self.table.setItem(index, column, item)

    @staticmethod
    def _number(value: Optional[float], unit: str = "") -> str:
        if value is None:
            return "—"
        return (("%.4g" % value) + ("" if unit == "%" else " " + unit))

    @staticmethod
    def _metric_colour(limits, metric: str, reading: Reading) -> str:
        value = reading.metric(metric)
        verdict = limits.trouble(metric, value) if value is not None else None
        return {"critical": DOWN, "warning": DEGRADED}.get(verdict or "", "")


class DeviceTab(QWidget):
    """One device, in as much detail as the gear was willing to give."""

    def __init__(self, window: "MainWindow"):
        super().__init__()
        self.window = window
        self.device_key = ""
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        outer.addWidget(self.scroll)

        self.body = QWidget()
        self.scroll.setWidget(self.body)
        layout = QVBoxLayout(self.body)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(10)

        head = QHBoxLayout()
        self.name = QLabel("—")
        self.name.setObjectName("h1")
        self.badge = Badge()
        self.meta = QLabel("")
        self.meta.setObjectName("dim")
        head.addWidget(self.name)
        head.addWidget(self.badge)
        head.addStretch(1)
        self.poll_button = QPushButton("poll this device now")
        self.poll_button.clicked.connect(lambda: self.window.poll_now(self.device_key))
        head.addWidget(self.poll_button)
        layout.addLayout(head)

        self.facts = QLabel("")
        self.facts.setObjectName("dim")
        self.facts.setWordWrap(True)
        layout.addWidget(self.facts)

        self.metrics_box = QGroupBox("health")
        self.metrics_layout = QVBoxLayout(self.metrics_box)
        self.metrics: Dict[str, MetricRow] = {}
        for key, label, unit, low_is_bad in (
                ("cpu", "CPU", "%", False), ("memory", "RAM", "%", False),
                ("temperature", "temperature", "°C", False), ("disk", "disk", "%", False),
                ("battery", "battery", "%", True), ("optical", "optical", "dBm", True),
                ("fan", "fan", "rpm", False), ("voltage", "voltage", "V", False),
                ("power", "power", "W", False), ("runtime", "runtime", "min", True)):
            row = MetricRow(label, unit=unit, low_is_bad=low_is_bad)
            self.metrics[key] = row
            self.metrics_layout.addWidget(row)
            row.setVisible(False)
        layout.addWidget(self.metrics_box)

        self.graphs_box = QGroupBox("history — last 24 h")
        graphs = QGridLayout(self.graphs_box)
        self.graphs: Dict[str, Sparkline] = {}
        for index, (key, colour) in enumerate((("cpu", BLUE), ("memory", "#a78bfa"),
                                               ("latency_ms", UP), ("temperature", DEGRADED))):
            label = QLabel(key.replace("_ms", " (ms)"))
            label.setObjectName("dim")
            graph = Sparkline(colour=colour)
            self.graphs[key] = graph
            graphs.addWidget(label, (index // 2) * 2, index % 2)
            graphs.addWidget(graph, (index // 2) * 2 + 1, index % 2)
        layout.addWidget(self.graphs_box)

        self.ports_box = QGroupBox("ports")
        ports = QVBoxLayout(self.ports_box)
        self.ports = QTableWidget(0, 8)
        self.ports.setHorizontalHeaderLabels(("port", "name", "type", "state", "speed",
                                              "in", "out", "errors"))
        self.ports.verticalHeader().setVisible(False)
        self.ports.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.ports.setAlternatingRowColors(True)
        self.ports.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.ports.setMaximumHeight(260)
        ports.addWidget(self.ports)
        layout.addWidget(self.ports_box)

        self.events_box = QGroupBox("what changed here")
        events = QVBoxLayout(self.events_box)
        self.events = QTableWidget(0, 4)
        self.events.setHorizontalHeaderLabels(("when", "severity", "kind", "what"))
        self.events.verticalHeader().setVisible(False)
        self.events.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.events.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.events.setMaximumHeight(200)
        events.addWidget(self.events)
        layout.addWidget(self.events_box)
        layout.addStretch(1)

    def hide_all_metrics(self) -> None:
        for row in self.metrics.values():
            row.setVisible(False)

    def load(self, device: Device, reading: Reading, interfaces, events, history: Dict[str, List]
             ) -> None:
        self.device_key = device.key()
        self.name.setText(device.name)
        self.badge.set_status(reading.status)
        self.meta.setText("%s · %s · %s%s" % (
            device.address or device.host, device.kind,
            device.vendor or "vendor unknown",
            (" · " + device.location) if device.location else ""))
        bits = []
        if reading.at:
            bits.append("seen %s" % when_text(reading.at))
        if reading.uptime_seconds():
            bits.append("uptime %s" % human_seconds(reading.uptime_seconds()))
        if reading.latency_ms is not None:
            bits.append("latency %.0f ms" % reading.latency_ms)
        if reading.loss is not None:
            bits.append("loss %.0f%%" % reading.loss)
        bits.append("%d port(s)" % len(interfaces))
        if device.snmp:
            bits.append("snmp v%s community %s" % (device.version, "set" if device.community
                                                   else "unset"))
        else:
            bits.append("reachability only")
        for key, value in (reading.facts or {}).items():
            if key in ("descr", "object_id", "location", "contact", "interfaces",
                       "serial", "model", "firmware") and value:
                bits.append("%s %s" % (key, str(value)[:60]))
        self.facts.setText(" · ".join(bits))

        limits = device.limits()
        self.hide_all_metrics()
        for key, row in self.metrics.items():
            value = reading.metric(key)
            if value is None:
                continue
            pair = limits.limits(key) or (100.0, 100.0)
            row.bar.warn, row.bar.crit = pair[0], pair[1]
            row.bar.low_is_bad = limits.direction(key) == "low"
            row.set_value(value)
            row.setVisible(True)

        for key, graph in self.graphs.items():
            points = [value for _at, value in history.get(key, []) if value is not None]
            pair = limits.limits(key) or (None, None)
            graph.warn, graph.crit = pair[0], pair[1]
            graph.set_points(points)
            graph.setVisible(bool(points))

        self.ports.setRowCount(len(interfaces))
        for index, port in enumerate(interfaces):
            colour = UP if port.up() else (DOWN if port.admin == "up" else UNKNOWN)
            cells = ((port.name, ""), (port.label(), ""), (port.type or "—", ""),
                     (port.oper or "?", colour),
                     (("%g M" % port.speed_mbps) if port.speed_mbps else "—", ""),
                     (human_bps(port.in_bps), ""), (human_bps(port.out_bps), ""),
                     ("%d/%d" % (port.in_errors, port.out_errors),
                      DOWN if (port.in_errors or port.out_errors) else ""))
            for column, (text, cell_colour) in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if cell_colour:
                    item.setForeground(QColor(cell_colour))
                self.ports.setItem(index, column, item)

        self.events.setRowCount(len(events))
        for index, event in enumerate(events):
            cells = ((when_text(event.at), ""), (event.severity, status_colour(
                {"critical": "down", "warning": "degraded"}.get(event.severity, "up"))),
                (event.kind, ""), (event.message, ""))
            for column, (text, cell_colour) in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if cell_colour:
                    item.setForeground(QColor(cell_colour))
                self.events.setItem(index, column, item)


class EventsTab(QWidget):
    """Everything that changed, newest first — the audit trail, not a live view."""

    def __init__(self, window: "MainWindow"):
        super().__init__()
        self.window = window
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("window:"))
        self.hours = QComboBox()
        for label, value in (("1 h", 1), ("6 h", 6), ("24 h", 24), ("7 days", 168),
                             ("30 days", 720)):
            self.hours.addItem(label, value)
        self.hours.setCurrentIndex(2)
        self.hours.currentIndexChanged.connect(lambda _i: self.window.reload())
        controls.addWidget(self.hours)
        controls.addWidget(QLabel("severity:"))
        self.severity = QComboBox()
        for label in ("all", "critical", "warning", "info"):
            self.severity.addItem(label)
        self.severity.currentIndexChanged.connect(lambda _i: self.window.reload())
        controls.addWidget(self.severity)
        controls.addStretch(1)
        self.count = QLabel("")
        self.count.setObjectName("dim")
        controls.addWidget(self.count)
        layout.addLayout(controls)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(("when", "severity", "kind", "device", "what"))
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table, 1)

    def selected(self) -> Tuple[float, str]:
        return float(self.hours.currentData() or 24), ("" if self.severity.currentText() == "all"
                                                       else self.severity.currentText())

    def reload(self, events: List[Event], names: Dict[str, str]) -> None:
        self.count.setText("%d event(s)" % len(events))
        self.table.setRowCount(len(events))
        for index, event in enumerate(events):
            colour = {"critical": DOWN, "warning": DEGRADED, "info": UP}.get(event.severity, DIM)
            cells = ((when_text(event.at), ""), (event.severity, colour), (event.kind, ""),
                     (names.get(event.device_id, event.device_id), ""), (event.message, ""))
            for column, (text, cell_colour) in enumerate(cells):
                item = QTableWidgetItem(str(text))
                if cell_colour:
                    item.setForeground(QColor(cell_colour))
                self.table.setItem(index, column, item)


class AlertsTab(QWidget):
    """Where the alerts go, and a button that proves it works."""

    KINDS = (("telegram", "Telegram", ("token", "chat_id")),
             ("email", "email (SMTP)", ("server", "port", "username", "password", "to")),
             ("webhook", "webhook", ("url",)),
             ("gotify", "gotify", ("url", "token")),
             ("ntfy", "ntfy", ("url", "token")),
             ("slack", "Slack", ("url",)),
             ("discord", "Discord", ("url",)))

    def __init__(self, window: "MainWindow"):
        super().__init__()
        self.window = window
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        left = QVBoxLayout()
        left.addWidget(QLabel("targets"))
        self.list = QListWidget()
        self.list.currentRowChanged.connect(self._picked)
        left.addWidget(self.list, 1)
        buttons = QHBoxLayout()
        add = QPushButton("add")
        add.clicked.connect(self.add_target)
        remove = QPushButton("remove")
        remove.clicked.connect(self.remove_target)
        buttons.addWidget(add)
        buttons.addWidget(remove)
        left.addLayout(buttons)
        holder = QWidget()
        holder.setLayout(left)
        holder.setMaximumWidth(320)
        layout.addWidget(holder)

        right = QVBoxLayout()
        box = QGroupBox("the selected target")
        form = QFormLayout(box)
        self.kind = QComboBox()
        for key, label, _fields in self.KINDS:
            self.kind.addItem(label, key)
        self.kind.currentIndexChanged.connect(self._kind_changed)
        form.addRow("kind", self.kind)
        self.name = QLineEdit()
        form.addRow("name", self.name)
        self.severity = QComboBox()
        for label in ("info", "warning", "critical"):
            self.severity.addItem(label)
        self.severity.setCurrentText("warning")
        form.addRow("tell me about", self.severity)
        self.quiet = QLineEdit()
        self.quiet.setPlaceholderText("23:00-07:00 — warnings wait, criticals do not")
        form.addRow("quiet hours", self.quiet)
        self.fields: Dict[str, QLineEdit] = {}
        for field in ("token", "chat_id", "server", "port", "username", "password", "to",
                      "url"):
            editor = QLineEdit()
            if field in ("password", "token"):
                editor.setEchoMode(QLineEdit.EchoMode.Password)
            self.fields[field] = editor
            form.addRow(field, editor)
        right.addWidget(box)

        actions = QHBoxLayout()
        save = QPushButton("save to config")
        save.clicked.connect(self.save)
        test = QPushButton("send a test message")
        test.setObjectName("primary")
        test.clicked.connect(self.send_test)
        actions.addWidget(save)
        actions.addWidget(test)
        actions.addStretch(1)
        right.addLayout(actions)
        self.note = QLabel("")
        self.note.setObjectName("dim")
        self.note.setWordWrap(True)
        right.addWidget(self.note)
        right.addStretch(1)
        layout.addLayout(right, 1)
        self._kind_changed()

    def _kind_changed(self) -> None:
        """Hide the fields this kind of target has no use for — a Discord webhook has
        no chat id, and an empty box invites a wrong answer."""
        wanted = dict((key, fields) for key, _label, fields in self.KINDS)[
            self.kind.currentData() or "telegram"]
        form = self.fields["token"].parentWidget().layout()
        for field, editor in self.fields.items():
            row, _role = form.getWidgetPosition(editor)
            item = form.itemAt(row, QFormLayout.ItemRole.LabelRole)
            label = item.widget() if item else None
            if label is not None:
                label.setVisible(field in wanted)
            editor.setVisible(field in wanted)

    def reload(self) -> None:
        self.list.clear()
        for target in self.window.config.alert_targets:
            note = target.chat_id or target.url or (", ".join(target.to or []) or target.server)
            item = QListWidgetItem("%s · %s%s" % (target.name, target.kind,
                                                  (" → " + str(note)) if note else ""))
            item.setData(Qt.ItemDataRole.UserRole, target)
            self.list.addItem(item)
        if self.list.count() and self.list.currentRow() < 0:
            self.list.setCurrentRow(0)

    def _picked(self, row: int) -> None:
        if row < 0:
            return
        target: AlertTarget = self.list.item(row).data(Qt.ItemDataRole.UserRole)
        index = self.kind.findData(target.kind)
        if index >= 0:
            self.kind.setCurrentIndex(index)
        self.name.setText(target.name)
        self.severity.setCurrentText(target.min_severity)
        self.quiet.setText(target.quiet_hours)
        self.fields["token"].setText(target.token)
        self.fields["chat_id"].setText(target.chat_id)
        self.fields["server"].setText(target.server)
        self.fields["port"].setText(str(target.port or ""))
        self.fields["username"].setText(target.username)
        self.fields["password"].setText(target.password)
        self.fields["to"].setText(", ".join(target.to or []))
        self.fields["url"].setText(target.url)
        self.note.setText("")

    def current(self) -> Optional[AlertTarget]:
        row = self.list.currentRow()
        if row < 0:
            return None
        return self.list.item(row).data(Qt.ItemDataRole.UserRole)

    def form_target(self, existing: Optional[AlertTarget] = None) -> AlertTarget:
        target = existing or AlertTarget(kind=self.kind.currentData() or "telegram")
        target.kind = self.kind.currentData() or "telegram"
        target.name = self.name.text().strip() or target.kind
        target.min_severity = self.severity.currentText()
        target.quiet_hours = self.quiet.text().strip()
        target.token = self.fields["token"].text().strip()
        target.chat_id = self.fields["chat_id"].text().strip()
        target.server = self.fields["server"].text().strip()
        try:
            target.port = int(self.fields["port"].text().strip() or 0)
        except ValueError:
            target.port = 0
        target.username = self.fields["username"].text().strip()
        target.password = self.fields["password"].text()
        target.to = [part.strip() for part in self.fields["to"].text().split(",") if part.strip()]
        target.url = self.fields["url"].text().strip()
        return target

    def add_target(self) -> None:
        target = self.form_target()
        self.window.config.alert_targets.append(target)
        self.reload()
        self.list.setCurrentRow(self.list.count() - 1)
        self.note.setText("added — press “save to config” to keep it")

    def remove_target(self) -> None:
        row = self.list.currentRow()
        if row < 0:
            return
        del self.window.config.alert_targets[row]
        self.reload()
        self.note.setText("removed — press “save to config” to keep it")

    def save(self) -> None:
        row = self.list.currentRow()
        if row >= 0:
            self.window.config.alert_targets[row] = self.form_target(self.current())
            self.reload()
        path = self.window.config.save()
        self.note.setText("saved to %s" % path)
        self.window.status.showMessage("alert targets saved to %s" % path, 6000)

    def send_test(self) -> None:
        target = self.form_target(self.current())
        self.note.setText("sending…")
        self.worker = AlertWorker(target, self)
        self.worker.done.connect(self._tested)
        self.worker.start()

    def _tested(self, detail: str, error: str) -> None:
        self.note.setText("sent · %s" % detail if not error else "failed · %s" % error)
        self.window.status.showMessage(self.note.text(), 8000)


class SettingsTab(QWidget):
    """The knobs, with the ones that are easy to get wrong explained in place."""

    THRESHOLDS = (("cpu", "CPU %"), ("memory", "RAM %"), ("temperature", "temperature °C"),
                  ("disk", "disk %"), ("battery", "battery % (low is bad)"),
                  ("optical_dbm", "optical dBm (low is bad)"),
                  ("latency_ms", "latency ms"), ("loss", "packet loss %"),
                  ("runtime_min", "runtime min (low is bad)"))

    def __init__(self, window: "MainWindow"):
        super().__init__()
        self.window = window
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        columns = QHBoxLayout()

        poll_box = QGroupBox("polling")
        poll_form = QFormLayout(poll_box)
        self.interval = QSpinBox()
        self.interval.setRange(5, 86400)
        self.interval.setSuffix(" s")
        poll_form.addRow("every", self.interval)
        self.workers = QSpinBox()
        self.workers.setRange(1, 64)
        poll_form.addRow("in parallel", self.workers)
        self.timeout = QDoubleSpinBox()
        self.timeout.setRange(0.2, 60.0)
        self.timeout.setSuffix(" s")
        poll_form.addRow("SNMP timeout", self.timeout)
        self.retries = QSpinBox()
        self.retries.setRange(0, 10)
        poll_form.addRow("retries", self.retries)
        self.refresh = QSpinBox()
        self.refresh.setRange(1, 600)
        self.refresh.setSuffix(" s")
        poll_form.addRow("repaint the window", self.refresh)
        columns.addWidget(poll_box, 1)

        net_box = QGroupBox("dashboard + networks")
        net_form = QFormLayout(net_box)
        self.bind = QLineEdit()
        net_form.addRow("web bind", self.bind)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        net_form.addRow("web port", self.port)
        self.communities = QLineEdit()
        self.communities.setPlaceholderText("public, private")
        net_form.addRow("SNMP communities", self.communities)
        self.failures = QSpinBox()
        self.failures.setRange(1, 20)
        net_form.addRow("failures → down", self.failures)
        self.successes = QSpinBox()
        self.successes.setRange(1, 20)
        net_form.addRow("successes → up", self.successes)
        self.title = QLineEdit()
        net_form.addRow("dashboard title", self.title)
        columns.addWidget(net_box, 1)
        outer.addLayout(columns)

        alert_box = QGroupBox("when to shout")
        alert_form = QFormLayout(alert_box)
        self.digest_after = QSpinBox()
        self.digest_after.setRange(1, 100)
        alert_form.addRow("digest a storm of", self.digest_after)
        self.max_per_run = QSpinBox()
        self.max_per_run.setRange(1, 200)
        alert_form.addRow("most messages per cycle", self.max_per_run)
        self.repeat = QSpinBox()
        self.repeat.setRange(1, 10080)
        self.repeat.setSuffix(" min")
        alert_form.addRow("repeat an open problem every", self.repeat)
        outer.addWidget(alert_box)

        threshold_box = QGroupBox("warning lines — each one gets a critical line "
                                  "`critical bump` further out")
        threshold_form = QFormLayout(threshold_box)
        self.thresholds: Dict[str, QDoubleSpinBox] = {}
        for key, label in self.THRESHOLDS:
            editor = QDoubleSpinBox()
            editor.setRange(-1000.0, 100000.0)
            editor.setDecimals(1)
            self.thresholds[key] = editor
            threshold_form.addRow(label, editor)
        self.bump = QDoubleSpinBox()
        self.bump.setRange(0.0, 1000.0)
        self.bump.setDecimals(1)
        threshold_form.addRow("critical bump", self.bump)
        outer.addWidget(threshold_box)

        buttons = QHBoxLayout()
        save = QPushButton("save configuration")
        save.setObjectName("primary")
        save.clicked.connect(self.save)
        revert = QPushButton("reload from disk")
        revert.clicked.connect(self.reload)
        buttons.addWidget(save)
        buttons.addWidget(revert)
        buttons.addStretch(1)
        outer.addLayout(buttons)
        self.note = QLabel("")
        self.note.setObjectName("dim")
        self.note.setWordWrap(True)
        outer.addWidget(self.note)
        outer.addStretch(1)

    def reload(self) -> None:
        config = self.window.config
        self.interval.setValue(max(5, int(config.interval)))
        self.workers.setValue(int(config.workers))
        self.timeout.setValue(float(config.snmp_timeout))
        self.retries.setValue(int(config.snmp_retries))
        self.refresh.setValue(int(config.refresh_seconds))
        self.bind.setText(config.bind)
        self.port.setValue(int(config.port))
        self.communities.setText(", ".join(config.communities))
        self.failures.setValue(int(config.failures_to_down))
        self.successes.setValue(int(config.successes_to_up))
        self.title.setText(config.title)
        self.digest_after.setValue(int(config.alert_digest_after))
        self.max_per_run.setValue(int(config.alert_max_per_run))
        self.repeat.setValue(int(config.alert_repeat_minutes))
        # `config.thresholds` is the raw overlay; the threshold object is that overlay
        # merged over the built-in defaults, which is what the poller actually uses.
        limits = config.threshold_object()
        for key, _label in self.THRESHOLDS:
            value = getattr(limits, key, None)
            self.thresholds[key].setValue(float(value if value is not None else 0.0))
        self.bump.setValue(float(limits.critical_bump))
        self.note.setText("")

    def save(self) -> None:
        config = self.window.config
        config.interval = self.interval.value()
        config.workers = self.workers.value()
        config.snmp_timeout = self.timeout.value()
        config.snmp_retries = self.retries.value()
        config.refresh_seconds = self.refresh.value()
        config.bind = self.bind.text().strip() or "0.0.0.0"
        config.port = self.port.value()
        config.communities = [part.strip() for part in self.communities.text().split(",")
                              if part.strip()] or ["public"]
        config.failures_to_down = self.failures.value()
        config.successes_to_up = self.successes.value()
        config.title = self.title.text().strip() or "nocdeck"
        config.alert_digest_after = self.digest_after.value()
        config.alert_max_per_run = self.max_per_run.value()
        config.alert_repeat_minutes = self.repeat.value()
        for key, _label in self.THRESHOLDS:
            config.thresholds[key] = self.thresholds[key].value()
        config.thresholds["critical_bump"] = self.bump.value()
        path = config.save()
        self.note.setText("saved to %s · new values apply to the next poll" % path)
        self.window.status.showMessage("settings saved", 5000)
        self.window.apply_settings()


class WallWindow(QWidget):
    """The screen on the wall: big, dark, no controls, one card per device."""

    def __init__(self, window: "MainWindow"):
        super().__init__(None, Qt.WindowType.Window)
        self.window = window
        self.setWindowTitle("nocdeck — wall")
        self.grid = QGridLayout(self)
        self.grid.setContentsMargins(14, 14, 14, 14)
        self.grid.setSpacing(10)
        self.cards: Dict[str, Tuple[QLabel, QLabel, QLabel]] = {}

    def reload(self, rows: List[dict]) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.cards.clear()
        columns = 4
        for index, row in enumerate(rows):
            device: Device = row["device"]
            reading: Reading = row["reading"]
            card = QFrame()
            card.setObjectName("tile")
            layout = QVBoxLayout(card)
            name = QLabel(device.name)
            name.setObjectName("h1")
            address = QLabel(device.address or device.host)
            address.setObjectName("dim")
            state = QLabel(self._line(reading))
            state.setObjectName("h1")
            state.setStyleSheet("color: %s;" % status_colour(reading.status))
            layout.addWidget(name)
            layout.addWidget(address)
            layout.addWidget(state)
            self.grid.addWidget(card, index // columns, index % columns)

    @staticmethod
    def _line(reading: Reading) -> str:
        bits = [reading.status]
        for key, unit in (("cpu", "%"), ("temperature", "°C"), ("memory", "%")):
            value = reading.metric(key)
            if value is None:
                continue
            label = "temp" if key == "temperature" else key.upper()
            bits.append("%s %s%s" % (label, ("%.4g" % value), unit))
        if reading.latency_ms is not None:
            bits.append("%.0f ms" % reading.latency_ms)
        return " · ".join(bits)


# ------------------------------------------------------------------------ window


class MainWindow(QMainWindow):
    """One window over the store: fleet, one device, events, alerts, settings."""

    def __init__(self, store: Store, config: Config, poller: Optional[Poller] = None,
                 simulator=None, parent=None):
        super().__init__(parent)
        self.store = store
        self.config = config
        self.poller = poller
        self.simulator = simulator
        self.worker: Optional[PollWorker] = None
        self.wall: Optional[WallWindow] = None
        self.setWindowTitle("nocdeck %s — %s" % (__version__, config.title))
        self.resize(1280, 820)
        self.setStyleSheet(STYLESHEET)

        self.toolbar = QToolBar("main")
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)
        self.poll_action = QAction("poll now", self)
        self.poll_action.setShortcut(QKeySequence("F5"))
        self.poll_action.triggered.connect(lambda: self.poll_now())
        self.auto_action = QAction("auto-poll", self)
        self.auto_action.setCheckable(True)
        self.auto_action.setChecked(poller is not None)
        self.auto_action.toggled.connect(self._auto_toggled)
        self.wall_action = QAction("wall", self)
        self.wall_action.setCheckable(True)
        self.wall_action.toggled.connect(self._wall_toggled)
        self.export_action = QAction("export inventory", self)
        self.export_action.triggered.connect(self.export_inventory)
        self.reload_action = QAction("reload", self)
        self.reload_action.setShortcut(QKeySequence("F6"))
        self.reload_action.triggered.connect(lambda: self.reload())
        self.about_action = QAction("version", self)
        self.about_action.triggered.connect(self.about)
        for action in (self.poll_action, self.auto_action, self.reload_action):
            self.toolbar.addAction(action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.wall_action)
        self.toolbar.addAction(self.export_action)
        self.toolbar.addAction(self.about_action)

        self.status = QStatusBar()
        self.setStatusBar(self.status)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.setCentralWidget(splitter)

        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(8, 8, 4, 8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("filter by name, address, tag…")
        self.search.textChanged.connect(lambda _t: self.reload())
        side_layout.addWidget(self.search)
        filters = QHBoxLayout()
        self.group_filter = QComboBox()
        self.kind_filter = QComboBox()
        self.status_filter = QComboBox()
        for combo, values, label in ((self.group_filter, [], "all groups"),
                                     (self.kind_filter, [], "all kinds"),
                                     (self.status_filter,
                                      ["up", "degraded", "down", "unknown"],
                                      "any state")):
            combo.addItem(label, "")
            for value in values:
                combo.addItem(value, value)
            combo.currentIndexChanged.connect(lambda _i: self.reload())
            filters.addWidget(combo)
        side_layout.addLayout(filters)
        self.device_list = QListWidget()
        self.device_list.currentRowChanged.connect(self._list_picked)
        side_layout.addWidget(self.device_list, 1)
        self.side_note = QLabel("")
        self.side_note.setObjectName("dim")
        self.side_note.setWordWrap(True)
        side_layout.addWidget(self.side_note)
        side.setMinimumWidth(240)
        side.setMaximumWidth(360)
        splitter.addWidget(side)

        self.tabs = QTabWidget()
        self.fleet_tab = FleetTab(self)
        self.device_tab = DeviceTab(self)
        self.events_tab = EventsTab(self)
        self.alerts_tab = AlertsTab(self)
        self.settings_tab = SettingsTab(self)
        for widget, label in ((self.fleet_tab, "fleet"), (self.device_tab, "device"),
                              (self.events_tab, "events"), (self.alerts_tab, "alerts"),
                              (self.settings_tab, "settings")):
            self.tabs.addTab(widget, label)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 1000])

        self.repaint_timer = QTimer(self)
        self.repaint_timer.timeout.connect(self.refresh)
        self.repaint_timer.start(max(2, int(config.refresh_seconds)) * 1000)
        self.tick_timer = QTimer(self)
        self.tick_timer.timeout.connect(self._tick)
        self.tick_timer.start(1000)

        self.settings_tab.reload()
        self.alerts_tab.reload()
        self.reload()
        if poller is not None and self.auto_action.isChecked():
            QTimer.singleShot(400, lambda: self.poll_now())

    # ------------------------------------------------------------------ plumbing
    def refresh(self) -> None:
        """Reload from a timer, and never let a bad cycle end the window."""
        try:
            self.reload()
        except Exception as exc:                          # noqa: BLE001
            import traceback

            traceback.print_exc()
            self.status.showMessage("refresh failed: %s" % exc, 10000)

    def apply_settings(self) -> None:
        self.repaint_timer.start(max(2, int(self.config.refresh_seconds)) * 1000)

    def _tick(self) -> None:
        """Once a second: the clock in the status bar, and nothing more.

        A timer callback is the worst place for an exception: PyQt6 turns an unhandled
        one into `qFatal`, so a bad number would take the window with it. The status bar
        is the least important thing on screen, which is exactly why it is not allowed
        to be the last thing on it.
        """
        if self.worker is not None and self.worker.isRunning():
            self.status.showMessage("polling…")
            return
        try:
            fleet = self.store.fleet(hours=24)
            stamp = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
            self.status.showMessage("%s · %d device(s) · %d up / %d degraded / %d down · "
                                    "%d reading(s) 24 h · db %s"
                                    % (stamp, fleet["devices"], fleet["up"],
                                       fleet["degraded"], fleet["down"], fleet["samples"],
                                       human_bytes(self.store.size())))
        except Exception as exc:                          # noqa: BLE001
            self.status.showMessage("the status bar could not read the database: %s" % exc)

    def _auto_toggled(self, checked: bool) -> None:
        if checked:
            self.poll_now()
        self.status.showMessage("auto-poll %s" % ("on" if checked else "off"), 4000)

    def _wall_toggled(self, checked: bool) -> None:
        if checked:
            self.wall = WallWindow(self)
            self.wall.reload(self.store_snapshot())
            self.wall.showFullScreen()
        elif self.wall is not None:
            self.wall.close()
            self.wall = None

    def _list_picked(self, row: int) -> None:
        if row < 0:
            return
        key = self.device_list.item(row).data(Qt.ItemDataRole.UserRole)
        self.fleet_tab.select(key)
        self.show_device(key)

    def selected_key(self) -> str:
        return self.current_key

    def closeEvent(self, event) -> None:                 # noqa: N802 — Qt's spelling
        """Stop the clocks before the store goes away.

        A timer that fires into a closed database is a crash on the way out, which
        is the worst kind: it looks like the tool broke when it was only leaving.
        """
        self.repaint_timer.stop()
        self.tick_timer.stop()
        if self.worker is not None and self.worker.isRunning():
            self.worker.wait(4000)
        if self.wall is not None:
            self.wall.close()
            self.wall = None
        super().closeEvent(event)

    # ------------------------------------------------------------------- reading
    def store_snapshot(self) -> List[dict]:
        from ..web import Dashboard

        dashboard = Dashboard(self.store, self.config, self.poller)
        query = self.search.text().strip()
        rows = dashboard.snapshot(query, self.group_filter.currentData() or "",
                                  self.kind_filter.currentData() or "",
                                  self.status_filter.currentData() or "")
        for row in rows:
            row["ports_down"] = [port for port in self.store.interfaces(row["device"].key())
                                 if port.oper == "down" and port.admin == "up"]
        return rows

    def poll_now(self, key: str = "") -> None:
        if self.poller is None:
            self.status.showMessage("no poller attached — this window is read-only", 6000)
            return
        if self.worker is not None and self.worker.isRunning():
            self.status.showMessage("a poll is already running", 4000)
            return
        if key:
            device = self.store.get_device(key)
            if device is None:
                return
            self.worker = _OneDeviceWorker(self.poller, device, self.simulator, self)
        else:
            self.worker = PollWorker(self.poller, self.simulator, self)
        self.worker.done.connect(self._polled)
        self.worker.start()
        self.status.showMessage("polling…")

    def _polled(self, outcomes, error: str) -> None:
        if error:
            self.status.showMessage("poll failed: %s" % error, 8000)
        elif outcomes:
            bad = [outcome for outcome in outcomes if outcome.reading.status != "up"]
            self.status.showMessage("polled %d device(s) · %d not up" % (len(outcomes), len(bad)),
                                    8000)
        self.reload()

    def reload(self) -> None:
        """Everything on screen, from the store. Called after every poll and on a timer."""
        current = getattr(self, "current_key", "")
        rows = self.store_snapshot()

        groups = sorted({device.group for device in self.store.devices() if device.group})
        kinds = sorted({device.kind for device in self.store.devices() if device.kind})
        for combo, values in ((self.group_filter, groups), (self.kind_filter, kinds)):
            if [combo.itemData(i) for i in range(combo.count())] != [""] + values:
                chosen = combo.currentData()
                combo.blockSignals(True)
                combo.clear()
                combo.addItem("all groups" if combo is self.group_filter else "all kinds", "")
                for value in values:
                    combo.addItem(value, value)
                combo.setCurrentIndex(max(0, combo.findData(chosen)))
                combo.blockSignals(False)

        self.device_list.blockSignals(True)
        self.device_list.clear()
        for row in rows:
            device: Device = row["device"]
            reading: Reading = row["reading"]
            item = QListWidgetItem("%s  %s\n%s · %s%s"
                                   % (_bullet(reading.status), device.name,
                                      device.address or device.host, reading.status,
                                      (" · %.0f ms" % reading.latency_ms)
                                      if reading.latency_ms is not None else ""))
            item.setData(Qt.ItemDataRole.UserRole, device.key())
            item.setForeground(QColor(status_colour(reading.status)))
            self.device_list.addItem(item)
            if device.key() == current:
                self.device_list.setCurrentRow(self.device_list.count() - 1)
        self.device_list.blockSignals(False)

        fleet = self.store.fleet(hours=24)
        events = [event for event in self.store.events(hours=24, limit=500)
                  if event.severity in ("critical", "warning")]
        self.fleet_tab.reload(rows, fleet, len(events))
        self.events_tab.reload(self.store.events(hours=self.events_tab.selected()[0],
                                                 severity=self.events_tab.selected()[1],
                                                 limit=400), self.names())
        self.side_note.setText("%d shown of %d in the inventory"
                               % (len(rows), len(self.store.devices())))
        if self.wall is not None:
            self.wall.reload(rows)
        if current:
            self.show_device(current, quiet=True)
        elif rows:
            self.show_device(rows[0]["device"].key(), quiet=True)

    def names(self) -> Dict[str, str]:
        return {device.key(): device.name for device in self.store.devices()}

    def show_device(self, key: str, quiet: bool = False) -> None:
        device = self.store.get_device(key)
        if device is None:
            return
        self.current_key = key
        reading = self.store.last_sample(key) or Reading(device_id=key)
        history = {metric: self.store.history(key, metric, hours=24, limit=400)
                   for metric in ("cpu", "memory", "latency_ms", "temperature")}
        self.device_tab.load(device, reading, self.store.interfaces(key),
                             self.store.events(hours=720, device_id=key, limit=60), history)
        if quiet:
            return
        self.tabs.setCurrentIndex(1 if self.tabs.currentIndex() == 1 else
                                  self.tabs.currentIndex())

    # ------------------------------------------------------------------- actions
    def export_inventory(self) -> None:
        payload = {"exported": now_utc().isoformat(timespec="seconds"),
                   "version": __version__,
                   "devices": [device.as_dict() for device in self.store.devices()]}
        path = pathlib.Path(getattr(self.store, "path", db_path())).parent / \
            "inventory-export.json"
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        self.status.showMessage("inventory written to %s" % path, 8000)

    def about(self) -> None:
        summary = self.config.summarise()
        self.status.showMessage(
            "nocdeck %s · %s · SNMP v1/v2c · %d vendors · %d standard tables"
            % (__version__, "; ".join(summary[:2]),
               len({row.vendor for row in mibs.VENDOR_METRICS if row.vendor}),
               len(mibs.standard_table_roots())), 10000)


class _OneDeviceWorker(PollWorker):
    """`poll this device now` — the same cycle, aimed at one address."""

    def __init__(self, poller: Poller, device: Device, simulator=None, parent=None):
        super().__init__(poller, simulator, parent)
        self.device = device

    def run(self) -> None:                               # noqa: D102
        try:
            if self.simulator is not None:
                self.simulator.advance(60.0, elapsed=time.time() - self.started_at)
            outcome = self.poller.poll(self.device, force=True)
            self.done.emit([outcome], outcome.error or "")
        except Exception as exc:                         # noqa: BLE001
            self.done.emit([], str(exc))


def _bullet(status: str) -> str:
    return {"up": "●", "degraded": "◐", "down": "✖", "unknown": "○"}.get(status, "○")


# --------------------------------------------------------------------------- entry


def build_window(store: Store, config: Config, poller: Optional[Poller] = None,
                 simulator=None) -> MainWindow:
    return MainWindow(store, config, poller, simulator)


#: The tab names live in the package so `cli.py` can validate a `--tab` without
#: importing Qt; this is the window's own view of the same tuple.


def parse_args(argv: Optional[Sequence[str]] = None) -> Dict[str, object]:
    """Plain arguments in, a dictionary out — no Qt, no store, no side effects.

    `None` means "the command line I was started with", the same convention argparse
    uses, so a frozen entry point and a subcommand can both call it without thinking.
    """
    options: Dict[str, object] = {"shot": "", "tab": "", "demo": False, "db": "",
                                  "size": 0, "warmup": 6, "seed": 7}
    argv = list(sys.argv[1:] if argv is None else argv)
    index = 0
    while index < len(argv):
        argument = argv[index]

        def value(default: str = "") -> str:
            nonlocal index
            index += 1
            return argv[index] if index < len(argv) else default

        if argument == "--shot":
            options["shot"] = value("nocdeck-desktop.png")
        elif argument == "--tab":
            options["tab"] = value()
        elif argument == "--demo":
            options["demo"] = True
        elif argument == "--db":
            options["db"] = value()
        elif argument in ("--size", "--warmup", "--seed"):
            options[argument[2:]] = int(value("0") or 0)
        index += 1
    return options


def main(argv: Optional[Sequence[str]] = None) -> int:
    """`nocdeck desktop` — argparse stays in `cli.py`; this takes plain arguments."""
    options = parse_args(argv)
    shot = str(options["shot"])
    tab = str(options["tab"])
    demo = bool(options["demo"])
    db = str(options["db"])
    size, warmup, seed = int(options["size"]), int(options["warmup"]), int(options["seed"])

    from .. import simulate

    store = Store(db or db_path())
    config = Config.load()
    simulator = None
    if demo:
        nodes, simulator = simulate.build_simulator(store, config, size=size, seed=seed)
        poller = Poller(store, config, client_factory=simulator.client_for,
                        prober=simulator.prober, tcp_prober=simulator.tcp_prober,
                        http_prober=simulator.http_prober)
        started = time.time()
        for pass_number in range(warmup):
            simulator.advance(60.0, elapsed=pass_number * 60.0)
            poller.run_once(force=True)
        if shot:
            simulator.advance(60.0, elapsed=time.time() - started)
            poller.run_once(force=True)
    else:
        poller = Poller(store, config, on_events=lambda events: AL.dispatch(store, config,
                                                                           events))

    app = QApplication.instance() or QApplication(sys.argv[:1])
    window = build_window(store, config, poller, simulator)
    if demo:
        window.auto_action.setChecked(True)

    def mark(text: str) -> None:
        """Progress on file descriptor 2, not `sys.stderr`.

        A frozen windowed build has no Python streams at all (`sys.stderr` is None), so
        anything written through them disappears — which is how a crash-before-the-window
        looks like a hang. Qt writes to the descriptor directly for the same reason.
        """
        try:
            os.write(2, ("· %s\n" % text).encode("utf-8", "replace"))
        except OSError:
            pass

    def watchdog(seconds: float) -> None:
        """A screenshot is never worth hanging a build machine.

        The window gets its own process, so a frozen copy that wedges — a missing Qt
        platform plugin is the usual reason — would otherwise sit there until a CI
        timeout hours later. This ends it early, loudly, with a code the workflow sees.
        """

        def bark() -> None:
            time.sleep(seconds)
            mark("shot: nothing after %.0f s — giving up" % seconds)
            os._exit(4)

        threading.Thread(target=bark, daemon=True, name="shot-watchdog").start()

    if shot:
        watchdog(180.0)
        # Render without ever opening a real window: `WA_DontShowOnScreen` lays the
        # widgets out and paints them exactly as they would look, which is what a
        # screenshot wants, and it works on a build machine with no display server
        # (and, unlike `show()`, it can be done more than once in one process).
        window.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
        window.resize(1280, 820)
        mark("shot: window built")
        window.show()
        mark("shot: shown")
        window.reload()
        mark("shot: reloaded")
        if tab:
            labels = [window.tabs.tabText(i).lower() for i in range(window.tabs.count())]
            window.tabs.setCurrentIndex(labels.index(tab.lower())
                                        if tab.lower() in labels else 0)
        app.processEvents()
        for _ in range(6):
            app.processEvents()
            time.sleep(0.05)
        mark("shot: events pumped")
        path = pathlib.Path(shot)
        window.grab().save(str(path))
        mark("shot: grabbed")
        print("wrote %s (%d bytes)" % (path, path.stat().st_size))
        window.close()
        mark("shot: window closed")
        store.close()
        mark("shot: store closed")
        return 0

    window.show()
    code = app.exec()
    store.close()
    return int(code)
