"""The add-device dialog: an address, a port, and the credentials for it.

This is the window a person opens when a new switch arrives, and it is the one place in
the desktop app where nothing may be mysterious. So it does three things a form usually
does not:

* **It talks to the device before you trust it.** "Test connection" polls once and says
  what came back — the sysDescr, the port count, or the exact reason the credentials
  were refused. A wrong passphrase says so now, not at 03:00.
* **It says what a v3 passphrase is.** v1/v2c has a community string; v3 has a username
  and two passphrases, and one of them is only used if you ask for encryption. The form
  labels which is which instead of leaving the operator to remember.
* **It never shows a stored secret.** Editing a device leaves the passphrase box empty
  and keeps what is stored unless something new is typed — a form that silently wipes a
  working credential is worse than one that asks again.

The dialog writes nothing itself: `MainWindow` saves and polls through the same poller
the rest of the app uses, so a device added here is indistinguishable from one added by
`nocdeck add`.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                             QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
                             QMessageBox, QPushButton, QScrollArea, QSpinBox, QVBoxLayout,
                             QWidget)

from ..model import Device
from ..snmpv3 import AUTH_PROTOCOLS, PRIV_PROTOCOLS

KINDS = ("generic", "switch", "router", "firewall", "server", "ap", "ups", "printer",
         "storage", "camera")


def _holder(layout) -> QWidget:
    """A widget whose only job is to hold a layout Qt will not add directly."""
    holder = QWidget()
    holder.setLayout(layout)
    return holder


class AddDeviceDialog(QDialog):
    """A device, as typed by a person who knows what is plugged in where."""

    def __init__(self, config, device: Optional[Device] = None, parent=None):
        super().__init__(parent)
        self.device = device
        self.setWindowTitle("edit %s" % device.name if device else "add a device")
        self.setMinimumWidth(880)
        editing = device is not None

        outer = QVBoxLayout(self)
        intro = QLabel(
            "nocdeck will poll this address over SNMP, ping it, and watch the ports and "
            "URL below. Nothing is sent anywhere else."
            if not editing else
            "Editing %s. The passphrase boxes are empty on purpose: leave them empty to "
            "keep the credentials already stored." % device.name)
        intro.setWordWrap(True)
        intro.setObjectName("dim")
        outer.addWidget(intro)

        columns = QHBoxLayout()
        left = QVBoxLayout()
        right = QVBoxLayout()

        # ---------------------------------------------------------------- identity
        identity = QGroupBox("the device")
        form = QFormLayout(identity)
        self.name = QLineEdit(device.name if editing else "")
        self.name.setPlaceholderText("core-sw-01")
        form.addRow("name", self.name)
        self.host = QLineEdit(device.host if editing else "")
        self.host.setPlaceholderText("10.20.0.2 or switch.dc.example.net")
        form.addRow("address", self.host)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(device.port if editing else 161)
        form.addRow("SNMP port", self.port)
        self.kind = QComboBox()
        self.kind.addItems(KINDS)
        self.kind.setCurrentText(device.kind if editing and device.kind in KINDS
                                 else "switch")
        form.addRow("kind", self.kind)
        self.group = QLineEdit(device.group if editing else "")
        self.group.setPlaceholderText("dc, campus…")
        form.addRow("group", self.group)
        self.location = QLineEdit(device.location if editing else "")
        self.location.setPlaceholderText("rack 3, floor 2")
        form.addRow("location", self.location)
        left.addWidget(identity)

        # ------------------------------------------------------------ credentials
        credentials = QGroupBox("how to ask it")
        cred_form = QFormLayout(credentials)
        self.version = QComboBox()
        self.version.addItems(["1", "2c", "3"])
        self.version.setCurrentText(device.version if editing else "2c")
        self.version.currentTextChanged.connect(self._version_changed)
        cred_form.addRow("SNMP version", self.version)

        self.community = QLineEdit(device.community if editing else "public")
        cred_form.addRow("community (v1/v2c)", self.community)

        self.user = QLineEdit(device.user if editing else "")
        self.user.setPlaceholderText("nocmon")
        cred_form.addRow("v3 username", self.user)
        self.auth = QComboBox()
        self.auth.addItems(["", *sorted(set(AUTH_PROTOCOLS))])
        self.auth.setCurrentText((device.auth if editing else "").lower())
        cred_form.addRow("v3 authentication", self.auth)
        self.auth_key = QLineEdit()
        self.auth_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.auth_key.setPlaceholderText("keep the stored one" if editing
                                         else "the authentication passphrase")
        cred_form.addRow("auth passphrase", self.auth_key)
        self.priv = QComboBox()
        self.priv.addItems(["", *sorted(set(PRIV_PROTOCOLS))])
        self.priv.setCurrentText((device.priv if editing else "").lower())
        cred_form.addRow("v3 privacy", self.priv)
        self.priv_key = QLineEdit()
        self.priv_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.priv_key.setPlaceholderText("keep the stored one" if editing
                                         else "the privacy passphrase")
        cred_form.addRow("priv passphrase", self.priv_key)
        self.context = QLineEdit(device.context if editing else "")
        self.context.setPlaceholderText("usually empty")
        cred_form.addRow("context name", self.context)
        self.show_secrets = QCheckBox("show what I type")
        self.show_secrets.toggled.connect(self._show_secrets)
        cred_form.addRow("", self.show_secrets)
        self.v3_hint = QLabel("v3 needs a username. Authentication is required; privacy "
                              "encrypts the conversation and is worth having.")
        self.v3_hint.setWordWrap(True)
        self.v3_hint.setObjectName("dim")
        cred_form.addRow("", self.v3_hint)
        right.addWidget(credentials)

        # ------------------------------------------------------------ the checks
        checks = QGroupBox("what to watch")
        checks_form = QFormLayout(checks)
        self.interval = QSpinBox()
        self.interval.setRange(5, 86400)
        self.interval.setSuffix(" s")
        self.interval.setValue(device.interval if editing else int(config.interval))
        checks_form.addRow("poll every", self.interval)
        self.tcp_ports = QLineEdit(",".join(str(port) for port in
                                           (device.tcp_ports if editing else [22, 443])))
        self.tcp_ports.setPlaceholderText("22, 443 (optional)")
        checks_form.addRow("watch TCP ports", self.tcp_ports)
        self.http_url = QLineEdit(device.http_url if editing else "")
        self.http_url.setPlaceholderText("https://10.20.0.2/ (optional)")
        checks_form.addRow("watch a URL", self.http_url)
        self.tags = QLineEdit(",".join(device.tags if editing else []))
        self.tags.setPlaceholderText("core, rack1")
        checks_form.addRow("tags", self.tags)
        flags = QGridLayout()
        self.snmp = QCheckBox("SNMP")
        self.snmp.setChecked(device.snmp if editing else True)
        self.ping = QCheckBox("ping")
        self.ping.setChecked(device.ping if editing else True)
        self.snmp_only = QCheckBox("SNMP only (do not ping it)")
        self.snmp_only.setChecked(device.snmp_only if editing else False)
        self.force = QCheckBox("overwrite a device with the same name")
        flags.addWidget(self.snmp, 0, 0)
        flags.addWidget(self.ping, 0, 1)
        flags.addWidget(self.snmp_only, 1, 0)
        flags.addWidget(self.force, 1, 1)
        checks_form.addRow("", _holder(flags))
        right.addWidget(checks)

        columns.addLayout(left, 1)
        columns.addLayout(right, 1)
        body = QWidget()
        body.setLayout(columns)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self.result)

        buttons = QDialogButtonBox()
        self.test_button = QPushButton("test connection")
        self.test_button.setToolTip("poll it once without saving anything")
        self.save_button = QPushButton("save" if editing else "add it")
        self.save_button.setDefault(True)
        buttons.addButton(self.test_button, QDialogButtonBox.ButtonRole.ActionRole)
        buttons.addButton(self.save_button, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

        self._version_changed(self.version.currentText())

    # ------------------------------------------------------------------ helpers
    def _show_secrets(self, visible: bool) -> None:
        mode = (QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)
        self.auth_key.setEchoMode(mode)
        self.priv_key.setEchoMode(mode)

    def _version_changed(self, version: str) -> None:
        """v3 is a different set of questions, so ask those instead."""
        v3 = version == "3"
        for widget in (self.community,):
            widget.setEnabled(not v3)
        for widget in (self.user, self.auth, self.auth_key, self.priv, self.priv_key,
                       self.context, self.v3_hint):
            widget.setEnabled(v3)
        if v3 and not self.auth.currentText():
            self.auth.setCurrentText("sha256")
        if v3 and not self.priv.currentText():
            self.priv.setCurrentText("aes")

    def payload(self) -> Dict[str, object]:
        """Exactly what a person typed, in the shape the model already understands."""
        return {
            "name": self.name.text().strip(), "host": self.host.text().strip(),
            "port": self.port.value(), "kind": self.kind.currentText(),
            "group": self.group.text().strip(), "location": self.location.text().strip(),
            "version": self.version.currentText(),
            "community": self.community.text(),
            "user": self.user.text().strip(), "auth": self.auth.currentText(),
            "auth_key": self.auth_key.text(), "priv": self.priv.currentText(),
            "priv_key": self.priv_key.text(), "context": self.context.text().strip(),
            "interval": self.interval.value(), "tcp_ports": self.tcp_ports.text(),
            "http_url": self.http_url.text().strip(), "tags": self.tags.text(),
            "snmp": self.snmp.isChecked(), "ping": self.ping.isChecked(),
            "snmp_only": self.snmp_only.isChecked(), "force": self.force.isChecked(),
        }

    def proposed_device(self) -> Device:
        """The device this form describes — validated, not saved."""
        return Device.from_payload(self.payload(), existing=self.device)

    def problems(self) -> List[str]:
        return self.proposed_device().validate()

    def show_result(self, ok: bool, text: str) -> None:
        colour = "#3ddc84" if ok else "#ff5f56"
        self.result.setText(("<b style='color:%s'>%s</b>" % (colour, "✓" if ok else "✗"))
                            + " " + text)
        self.result.repaint()

    def complain(self, problems: List[str]) -> None:
        """Say what is wrong next to the form, and in a box if it is not obvious."""
        self.show_result(False, " · ".join(problems))
        QMessageBox.warning(self, "not yet", "\n".join(problems))
