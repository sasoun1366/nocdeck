"""Settings: one JSON file, environment variables on top, defaults underneath.

The order matters and is the usual one — a value in the environment beats the file,
the file beats the defaults — because the file is what a person edits and the
environment is what a container or a CI job sets.
"""

from __future__ import annotations

import json
import os
import pathlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .model import AlertTarget, Thresholds

DEFAULT_HOME = "~/.nocdeck"
CONFIG_NAME = "config.json"
DB_NAME = "nocdeck.db"
#: The communities a scan will try, in order. Change one and everything is your own.
DEFAULT_COMMUNITIES = ("public", "private")


def home() -> pathlib.Path:
    path = pathlib.Path(os.environ.get("NOCDECK_HOME") or DEFAULT_HOME).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def config_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("NOCDECK_CONFIG") or (home() / CONFIG_NAME))


def db_path() -> pathlib.Path:
    return pathlib.Path(os.environ.get("NOCDECK_DB") or (home() / DB_NAME))


@dataclass
class Config:
    """Everything that is not a device."""

    # ---- polling
    interval: int = 60                     # default seconds between polls
    workers: int = 24                      # devices polled at once
    snmp_timeout: float = 2.0
    snmp_retries: int = 1
    snmp_bulk: int = 25                    # rows per GETBULK
    ping_count: int = 3
    ping_timeout: float = 1.5
    tcp_fallback: bool = True
    max_table_rows: int = 4000             # a walk that never ends is a broken agent

    # ---- health logic
    failures_to_down: int = 2              # one lost packet is not an outage
    successes_to_up: int = 2
    flap_window_minutes: int = 10
    flap_count: int = 4                    # this many transitions in the window = flapping

    # ---- what to keep
    sample_days: int = 14
    event_days: int = 120
    rollup_days: int = 400

    # ---- web
    bind: str = "0.0.0.0"
    port: int = 8090
    title: str = "nocdeck"
    refresh_seconds: int = 30
    public_summary: bool = False           # a read-only page without the detail

    # ---- alerts
    alert_targets: List[AlertTarget] = field(default_factory=list)
    alert_max_per_run: int = 12            # a storm should not become a flood
    alert_digest_after: int = 4            # more than this many, send one digest instead
    alert_repeat_minutes: int = 0          # 0 = only on transitions, never repeated

    # ---- discovery
    communities: List[str] = field(default_factory=lambda: list(DEFAULT_COMMUNITIES))
    scan_timeout: float = 1.0

    # ---- thresholds applied to any device that has none of its own
    thresholds: Dict[str, float] = field(default_factory=dict)

    # ------------------------------------------------------------------ plumbing
    def to_dict(self) -> Dict[str, Any]:
        data = {key: value for key, value in self.__dict__.items()
                if key != "alert_targets"}
        data["alert_targets"] = [target.as_dict() for target in self.alert_targets]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        known = {f for f in cls.__dataclass_fields__}
        clean = {k: v for k, v in (data or {}).items() if k in known and v is not None}
        targets = [AlertTarget.from_dict(row) for row in (data.get("alert_targets") or [])]
        config = cls(**{k: v for k, v in clean.items() if k != "alert_targets"})
        config.alert_targets = targets
        config.communities = [str(c) for c in (data.get("communities") or DEFAULT_COMMUNITIES)]
        return config

    def threshold_object(self, device_thresholds: Optional[Dict[str, float]] = None
                         ) -> Thresholds:
        merged = dict(self.thresholds or {})
        merged.update(device_thresholds or {})
        return Thresholds(**{k: v for k, v in merged.items()
                             if k in Thresholds.__dataclass_fields__})

    # ------------------------------------------------------------------- loading
    @classmethod
    def load(cls, path: Optional[pathlib.Path] = None) -> "Config":
        path = path or config_path()
        data: Dict[str, Any] = {}
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = {}
        config = cls.from_dict(data if isinstance(data, dict) else {})
        config.apply_environment()
        return config

    def apply_environment(self) -> None:
        """The handful of variables worth setting in a container or a CI job."""
        env = os.environ
        for name, attribute, caster in (
            ("NOCDECK_PORT", "port", int),
            ("NOCDECK_BIND", "bind", str),
            ("NOCDECK_INTERVAL", "interval", int),
            ("NOCDECK_WORKERS", "workers", int),
            ("NOCDECK_SNMP_TIMEOUT", "snmp_timeout", float),
            ("NOCDECK_COMMUNITIES", "communities", lambda v: [p.strip() for p in v.split(",") if p.strip()]),
        ):
            if env.get(name):
                try:
                    setattr(self, attribute, caster(env[name]))
                except (TypeError, ValueError):
                    pass
        if env.get("NOCDECK_TELEGRAM_TOKEN") and env.get("NOCDECK_TELEGRAM_CHAT"):
            exists = any(t.kind == "telegram" and t.chat_id == env["NOCDECK_TELEGRAM_CHAT"]
                         for t in self.alert_targets)
            if not exists:
                self.alert_targets.append(AlertTarget(
                    kind="telegram", name="telegram (environment)",
                    token=env["NOCDECK_TELEGRAM_TOKEN"],
                    chat_id=env["NOCDECK_TELEGRAM_CHAT"]))
        if env.get("NOCDECK_WEBHOOK"):
            self.alert_targets.append(AlertTarget(kind="webhook", name="webhook (environment)",
                                                  url=env["NOCDECK_WEBHOOK"]))

    def save(self, path: Optional[pathlib.Path] = None) -> pathlib.Path:
        path = path or config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
        try:
            os.chmod(path, 0o600)          # a config can hold a token
        except OSError:
            pass
        return path

    def summarise(self) -> List[str]:
        """The lines `nocdeck doctor` prints."""
        lines = [
            "home            %s" % home(),
            "database        %s" % db_path(),
            "interval        %d s · %d workers" % (self.interval, self.workers),
            "snmp            timeout %.1fs · %d retries · bulk %d"
            % (self.snmp_timeout, self.snmp_retries, self.snmp_bulk),
            "health          %d failures to down · %d successes to up"
            % (self.failures_to_down, self.successes_to_up),
            "retention       samples %d d · events %d d · rollups %d d"
            % (self.sample_days, self.event_days, self.rollup_days),
            "web             http://%s:%d" % (self.bind, self.port),
            "communities     %s" % ", ".join(self.communities),
        ]
        if not self.alert_targets:
            lines.append("alerts          none configured — `nocdeck alert add …`")
        else:
            for target in self.alert_targets:
                lines.append("alerts          %-9s %s%s"
                             % (target.kind, target.name or "",
                                "" if target.enabled else " (disabled)"))
        return lines
