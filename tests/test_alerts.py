"""Alerts: which ones go out, which ones do not, and what the message says.

The rule this file exists to protect is the one that keeps a monitoring tool
trusted: a person is told about a *change*, once, and never forty times about a
flapping port. Everything below either checks that rule or checks the wording of
what does get sent.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from nocdeck import alerts as AL
from nocdeck.model import AlertTarget, Event, severity_at_least

from conftest import FakeOpener, ago_iso


def event(kind="down", severity="critical", subject="device", message="core-sw-01 is down",
          at=None, device_id="core-sw-01"):
    return Event(at=at or ago_iso(minutes=1), device_id=device_id, kind=kind,
                 severity=severity, subject=subject, message=message)


# ------------------------------------------------------------------- the words


def test_one_event_reads_like_one_line():
    line = AL.event_line(event())
    assert "🔴" in line and "قطع شد" in line and "down" in line


def test_a_digest_counts_the_severities():
    text = AL.format_events([event(), event(severity="warning", kind="degraded"),
                             event(severity="info", kind="up", message="back")],
                            digest=True)
    assert "3 رویداد" in text and "🔴 1" in text and "🟠 1" in text and "🟢 1" in text


def test_the_dashboard_link_is_only_added_when_there_is_one():
    assert "dashboard" not in AL.format_events([event()])
    assert "http://noc:8090" in AL.format_events([event()], url="http://noc:8090")


def test_severity_is_compared_on_a_scale():
    assert severity_at_least("critical", "warning")
    assert not severity_at_least("info", "warning")
    assert severity_at_least("warning", "warning")


# ------------------------------------------------------------------ quiet hours


def test_quiet_hours_wrap_midnight():
    target = AlertTarget(kind="telegram", quiet_hours="23:00-07:00")
    inside = datetime(2026, 9, 21, 2, 0, tzinfo=timezone.utc)
    assert AL.in_quiet_hours(target, inside)
    assert not AL.in_quiet_hours(target, datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc))


def test_quiet_hours_inside_one_day():
    target = AlertTarget(kind="telegram", quiet_hours="12:00-14:00")
    assert AL.in_quiet_hours(target, datetime(2026, 9, 21, 13, 0, tzinfo=timezone.utc))
    assert not AL.in_quiet_hours(target, datetime(2026, 9, 21, 15, 0, tzinfo=timezone.utc))


def test_a_malformed_quiet_window_never_silences_an_alert():
    assert not AL.in_quiet_hours(AlertTarget(kind="telegram", quiet_hours="last night"))
    assert not AL.in_quiet_hours(AlertTarget(kind="telegram", quiet_hours=""))


# ------------------------------------------------------------------- telegram


def test_a_telegram_message_goes_to_the_right_room(monkeypatch):
    opener = FakeOpener()
    monkeypatch.setattr(AL, "OPENER", opener)
    target = AlertTarget(kind="telegram", token="123:abc", chat_id="-100999")
    detail = AL.send_telegram(target, "<b>hello</b>")
    assert "message 7" in detail
    sent = opener.calls[0]
    assert sent["url"].endswith("/bot123:abc/sendMessage")
    assert sent["json"]["chat_id"] == "-100999"
    assert sent["json"]["parse_mode"] == "HTML"


def test_telegrams_refusal_is_quoted_back(monkeypatch):
    monkeypatch.setattr(AL, "OPENER", FakeOpener(
        payload=json.dumps({"ok": False, "description": "chat not found"}).encode()))
    with pytest.raises(AL.AlertError) as caught:
        AL.send_telegram(AlertTarget(kind="telegram", token="1:a", chat_id="nope"),
                         "hello")
    assert "chat not found" in str(caught.value)


def test_a_target_without_credentials_says_so_before_trying():
    with pytest.raises(AL.AlertError):
        AL.send_telegram(AlertTarget(kind="telegram", token="", chat_id=""), "hi")


# -------------------------------------------------------------------- webhook


def test_a_webhook_carries_structured_events(monkeypatch):
    opener = FakeOpener(payload=b"ok", status=202)
    monkeypatch.setattr(AL, "OPENER", opener)
    target = AlertTarget(kind="webhook", url="https://hooks.example.net/noc")
    detail = AL.send_webhook(target, [event()], {"core-sw-01": "core-sw-01"},
                             "http://noc:8090")
    assert detail == "HTTP 202"
    body = opener.calls[0]["json"]
    assert body["source"] == "nocdeck"
    assert body["events"][0]["kind"] == "down"
    assert body["dashboard"] == "http://noc:8090"


def test_a_webhook_that_answers_500_is_an_error_not_a_silence(monkeypatch):
    class Angry(FakeOpener):
        def __call__(self, request, timeout=None, **kwargs):
            import urllib.error
            raise urllib.error.HTTPError(request.full_url, 500, "boom", {}, None)

    monkeypatch.setattr(AL, "OPENER", Angry())
    with pytest.raises(AL.AlertError) as caught:
        AL.send_webhook(AlertTarget(kind="webhook", url="https://x.example/"), [event()])
    assert "500" in str(caught.value)


# -------------------------------------------------------------------- dispatch


def dispatch_to(store, config, events, **kwargs):
    return AL.dispatch(store, config, events, **kwargs)


def test_nothing_is_sent_when_no_target_is_configured(store, config, switch):
    store.save_device(switch)
    report = dispatch_to(store, config, [event()])
    assert report["sent"] == []
    assert "no alert targets configured" in report["skipped"][0]


def test_a_transition_is_sent_once_and_not_again(store, config, switch, monkeypatch):
    store.save_device(switch)
    opener = FakeOpener(payload=json.dumps({"ok": True, "result": {"message_id": 3}}).encode())
    monkeypatch.setattr(AL, "OPENER", opener)
    config.alert_targets = [AlertTarget(kind="telegram", name="ops", token="1:a",
                                        chat_id="-100")]

    # the first time this device goes down, somebody is told
    first_event = event(at=ago_iso(minutes=4))
    first = dispatch_to(store, config, [first_event])
    assert len(first["sent"]) == 1, "a fresh trouble is worth a message"
    store.add_event(first_event)

    # the same trouble, still going on: the dashboard shows it, nobody is told again
    second = dispatch_to(store, config, [event(at=ago_iso(minutes=1))])
    assert second["sent"] == []
    assert any("already open" in note for note in second["skipped"])
    assert len(opener.calls) == 1


def test_good_news_rides_along_with_bad_news(store, config, switch, monkeypatch):
    monkeypatch.setattr(AL, "OPENER", FakeOpener())
    store.save_device(switch)
    config.alert_targets = [AlertTarget(kind="telegram", name="ops", token="1:a",
                                        chat_id="-100", min_severity="info")]
    report = dispatch_to(store, config, [event(kind="up", severity="info",
                                               message="back")])
    assert len(report["sent"]) == 1, "a recovery is worth a message even on its own"


def test_a_recovery_is_info_so_a_warning_only_target_does_not_get_it(store, config, switch,
                                                                     monkeypatch):
    """`--min-severity warning` is the default, and a device coming back is not a
    warning. `--min-severity info` is how a target asks for the good news too."""
    opener = FakeOpener()
    monkeypatch.setattr(AL, "OPENER", opener)
    store.save_device(switch)
    config.alert_targets = [AlertTarget(kind="telegram", name="ops", token="1:a",
                                        chat_id="-100")]
    report = dispatch_to(store, config, [event(kind="up", severity="info")])
    assert report["sent"] == [] and len(opener.calls) == 0


def test_a_storm_becomes_one_digest(store, config, switch, monkeypatch):
    opener = FakeOpener()
    monkeypatch.setattr(AL, "OPENER", opener)
    store.save_device(switch)
    config.alert_targets = [AlertTarget(kind="telegram", name="ops", token="1:a",
                                        chat_id="-100")]
    events = [event(subject="cpu", kind="threshold", severity="warning",
                    at=ago_iso(minutes=1)) for _ in range(9)]
    report = dispatch_to(store, config, events)
    assert len(report["sent"]) == 1, "one message, not nine"
    assert report["sent"][0]["events"] == 9
    body = opener.calls[0]["json"]["text"]
    assert "9 رویداد" in body


def test_the_per_run_cap_is_reported_rather_than_hidden(store, config, switch, monkeypatch):
    monkeypatch.setattr(AL, "OPENER", FakeOpener())
    store.save_device(switch)
    config.alert_targets = [AlertTarget(kind="telegram", name="ops", token="1:a",
                                        chat_id="-100")]
    config.alert_max_per_run = 3
    events = [event(subject="s%d" % index, kind="threshold", at=ago_iso(minutes=1))
              for index in range(10)]
    report = dispatch_to(store, config, events)
    assert report["sent"][0]["events"] == 3
    assert any("cap" in note for note in report["skipped"])


def test_a_target_that_only_wants_criticals_is_not_woken_for_a_warning(store, config,
                                                                       switch, monkeypatch):
    opener = FakeOpener()
    monkeypatch.setattr(AL, "OPENER", opener)
    store.save_device(switch)
    config.alert_targets = [AlertTarget(kind="telegram", name="night", token="1:a",
                                        chat_id="-100", min_severity="critical")]
    report = dispatch_to(store, config, [event(severity="warning", kind="degraded")])
    assert report["sent"] == [] and len(opener.calls) == 0


def test_critical_news_ignores_quiet_hours_but_a_warning_does_not(store, config, switch,
                                                                 monkeypatch):
    opener = FakeOpener()
    monkeypatch.setattr(AL, "OPENER", opener)
    store.save_device(switch)
    config.alert_targets = [AlertTarget(kind="telegram", name="ops", token="1:a",
                                        chat_id="-100", quiet_hours="00:00-23:59")]
    quiet = datetime(2026, 9, 21, 3, 0, tzinfo=timezone.utc)
    report = dispatch_to(store, config,
                         [event(severity="warning", kind="degraded", at=ago_iso(minutes=1))],
                         now=quiet)
    assert report["sent"] == [] and any("quiet hours" in note for note in report["skipped"])

    report = dispatch_to(store, config, [event(subject="device", at=ago_iso())], now=quiet)
    assert len(report["sent"]) == 1, "a device that is down at 3 a.m. is why you built this"


def test_a_failing_target_is_reported_and_does_not_stop_the_others(store, config, switch,
                                                                   monkeypatch):
    class Half:
        def __init__(self):
            self.calls = []

        def __call__(self, request, timeout=None, **kwargs):
            self.calls.append(request.full_url)
            if "bot9:z" in request.full_url:          # the target the test wants to fail
                raise OSError("no route to host")
            return FakeOpener()(request, timeout=timeout, **kwargs)

    monkeypatch.setattr(AL, "OPENER", Half())
    store.save_device(switch)
    config.alert_targets = [
        AlertTarget(kind="telegram", name="broken", token="9:z", chat_id="-1"),
        AlertTarget(kind="telegram", name="ops", token="1:a", chat_id="-100"),
    ]
    report = dispatch_to(store, config, [event(at=ago_iso(minutes=2))])
    assert report["errors"] and "broken" in report["errors"][0]
    assert len(report["sent"]) == 1, "the second target still got it"


def test_the_test_command_sends_a_message_that_says_it_is_a_test(monkeypatch):
    opener = FakeOpener()
    monkeypatch.setattr(AL, "OPENER", opener)
    detail = AL.test_target(AlertTarget(kind="telegram", token="1:a", chat_id="-100"))
    assert "message" in detail
    assert "TEST" in opener.calls[0]["json"]["text"]


def test_email_needs_a_server_and_a_recipient():
    with pytest.raises(AL.AlertError):
        AL.send_email(AlertTarget(kind="email", server="", to=[]), "hi")
