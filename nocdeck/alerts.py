"""Telling someone: Telegram, email, or a webhook, without ever flooding them.

A monitoring tool earns its keep at three in the morning, and loses it the first
time it sends forty messages about one flapping port. So:

* an alert is sent for a **transition**, not for a state — the state is on the
  dashboard, which is what a dashboard is for
* an event that is already open is not repeated (`store.open_problem`)
* more than `digest_after` events in one cycle become **one** message
* quiet hours are respected, except for `critical`
* every send is marked in the database, so a restart does not resend the night

The transports are the standard library: `urllib` for Telegram and webhooks,
`smtplib` for mail. Nothing to install, nothing to keep running.
"""

from __future__ import annotations

import json
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import datetime, time as clock_time, timedelta, timezone
from email.message import EmailMessage
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .model import (AlertTarget, Event, human_seconds, iso, now_utc, parse_iso,
                    severity_at_least)

USER_AGENT = "nocdeck/0.1 (+https://github.com/sasoun1366/nocdeck)"

#: The one door to the network in this module. Tests and air-gapped users replace it
#: (`alerts.OPENER = my_transport`) instead of monkey-patching urllib itself.
OPENER = urllib.request.urlopen
EMOJI = {"critical": "🔴", "warning": "🟠", "info": "🟢"}
KIND_TEXT = {
    "down": ("قطع شد", "down"), "up": ("برگشت", "back"),
    "degraded": ("افت کرد", "degraded"), "recovered": ("سالم شد", "recovered"),
    "threshold": ("از حد گذشت", "over the line"), "cleared": ("به حد برگشت", "back under"),
    "interface-down": ("پورت قطع شد", "port down"), "interface-up": ("پورت وصل شد", "port up"),
    "flap": ("پرید و برگشت", "flapping"),
}


class AlertError(Exception):
    """A target refused the message, with the reason a person needs to fix it."""


# ------------------------------------------------------------------- message text


def event_line(event: Event, device_name: str = "") -> str:
    """One event as one line — the digest is built from these."""
    fa, en = KIND_TEXT.get(event.kind, (event.kind, event.kind))
    head = "%s %s" % (EMOJI.get(event.severity, "•"), device_name or event.device_id)
    when = parse_iso(event.at) or now_utc()
    stamp = when.astimezone(timezone.utc).strftime("%H:%M")
    return "%s — %s / %s · %s UTC" % (head, fa, en, stamp)


def format_events(events: Sequence[Event], names: Optional[Dict[str, str]] = None,
                  url: str = "", digest: bool = False) -> str:
    """The message body: what changed, in both languages, in a few lines."""
    names = names or {}
    lines: List[str] = []
    if digest and len(events) > 1:
        count = {"critical": 0, "warning": 0, "info": 0}
        for event in events:
            count[event.severity] = count.get(event.severity, 0) + 1
        lines.append("🛡 <b>nocdeck — %d رویداد</b> / %d events" % (len(events), len(events)))
        lines.append("🔴 %d · 🟠 %d · 🟢 %d" % (count.get("critical", 0), count.get("warning", 0),
                                                count.get("info", 0)))
        lines.append("")
    for event in events:
        name = names.get(event.device_id, event.device_id)
        lines.append("<b>%s</b>" % event.message if not digest else event_line(event, name))
        if not digest:
            lines.append("%s / %s" % (KIND_TEXT.get(event.kind, ("", ""))[0],
                                      KIND_TEXT.get(event.kind, ("", ""))[1]))
    if url:
        lines.append("")
        lines.append('🔗 <a href="%s">داشبورد / dashboard</a>' % url)
    return "\n".join(lines)


def make_webhook_payload(events: Sequence[Event], names: Optional[Dict[str, str]] = None,
                         url: str = "") -> Dict[str, object]:
    names = names or {}
    return {
        "source": "nocdeck",
        "sent_at": iso(),
        "dashboard": url,
        "events": [
            {"at": event.at, "device": event.device_id,
             "device_name": names.get(event.device_id, event.device_id),
             "kind": event.kind, "severity": event.severity, "subject": event.subject,
             "message": event.message, "value": event.value, "detail": event.detail}
            for event in events
        ],
    }


# -------------------------------------------------------------------- quiet hours


def in_quiet_hours(target: AlertTarget, when: Optional[datetime] = None) -> bool:
    """`"23:00-07:00"`, local time, wrapping midnight. Malformed means 'no'."""
    text = (target.quiet_hours or "").strip()
    if not text or "-" not in text:
        return False
    try:
        start_text, end_text = text.split("-", 1)
        start = clock_time(*[int(part) for part in start_text.strip().split(":")][:2])
        end = clock_time(*[int(part) for part in end_text.strip().split(":")][:2])
    except (ValueError, TypeError):
        return False
    # Compare in the machine's own time zone: "23:00-07:00" means the local night, and
    # the clock in the config file has no time zone attached.
    moment = when or datetime.now().astimezone()
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    local = moment.time()
    if start <= end:
        return start <= local < end
    return local >= start or local < end


# ---------------------------------------------------------------------- sender


def send_telegram(target: AlertTarget, text: str, timeout: float = 15.0) -> str:
    if not target.token or not target.chat_id:
        raise AlertError("telegram target needs a token and a chat id")
    url = "https://api.telegram.org/bot%s/sendMessage" % target.token
    payload = {"chat_id": target.chat_id, "text": text[:4000],
               "parse_mode": "HTML", "disable_web_page_preview": True}
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT})
    try:
        with OPENER(request, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        try:
            detail = json.loads(detail).get("description", detail)
        except ValueError:
            pass
        raise AlertError("telegram refused: %s" % detail[:160]) from None
    except Exception as exc:                                    # noqa: BLE001
        raise AlertError("telegram unreachable: %s" % exc) from None
    if not body.get("ok"):
        raise AlertError("telegram said: %s" % body.get("description", "?"))
    return "message %s" % body.get("result", {}).get("message_id", "?")


def send_email(target: AlertTarget, text: str, subject: str = "nocdeck alert") -> str:
    if not target.server or not target.to:
        raise AlertError("email target needs an smtp server and at least one recipient")
    message = EmailMessage()
    message["From"] = target.sender or target.username or "nocdeck@localhost"
    message["To"] = ", ".join(target.to)
    message["Subject"] = subject
    message.set_content(_plain(text))
    message.add_alternative("<pre style='font:13px/1.5 monospace'>%s</pre>"
                             % html_escape(text), subtype="html")
    try:
        if target.port == 465:
            with smtplib.SMTP_SSL(target.server, target.port, timeout=20,
                                  context=ssl.create_default_context()) as server:
                if target.username:
                    server.login(target.username, target.password)
                server.send_message(message)
        else:
            with smtplib.SMTP(target.server, target.port, timeout=20) as server:
                server.ehlo()
                try:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                except smtplib.SMTPException:
                    pass                                   # a relay on the LAN may not do TLS
                if target.username:
                    server.login(target.username, target.password)
                server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        raise AlertError("smtp refused: %s" % exc) from None
    return "sent to %s" % ", ".join(target.to)


def send_webhook(target: AlertTarget, events: Sequence[Event],
                 names: Optional[Dict[str, str]] = None, dashboard: str = "") -> str:
    if not target.url:
        raise AlertError("webhook target needs a url")
    payload = make_webhook_payload(events, names, dashboard)
    request = urllib.request.Request(
        target.url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method=(target.method or "POST").upper())
    try:
        with OPENER(request, timeout=20) as response:
            return "HTTP %d" % response.status
    except urllib.error.HTTPError as exc:
        raise AlertError("webhook answered HTTP %d" % exc.code) from None
    except Exception as exc:                                    # noqa: BLE001
        raise AlertError("webhook unreachable: %s" % exc) from None


def _plain(html: str) -> str:
    for tag in ("<b>", "</b>", "<i>", "</i>", "<pre>", "</pre>"):
        html = html.replace(tag, "")
    return html.replace("<br>", "\n")


def html_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def send_to(target: AlertTarget, events: Sequence[Event],
            names: Optional[Dict[str, str]] = None, dashboard: str = "",
            digest: bool = False) -> str:
    """One target, one message. The caller decides *what* deserves sending."""
    text = format_events(events, names, dashboard, digest=digest)
    if target.kind == "telegram":
        return send_telegram(target, text)
    if target.kind == "email":
        subject = "nocdeck: %s" % (events[0].message if len(events) == 1
                                   else "%d events" % len(events))
        return send_email(target, text, subject[:150])
    if target.kind == "webhook":
        return send_webhook(target, events, names, dashboard)
    raise AlertError("unknown target kind: %r" % target.kind)


# ------------------------------------------------------------------- dispatching


def dispatch(store, config, events: Sequence[Event], dashboard: str = "",
             force: bool = False, now: Optional[datetime] = None) -> Dict[str, object]:
    """Send what deserves sending, and record it. Returns a small report.

    `force` is for `nocdeck alert test` and for a human who wants to see the path
    work; the scheduled path never forces.
    """
    report: Dict[str, object] = {"sent": [], "skipped": [], "errors": [], "events": len(events)}
    if not events:
        return report
    targets = [target for target in config.alert_targets if target.enabled]
    if not targets:
        report["skipped"].append("no alert targets configured")
        return report

    names: Dict[str, str] = {}
    for event in events:
        if event.device_id not in names:
            device = store.get_device(event.device_id)
            names[event.device_id] = device.name if device else event.device_id

    interesting: List[Event] = []
    for event in events:
        if not force:
            if event.kind in ("up", "recovered", "interface-up", "cleared"):
                pass                                    # good news rides along with bad news
            elif store.open_problem(event.device_id, event.kind, event.subject,
                                    before=event.at):
                report["skipped"].append("already open: %s %s"
                                         % (event.device_id, event.kind))
                continue
        interesting.append(event)

    if not interesting:
        return report

    digest = len(interesting) > max(1, int(config.alert_digest_after))
    if len(interesting) > config.alert_max_per_run and not force:
        dropped = len(interesting) - config.alert_max_per_run
        interesting = interesting[:config.alert_max_per_run]
        report["skipped"].append("%d events beyond the per-run cap" % dropped)
        digest = True

    for target in targets:
        wanted = [event for event in interesting
                  if severity_at_least(event.severity, target.min_severity)]
        if not wanted:
            report["skipped"].append("%s: nothing at or above %s"
                                     % (target.name or target.kind, target.min_severity))
            continue
        if in_quiet_hours(target, now) and not any(event.severity == "critical"
                                                   for event in wanted):
            report["skipped"].append("%s: quiet hours" % (target.name or target.kind))
            continue
        try:
            detail = send_to(target, wanted, names, dashboard, digest=digest)
            report["sent"].append({"target": target.name or target.kind, "detail": detail,
                                   "events": len(wanted)})
            for event in wanted:
                event.notified = True
        except AlertError as exc:
            report["errors"].append("%s: %s" % (target.name or target.kind, exc))

    if report["sent"]:
        for event in interesting:
            if event.notified and event.detail.get("event_id"):
                store.mark_notified(int(event.detail["event_id"]))
    return report


def test_target(target: AlertTarget, dashboard: str = "") -> str:
    """`nocdeck alert test <name>` — prove the credentials before trusting them."""
    sample = [Event(at=iso(), device_id="demo-sw-01", kind="down", severity="critical",
                    subject="device", message="TEST — demo-sw-01 is down (this is a test)")]
    return send_to(target, sample, {"demo-sw-01": "demo-sw-01"},
                   dashboard, digest=False)


def summarise_targets(config) -> List[str]:
    lines: List[str] = []
    for target in config.alert_targets:
        where = (target.chat_id or ",".join(target.to) or target.url or target.server)
        lines.append("%-10s %-22s %s%s" % (target.kind, target.name or "", where,
                                           "" if target.enabled else "  (disabled)"))
    return lines
