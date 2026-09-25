# How nocdeck is put together

One rule decides most of this file: **the views are dumb**. The web page and the desktop
window hold no monitoring logic at all. They ask the store for a snapshot and draw it.
Everything a person could argue about — what counts as down, when a warning becomes an
alert, how a rate is computed — lives in the engine, once.

```text
            ┌──────────────┐
   SNMP ────┤  snmp        │  the wire: BER, PDUs, sessions, v1/v2c
   ICMP ────┤  probe       │  ping, TCP port, HTTP(S) + certificate expiry
   TCP ─────┤              │
            └──────┬───────┘
                   │
            ┌──────▼───────┐
            │  mibs        │  what to ask: standard tables, vendor rows, your JSON
            └──────┬───────┘
                   │
            ┌──────▼───────┐     ┌────────────┐
            │  poller      │────▶│  alerts    │  telegram · email · webhook
            │  one cycle   │     └────────────┘
            └──────┬───────┘
                   │  readings, events
            ┌──────▼───────┐
            │  model       │  thresholds, hysteresis, human units — the only rules
            └──────┬───────┘
                   │
            ┌──────▼───────┐
            │  store       │  SQLite: samples, interfaces, events, rollups
            └──┬────────┬──┘
               │        │
        ┌──────▼──┐  ┌──▼──────────┐
        │  web    │  │  desktop    │   both read, neither decides
        └─────────┘  └─────────────┘
```

## Why the SNMP codec is hand-written

`pysnmp` is a fine library and it is 20 dependencies deep. This tool is meant to be
dropped onto a switch closet server with a system Python and no package index, and to
run for years. BER encoding for the eleven types an SNMP client actually needs is about
400 lines, and writing it means the tests can pin the wire format byte for byte —
`tests/test_snmp.py` includes the negative-integer minimal-length case (`-128` is `80`,
not `ff 80`) that real agents are unforgiving about.

The price is paid at SNMP v3: the standard library has no AES or DES, so v3 cannot be
implemented honestly here. Instead of half-supporting it, the tool detects the version
and says "this needs `pysnmp`" — a wrong answer that looks right is worse than a missing
feature.

## The threshold rule

There is one function:

```python
limits.trouble(metric, value)   # → None · "degraded" · "critical"
```

Every metric declares a warning line, and a direction. High-is-bad is the common case
(CPU, temperature, latency), but a battery, a UPS runtime and an optical transceiver are
**low-is-bad**: −28 dBm of light is a problem, 100 % of battery is not. Deciding this per
metric, in one table, is why `model.LOW_IS_BAD` exists and why the poller never compares
numbers itself.

The critical line is the warning line plus (or minus) `critical_bump`, so an operator
who moves a warning line moves the critical one with it instead of finding out later
that the two crossed over.

## Hysteresis, or why one lost packet is not an outage

`failures_to_down` and `successes_to_up` (2 by default) sit between the raw check and the
stored state. A single timeout on a saturated Wi-Fi link is not "down", and a device that
answers once after an outage is not "up" yet. `poller` counts cycles, not seconds, so the
behaviour is the same on a five-second and a five-minute interval.

Flapping is separate: more than `flap_count` state changes inside `flap_window_minutes`
and the device's events get marked as flapping, which is the difference between "this
link needs a cable" and "this link needs an alert that stops shouting".

## Rates from counters

Port traffic comes from 32- or 64-bit octet counters that wrap. A rate is
`(now − before) / Δt`, computed against the *previous* reading of the same port, and a
counter that went backwards (a reboot, or a wrap) produces no sample rather than a
gigantic one. That arithmetic is in `poller`, and `tests/test_engine.py` has the case
with a counter reset in it, because that is the bug that produces a 40 Tbps graph.

## The store

One SQLite file, WAL mode, four tables that matter: `samples` (one row per poll, hot
metrics as columns so the graphs are an index scan), `interfaces` (latest port state),
`events` (append-only), `rollups` (hourly averages kept for a year after raw samples are
pruned). `nocdeck prune` is a policy, not a surprise: 14 days of raw samples, 120 days of
events, 400 days of rollups by default.

## The two views

`web.Dashboard` renders strings; `desktop` builds widgets. Both call
`Dashboard.snapshot()` for the fleet and `store.history()` for a graph, and neither
computes a status. That is why `nocdeck demo` can promise that what you see is what the
real thing does: the demo substitutes the SNMP *client*, one layer below everything that
decides anything, and the rest of the pipeline — thresholds, events, alerts, both
views — is the production code.

The desktop window adds three things the web cannot: a poller on a background thread with
the window staying responsive, a full-screen wall, and a settings tab. It runs offscreen
(`QT_QPA_PLATFORM=offscreen`), which is why 27 of the tests can drive the real window on
a build machine with no display, and why `--shot` can draw the README's screenshots on a
server.

## Adding a vendor without touching Python

`~/.nocdeck/mibs/*.json`:

```json
[
  {"key": "temperature", "label": "Chassis temp", "oid": "1.3.6.1.4.1.9999.1.0",
   "unit": "°C"},
  {"key": "battery", "label": "Battery", "oid": "1.3.6.1.4.1.9999.2.0",
   "unit": "%", "divisor": 10}
]
```

`key` must be one of the canonical metrics (`mibs.CANONICAL`), so a new vendor lands in
the same graphs, the same thresholds and the same alerts as everything else.
