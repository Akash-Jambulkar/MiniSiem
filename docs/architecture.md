# Architecture Deep-Dive

The Mini-SIEM is deliberately built as five composable stages. Each stage is a
plain Python module you can read in a single sitting, so the whole "under the
hood" of a commercial SIEM (Splunk / Sentinel / ELK / Wazuh) becomes visible.

## 1. Collectors — get log lines into memory
File: [`src/collectors/file_tailer.py`](../src/collectors/file_tailer.py)

Two modes:

- **`read_batch(path)`** — reads a whole file, yields lines one at a time.
  Perfect for demos on the bundled `data/samples/*` fixtures.
- **`follow(path)`** — seeks to EOF and polls for new lines every 500ms,
  emulating `tail -f`. This is what you point at `/var/log/auth.log` to run in
  near-real-time.

We deliberately avoid inotify / watchdog for portability; the poll interval is
tunable and CPU cost is negligible for anything short of a busy firewall.

## 2. Parsers — turn strings into structured events
Files: [`src/parsers/`](../src/parsers/)

Every parser normalises to the same envelope (ECS-flavoured):

```json
{
  "timestamp": "2026-03-05T02:14:00+00:00",
  "event_type": "ssh_failed_login",
  "source_ip": "203.0.113.42",
  "user": "root",
  "source": "auth.log",
  "raw": "Mar  5 02:14:00 victim-01 sshd[2000]: Failed password ..."
}
```

Web / Cowrie events add `http_status`, `user_agent`, `command`, etc.

Why a shared schema? Because *every* downstream stage (detection rules, alerts,
dashboard) can then be source-agnostic — the same brute-force rule fires whether
the event came from Linux `auth.log` or the Cowrie honeypot.

## 3. Detection engine — sliding-window rules
File: [`src/detections/engine.py`](../src/detections/engine.py)

Four rule types (see `rules/*.yml`):

| Type            | Semantics                                         | Example rule                          |
|-----------------|---------------------------------------------------|---------------------------------------|
| `threshold`     | ≥N matching events per group in W seconds         | 5 failed SSH logins per IP / 60s      |
| `distinct_users`| ≥N *distinct* field values per group in W seconds | 10 usernames per IP / 10 min (spray)  |
| `conditional`   | ≥N of type A **and** ≥1 of type B in window       | successful brute force                |
| `field_match`   | Single event matches a value / list / regex       | scanner user-agent, admin-path probe  |

State is per-rule + per-group-key `deque`s of `(timestamp, event)` tuples. Every
event trims events older than the window from the front — memory stays bounded
by `active_ips × window × event_rate`.

**Cool-down**: once a rule fires for a group key, it will not fire again for
that key until at least `window_seconds` have passed. Without this, a 20-event
brute-force burst would emit 16 duplicate alerts — real SOCs call this "alert
fatigue" and it's how analysts miss real incidents.

## 4. Threat-intel enrichment — external context
Files: [`src/enrichment/abuseipdb.py`](../src/enrichment/abuseipdb.py) +
[`src/enrichment/cache.py`](../src/enrichment/cache.py)

`AbuseIPDBEnricher.enrich(ip)` returns `{abuse_confidence_score, country_code,
isp, domain, total_reports, usage_type}`.

The SQLite cache keeps lookups **under the 1,000-req/day free-tier ceiling**
(TTL: 24h). If no API key is configured or the request fails, enrichment simply
returns `None` — the pipeline never blocks on external services.

## 5. Alerting — notify humans and files
Files: [`src/alerting/`](../src/alerting/)

Three sinks run in parallel and each is independently opt-in:

- **`ConsoleAlerter`** — Rich-formatted panels for terminal screenshots.
- **`SlackAlerter`** — Block Kit message with fields + severity emoji.
- **`DiscordAlerter`** — Embed with coloured sidebar per severity.

Alerts are additionally written to `data/output/alerts.jsonl` (append-only)
so the Streamlit dashboard can render them.

## Data flow summary

```
raw line ─▶ parser ─▶ event  ─▶ engine.process(event) ─▶ [alerts]
                     │                                    │
                     ▼                                    ▼
              events.jsonl                          enrichment
                                                          │
                                                          ▼
                                                  console / slack / discord
                                                          │
                                                          ▼
                                                    alerts.jsonl ─▶ Streamlit
```
