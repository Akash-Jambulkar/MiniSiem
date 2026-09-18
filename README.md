# 🛡️ Mini-SIEM — Log Analysis & Threat Detection Pipeline

A Python-based **mini Security Information & Event Management (SIEM)** pipeline built
as a hands-on cybersecurity portfolio project. It ingests SSH / web-server /
honeypot logs, parses them into a structured schema, runs a rule engine mapped to
**MITRE ATT&CK**, enriches suspicious IPs with **AbuseIPDB** threat intelligence,
fires alerts to **Slack / Discord**, and visualises the results on a **Streamlit**
dashboard — all reproducible with **Docker Compose**.

https://akash-jambulkar.github.io/MiniSiem/
---

## 🎬 Demo — one command to see it work

```bash
git clone https://github.com/Akash-Jambulkar/MiniSiem
cd MiniSiem
cp .env.example .env       # (optional) fill in ABUSEIPDB_API_KEY / SLACK_WEBHOOK_URL
docker compose up --build
```

Or run natively:

```bash
pip install -r requirements.txt
python -m src.main --input data/samples/auth.log --source ssh --no-enrich
streamlit run src/dashboard/app.py
```

The bundled sample data fires **4 correct alerts** covering brute force, successful
compromise, persistence, and password spraying — no honeypot needed.

---

## 🧭 Architecture

```
┌─────────────┐   ┌────────────┐   ┌────────────┐   ┌──────────────┐   ┌───────────────┐
│ Log sources │──▶│ Collectors │──▶│  Parsers   │──▶│ Detection    │──▶│ Alerting      │
│ auth.log    │   │ file tail  │   │ regex+JSON │   │ engine       │   │ Console/Slack │
│ nginx.log   │   │ batch read │   │ ECS schema │   │ YAML rules   │   │ /Discord      │
│ cowrie.json │   │            │   │            │   │ MITRE map    │   └───────┬───────┘
└─────────────┘   └────────────┘   └────────────┘   └──────┬───────┘           │
                                                          ▼                   ▼
                                          ┌──────────────────────┐   ┌──────────────────┐
                                          │ AbuseIPDB enrichment │   │ Streamlit dash + │
                                          │ (SQLite cache)       │   │ JSONL event log  │
                                          └──────────────────────┘   └──────────────────┘
```

Every stage is a small module you can read in one sitting. See
[`docs/architecture.md`](docs/architecture.md) for the deep dive.

---

## 🎯 Detection rules (mapped to MITRE ATT&CK)

| # | Rule ID                     | Log source     | Logic                                             | Severity | MITRE technique                  |
|---|-----------------------------|----------------|---------------------------------------------------|----------|----------------------------------|
| 1 | `ssh_bruteforce`            | auth.log       | ≥5 failed SSH logins / IP / 60s                   | high     | T1110.001 Password Guessing      |
| 2 | `successful_bruteforce`     | auth.log       | ≥5 fails then ≥1 success from same IP / 120s      | critical | T1110 + T1078 Valid Accounts     |
| 3 | `password_spraying`         | auth.log       | ≥10 distinct usernames from one IP / 10 min       | high     | T1110.003 Password Spraying      |
| 4 | `web_credential_stuffing`   | nginx          | ≥20 POST /login 401/403 from one IP / 60s         | high     | T1110.004 Credential Stuffing    |
| 5 | `suspicious_user_agent`     | nginx          | UA matches sqlmap/nikto/nmap/hydra/masscan/etc.   | medium   | T1595 Active Scanning            |
| 6 | `web_admin_probe`           | nginx          | Request to `.env` / `/wp-admin` / `/.git/` / etc. | medium   | T1595.003 Wordlist Scanning      |
| 7 | `new_user_after_login`      | auth.log       | `useradd` shortly after remote SSH login          | high     | T1136.001 Create Account         |
| 8 | `attacker_recon_command`    | cowrie         | Recon commands (`whoami`, `wget`, …) in session   | high     | T1082 System Information Discovery |

Rules are plain YAML (`rules/*.yml`) — add your own without touching Python.

---

## 📁 Repository layout

```
MiniSiem/
├── README.md                 ← you are here
├── .gitignore                ← .env, raw logs, caches
├── .env.example              ← API-key template (no secrets)
├── requirements.txt
├── Dockerfile
├── docker-compose.yml        ← pipeline + Streamlit dashboard
├── rules/                    ← YAML detection rules (MITRE-mapped)
├── data/
│   ├── samples/              ← safe synthetic logs (RFC-5737 IPs)
│   └── output/               ← JSONL events + alerts (gitignored)
├── src/
│   ├── main.py               ← CLI entrypoint / pipeline wiring
│   ├── collectors/           ← file tail / batch reader
│   ├── parsers/              ← ssh, nginx, cowrie regex/JSON parsers
│   ├── detections/           ← rule engine + YAML loader
│   ├── enrichment/           ← AbuseIPDB + SQLite cache
│   ├── alerting/             ← console (rich), Slack, Discord
│   ├── dashboard/            ← Streamlit UI
│   ├── generators/           ← synthetic log generator
│   └── utils/logger.py
├── tests/                    ← pytest: 15 parser + engine tests
├── docs/
│   ├── architecture.md
│   ├── detections.md
│   └── incident_walkthrough.md
└── website/                  ← GitHub Pages showcase (index.html)
```

---

## 🚀 Getting started

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. (Optional) Configure secrets

Copy `.env.example` → `.env` and fill:

| Variable                | Purpose                                      | Where to get it            |
|-------------------------|----------------------------------------------|----------------------------|
| `ABUSEIPDB_API_KEY`     | IP-reputation enrichment (1,000 checks/day free) | https://www.abuseipdb.com |
| `SLACK_WEBHOOK_URL`     | Slack alert channel                          | Slack Apps → Incoming Webhooks |
| `DISCORD_WEBHOOK_URL`   | Discord alert channel                        | Server Settings → Integrations |

Never commit `.env`. If a key leaks, **rotate it** — deleting the commit is not enough.

### 3. Run the pipeline on bundled sample data

```bash
# SSH brute force + successful compromise + persistence
python -m src.main --input data/samples/auth.log --source ssh --no-enrich

# Web credential stuffing + scanner recon
python -m src.main --input data/samples/nginx_access.log --source nginx --no-enrich

# Cowrie honeypot session (brute force + attacker commands)
python -m src.main --input data/samples/cowrie.json --source cowrie --no-enrich
```

Each run appends structured JSON to `data/output/events.jsonl` and
`data/output/alerts.jsonl`.

### 4. Open the dashboard

```bash
streamlit run src/dashboard/app.py
```

Browse to <http://localhost:8501>.

### 5. Tail a live log

```bash
python -m src.main --input /var/log/auth.log --source ssh --follow
```

### 6. Run the tests

```bash
python -m pytest tests/ -v      # 15/15 pass
```

---

## 🔍 Sample detected "incident"

Running the pipeline on `data/samples/auth.log` (a synthetic attacker session)
produces this **4-alert kill chain**:

1. **02:14:08** — `ssh_bruteforce` **[HIGH — T1110.001]**
   `203.0.113.42` triggered 20 failed logins in ~40 seconds.
2. **02:14:45** — `successful_bruteforce` **[CRITICAL — T1110 + T1078]**
   Same IP successfully authenticated as `root` after brute-forcing.
3. **02:15:30** — `new_user_after_login` **[HIGH — T1136.001]**
   `useradd svcbackup` (UID 0) executed — persistence established.
4. **02:22–02:26** — `password_spraying` **[HIGH — T1110.003]**
   Separate IP `198.51.100.17` sprayed 13 distinct usernames over 4 min.

That narrative — one IP fully compromising a host inside 90 seconds — is exactly
the story SOC analysts investigate every day. See
[`docs/incident_walkthrough.md`](docs/incident_walkthrough.md) for the full breakdown.

---

## 🧪 Add your own detection rule

Create `rules/09_my_rule.yml`:

```yaml
id: off_hours_login
name: Off-Hours Successful Login
description: "Interactive SSH login between 00:00-05:00 local time."
severity: medium
mitre: T1078
mitre_tactic: TA0001   # Initial Access
logic:
  type: field_match
  match:
    event_type: ssh_accepted_login
```

Restart the pipeline — no code changes needed.

---

## 🧠 Skills demonstrated

- **Python**: modular pipelines, generators, dataclass-flavoured schemas.
- **Regex + JSON parsing**: syslog, Combined Log Format, Cowrie JSON.
- **Detection engineering**: threshold / conditional / distinct-value / field-match rules with sliding windows and cool-downs.
- **MITRE ATT&CK**: every rule mapped to a technique + tactic; coverage visible in the dashboard.
- **Threat intelligence**: AbuseIPDB integration with an SQLite cache to respect the 1,000-req/day free tier.
- **Alerting**: Rich-formatted console, Slack blocks, Discord embeds.
- **Data viz**: pandas + Plotly + Streamlit KPI + time-series + MITRE coverage charts.
- **Testing**: 15 pytest cases covering parsers, engine logic, and cool-down behaviour.
- **Packaging**: Dockerfile + Compose for one-command reproduction.
- **Secure engineering**: `.env` handling, cache to protect quotas, RFC-5737 IPs in commited samples, no PII.

---

## 🛣️ Roadmap / stretch goals

- [ ] **Isolation-Forest anomaly detection** (`scikit-learn`) as an unsupervised layer alongside YAML rules.
- [ ] **SOAR-lite auto-response**: on `critical` + high abuse-score, POST the IP to a firewall API.
- [ ] **Sigma rule support**: convert `rules/*.yml` to Sigma so they run in Elastic / Splunk / Sentinel.
- [ ] **ELK / Wazuh output sink** as an alternative to Streamlit.
- [ ] **Cloud honeypot**: expose Cowrie on a disposable AWS EC2 / Azure VM to collect real telemetry.

---

## ⚠️ Safety notes

- Sample logs use **RFC-5737 TEST-NET-1/2/3** IPs — safe to publish.
- Never commit real `auth.log` / production logs; they contain PII and internal IPs.
- If you deploy a **Cowrie honeypot**, isolate it in a disposable cloud VM on a
  non-standard admin port. It **will** be attacked within minutes of exposure —
  never reuse credentials or connect it to your real network.
- Only attack systems you own or are explicitly authorised to test.

---

## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org/) — technique catalogue.
- [Cowrie SSH honeypot](https://docs.cowrie.org/) — Michel Oosterhof.
- [AbuseIPDB API](https://docs.abuseipdb.com/) — IP reputation.
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — detection-as-code rule format.
- [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html).

---

## 📝 Licence

MIT — do anything, no warranty. Feedback and PRs welcome.
