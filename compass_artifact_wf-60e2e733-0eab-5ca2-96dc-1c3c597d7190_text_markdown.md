# Project Plan: A Log Analysis & Threat Detection Pipeline for Your Cybersecurity Portfolio

## TL;DR
- **Build a "Mini-SIEM": a Python-based log analysis and threat-detection pipeline** that ingests SSH/auth, web-server, and (optionally) Windows/Sysmon logs, parses them into structured events, runs a set of detection rules mapped to MITRE ATT&CK, enriches suspicious IPs with threat-intel APIs (AbuseIPDB/VirusTotal/OTX), fires alerts to Slack/Discord, and visualizes results on a dashboard — all containerized with Docker and documented on GitHub. This single project touches nearly every Tier-1 SOC skill hiring managers screen for.
- **Recommended primary project: a detection pipeline fed by a Cowrie SSH honeypot**, because it generates authentic attacker data (real brute-force attempts within minutes of exposure), demonstrates end-to-end thinking (collection → parsing → detection → enrichment → alerting → dashboard), and gives you real screenshots and a genuine incident narrative for interviews.
- **Keep scope tight to finish it:** target 4–8 weeks at ~10 hrs/week, ship a working v1 with 5–8 detection rules before adding stretch goals (ML anomaly detection, cloud deployment, Streamlit UI). A finished, well-documented small project beats an ambitious half-built one every time.

## Key Findings
- **A log-analysis/detection project is the single highest-signal portfolio piece for entry-level SOC roles.** Job postings for SOC Tier-1 consistently demand SIEM familiarity, log analysis, MITRE ATT&CK, incident response, and scripting (Python/Bash) — and a portfolio directly overcomes the "2+ years experience" barrier that blocks certificate-only candidates.
- **You do not need to buy anything.** The entire stack is free: Python, ELK Stack or Wazuh (or a lightweight custom pipeline), Docker, Cowrie honeypot, and free-tier threat-intel APIs. Per AbuseIPDB's official FAQ, "free accounts currently have 1,000 requests/day for both IP check and report actions… Verified webmasters are allowed 3,000 requests/day" (limiter resets 00:00 UTC). VirusTotal's official docs state "The Public API is limited to 500 requests per day and a rate of 4 requests per minute. The Public API must not be used in commercial products or services." AlienVault OTX is free — using an API key "allows 10,000 requests per hour rather than just 1,000 requests per hour" unauthenticated (now operated by LevelBlue Labs). Shodan's billing/Help Center confirm "All Shodan accounts come with a free API plan," and a one-time $49 Membership "unlocks the API with 100 query credits and 100 scan credits per month."
- **Detection logic can start simple and still be realistic.** A rule like "5+ failed SSH logins from one IP within 60 seconds = brute force" is exactly what production SOCs use in their brute-force playbooks. CrowdSec's published leaky-bucket brute-force scenario (`crowdsecurity/ssh-bf`) sets `capacity: 5` / `leakspeed: 10s` — i.e. "if an IP address is doing more than 5 failed authentication in less than 20 seconds, the scenario will be triggered."
- **The differentiator is documentation and framing, not tool complexity.** Employers want to see detection logic explained, MITRE mapping, an architecture diagram, screenshots/GIF, and a clear README. Building a vanilla pipeline teaches you SIEM fundamentals "under the hood," which makes you better at Splunk/Sentinel later.
- **Test data is abundant and safe.** SecRepo, Splunk BOTS (botsv1–v4), EVTX-ATTACK-SAMPLES, and OTRF Security-Datasets provide labeled attack data mapped to ATT&CK — or you can generate your own safely with a Cowrie honeypot in an isolated VM.
- **The #1 way to sink the project is secrets in Git.** Never commit `.env` files or real logs; use `.gitignore`, commit a `.env.example`, and rotate any key that leaks (deleting the commit is not enough — it stays in history).

## Details

### 1. Project Overview & Scope

**What a SIEM is (plain terms):** SIEM = *Security Information and Event Management*. It's software that collects logs from many sources, stores them centrally, and runs rules to spot suspicious activity and raise alerts. Splunk, Microsoft Sentinel, and the ELK Stack are examples. Your project is essentially a **mini-SIEM**: you're building the core loop (collect → parse → detect → alert → visualize) yourself so you understand what commercial SIEMs do internally. As one ELK tutorial puts it, "ELK becomes a SIEM with proper configuration" — the raw log store only becomes a SIEM once you add correlation rules, alerting, and threat-intel enrichment.

**Three project ideas, increasing in complexity:**

**Idea 1 (Simple / warm-up) — "Log Triage Script."** A standalone Python CLI that reads a Linux `auth.log` (or Apache/Nginx access log), parses it with regex into structured events, applies a handful of detection rules (failed-login threshold, top offender IPs), and prints/exports a CSV report plus a matplotlib chart. ~1 week. Good for learning parsing and detection logic. Weakness: no live pipeline, limited "wow" factor.

**Idea 2 (RECOMMENDED PRIMARY) — "Mini-SIEM detection pipeline with honeypot feed."** A modular Python pipeline that:
1. Ingests logs from a **Cowrie SSH honeypot** (which produces real attacker data) and/or sample datasets and local `auth.log`.
2. Parses them into normalized JSON events.
3. Runs a rule engine (YAML-defined rules) covering brute force, port scans, off-hours logins, geo-anomalies, and known-bad IPs.
4. Enriches suspicious IPs via **AbuseIPDB / VirusTotal / OTX**.
5. Sends **Slack/Discord alerts** with context.
6. Ships events to **Elasticsearch + Kibana** (or a Streamlit dashboard) for visualization.
7. Runs via **Docker Compose** and is documented on GitHub with an architecture diagram, screenshots, and a demo GIF.
This is the sweet spot: it showcases Python, data pipelines, APIs, detection engineering, MITRE mapping, containerization, and documentation. ~4–8 weeks.

**Idea 3 (Advanced extension) — "Detection pipeline + ML anomaly detection + web UI + cloud."** Everything in Idea 2 plus an Isolation Forest model for unsupervised anomaly detection, a Flask/Streamlit web UI, SOAR-style automated response (auto-block via firewall/API), and deployment to a cloud VM (AWS EC2/Azure). This is a stretch target — do it only after v1 ships.

**Why the honeypot-fed pipeline (Idea 2) is the best showcase for SOC roles:** It produces a genuine incident narrative ("within minutes of exposing the honeypot, I saw brute-force attempts from X IPs across Y countries; my pipeline detected, enriched, and alerted on them"). That story, plus real screenshots, is exactly what interviewers probe for. It also demonstrates the full SOC workflow — the same detect→triage→enrich→escalate loop analysts run daily.

**Scope boundaries — what it WILL do:**
- Ingest and parse 1–3 log source types (start with SSH/auth logs).
- Run 5–8 documented detection rules mapped to MITRE ATT&CK.
- Enrich IPs with at least one threat-intel API.
- Alert to one channel (Slack or Discord).
- Visualize on one dashboard (Kibana or Streamlit).
- Be reproducible via Docker Compose with a clear README.

**What it WON'T do (explicitly out of scope for v1):**
- Not a production/enterprise SIEM; no HA, no multi-tenant, no massive scale.
- Not real-time sub-second streaming (near-real-time polling is fine).
- No offensive tooling beyond a controlled, authorized lab attack to generate data.
- No handling of real production or personal logs containing PII/secrets.
- Not a replacement for Wazuh/Splunk — it's a learning artifact that demonstrates you understand the internals.

### 2. Learning Outcomes & Skills Demonstrated

**Cybersecurity concepts (with the "why"):**
- **SIEM fundamentals** — you'll understand log collection, normalization, correlation, and alerting because you build each stage yourself.
- **Log parsing / normalization** — turning messy text lines into structured fields (timestamp, source IP, user, event type). Why it matters: every detection depends on clean, queryable data.
- **IOCs (Indicators of Compromise)** — observable artifacts (malicious IPs, hashes, domains) that signal a threat. You'll enrich events against IOC feeds.
- **Detection rules / detection engineering** — codifying "what does bad look like" into logic. Why: this is the core of blue-team work.
- **MITRE ATT&CK mapping** — ATT&CK is a knowledge base of adversary tactics/techniques (e.g., T1110 Brute Force). Mapping rules to it shows you speak the industry's shared language and lets you reason about detection coverage/gaps.
- **Threat intelligence enrichment** — adding context (is this IP known-bad? what's its abuse score?) to prioritize alerts.
- **Alert triage & false positives** — you'll learn tuning thresholds to reduce noise, a daily SOC reality.

**Technical skills:**
- **Python** — parsing, data structures, API calls, scheduling.
- **Regex** — extracting fields from log lines.
- **pandas** — aggregating/counting events (e.g., failed logins per IP per minute).
- **APIs (requests)** — querying threat-intel services, sending webhook alerts.
- **YAML/PyYAML** — externalizing detection rules as config (detection-as-code).
- **Docker / Docker Compose** — packaging the stack so anyone can run it.
- **Git/GitHub + Markdown** — version control and professional documentation.
- **Optional: ELK/Kibana, Streamlit, scikit-learn** — visualization and ML.

### 3. Recommended Tech Stack

**Language: Python 3.11+** — justified because it's the SOC automation lingua franca, has excellent libraries for log parsing (regex, pandas), HTTP (requests), scheduling (schedule/APScheduler), file watching (watchdog), and config (PyYAML, python-dotenv). The user is already comfortable with it.

**Log sources (start with the first, add others as time allows):**
- **Linux auth logs** (`/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL) — SSH login successes/failures; ideal first source, rich attacker signal.
- **Apache/Nginx access logs** — web attacks (scanning, injection probes, credential stuffing).
- **Cowrie honeypot JSON logs** — real attacker sessions, brute force, commands.
- **Windows Event Logs / Sysmon** (via EVTX samples) — Event ID 4625 (failed logon), 4624 (logon), process creation. Adds Windows breadth.
- **Zeek / Suricata** (advanced) — network flow / IDS alerts for port-scan and network detections.

**SIEM/visualization tool — recommendation:**
- **For learning + showcase depth: vanilla ELK Stack (Elasticsearch, Logstash, Kibana) via Docker.** You control parsing and dashboards; you learn SIEM internals. Setup is ~30–45 min with Docker Compose at intermediate level.
- **For a faster, more "enterprise-looking" result: Wazuh** — an open-source SIEM/XDR built on OpenSearch with pre-built agents, MITRE ATT&CK correlation, and dashboards out of the box. Think "pre-built gaming PC" vs. ELK's "build-your-own." Wazuh is more cost-effective/flat-scaling and includes file-integrity monitoring, but its community/integration catalog is smaller than Splunk's.
- **Lightweight alternative: Streamlit dashboard** (pure Python) if you want to avoid running the JVM-heavy Elasticsearch on a small laptop.
- **Splunk Free** is an option (industry-standard skill) but has a daily ingest cap and is heavier; ELK/Wazuh are more portfolio-friendly because they're fully open.

**My pick for the primary project:** Custom Python pipeline + **Elasticsearch/Kibana** for the dashboard, with Cowrie as the data source. This maximizes demonstrated skill (you wrote the detection engine) while still producing polished visuals. If your machine is constrained, swap Kibana for Streamlit.

**Threat-intel APIs (all have free tiers):**
- **AbuseIPDB** — community IP-reputation DB; free tier = 1,000 checks/day (verified webmasters get 3,000/day); returns an "abuse confidence score" 0–100 (100 = definitely malicious). Great primary enrichment source; simple REST + API key. Limiter resets at 00:00 UTC.
- **VirusTotal** — file/URL/IP/domain reputation across 70+ engines; public API is free but "limited to 500 requests per day and a rate of 4 requests per minute" and "must not be used in commercial products or services."
- **AlienVault OTX** — free community threat-intel "pulses"; API key optional but recommended, as it "allows 10,000 requests per hour rather than just 1,000 requests per hour" unauthenticated (operated by LevelBlue Labs).
- **Shodan** — internet-exposure/host data; "All Shodan accounts come with a free API plan" (basic host lookup works free); the one-time $49 Membership "unlocks the API with 100 query credits and 100 scan credits per month" plus search filters.

**Alerting:** Slack Incoming Webhooks or Discord webhooks (both free, dead-simple POST of JSON) — send an alert with IP, rule, severity, MITRE ID, and enrichment. Email via SMTP is a fallback.

**Containerization:** Docker + Docker Compose to run the pipeline + Elasticsearch + Kibana (+ Cowrie) as one reproducible stack.

**Version control/docs:** Git + GitHub, Markdown README, an architecture diagram (draw.io / Excalidraw / Mermaid), screenshots, and a short demo GIF (peek/asciinema/ScreenToGif).

### 4. Step-by-Step Architecture & Build Guide

**High-level data flow (architecture diagram description):**
```
[Log Sources]                 [Collection]        [Processing]         [Detection]           [Response/Output]
 Cowrie honeypot  ─┐
 Linux auth.log    ├─►  Filebeat / Python  ─►  Parser (regex→JSON) ─► Rule engine (YAML) ─┬─► Slack/Discord alert
 Apache/Nginx      │     watchdog tail                 │                     │             ├─► Elasticsearch → Kibana dashboard
 Sample datasets  ─┘                          Threat-intel enrichment◄──────┘             └─► CSV / incident report
                                               (AbuseIPDB/VT/OTX)
```
Draw this as boxes left→right with arrows; label each stage. Put this image at the top of your README.

**Phase 0 — Setup & repo scaffolding (0.5 day).** Goal: clean foundation. Tasks: create GitHub repo, virtualenv, `requirements.txt`, `.gitignore` (add `.env`, `*.log`, `data/raw/`), `.env.example`, and a README skeleton. Outcome: reproducible dev environment.

**Phase 1 — Log ingestion (2–4 days).** Goal: get log lines into the pipeline. Tasks: write a collector that either tails a file (`watchdog` or simple polling) or reads a static sample dataset; support both a "batch" mode (read a file) and a "follow" mode (stream new lines). Pseudocode:
```python
import time
def follow(path):
    with open(path) as f:
        f.seek(0, 2)  # go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5); continue
            yield line
```
Outcome: raw lines flowing into the parser.

**Phase 2 — Parsing / normalization (3–5 days).** Goal: structured events. Tasks: regex-parse each source into a common schema `{timestamp, source_ip, user, event_type, raw}`. Example for SSH failed login:
```python
import re
SSH_FAIL = re.compile(
    r'(?P<ts>\w{3}\s+\d+\s[\d:]+).*sshd.*Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)
def parse(line):
    m = SSH_FAIL.search(line)
    if m:
        return {"event_type": "ssh_failed_login", "user": m.group("user"),
                "source_ip": m.group("ip"), "ts_raw": m.group("ts"), "raw": line.strip()}
```
Tip: normalize to a schema close to Elastic Common Schema (ECS) so Kibana/Elastic integration is clean. Outcome: JSON events ready for detection.

**Phase 3 — Detection rules (4–6 days).** Goal: flag suspicious patterns. Tasks: build a small rule engine that reads YAML rules and applies them over sliding time windows using pandas or `collections.deque`/`Counter`. Example brute-force logic:
```python
from collections import defaultdict, deque
WINDOW, THRESHOLD = 60, 5   # 5 fails / 60s
fails = defaultdict(deque)
def check_bruteforce(ev, now):
    if ev["event_type"] != "ssh_failed_login": return None
    dq = fails[ev["source_ip"]]; dq.append(now)
    while dq and now - dq[0] > WINDOW: dq.popleft()
    if len(dq) >= THRESHOLD:
        return {"rule": "ssh_brute_force", "severity": "high",
                "mitre": "T1110.001", "ip": ev["source_ip"], "count": len(dq)}
```
Outcome: detections with rule name, severity, and MITRE ID. (See §5 for the full rule set.)

**Phase 4 — Threat-intel enrichment (2–3 days).** Goal: add context to flagged IPs. Tasks: query AbuseIPDB (primary), cache results to respect the 1,000/day limit, attach abuse score/country/ISP to the detection. Sketch:
```python
import requests, os
def check_ip(ip):
    r = requests.get("https://api.abuseipdb.com/api/v2/check",
        headers={"Key": os.environ["ABUSEIPDB_KEY"], "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90})
    d = r.json()["data"]
    return {"score": d["abuseConfidenceScore"], "country": d["countryCode"], "isp": d["isp"]}
```
Add a local cache dict/SQLite so repeated IPs don't burn quota. Outcome: enriched alerts (e.g., "score 100, CN, Tencent Cloud → BLOCK").

**Phase 5 — Alerting (1–2 days).** Goal: notify. Tasks: format a Slack/Discord webhook message with rule, IP, count, MITRE ID, enrichment, timestamp; add a severity threshold so only medium+ alerts fire (noise control). Outcome: real-time alerts in your channel (great screenshot).

**Phase 6 — Dashboard (3–5 days).** Goal: visualize. Tasks: ship events to Elasticsearch (bulk API or Filebeat) and build a Kibana dashboard (failed logins over time, top attacker IPs, map by country, alerts by MITRE technique) — or build a Streamlit app with the same charts. Outcome: the visual centerpiece of your portfolio.

**Phase 7 — Dockerize (2–3 days).** Goal: one-command reproducibility. Tasks: `Dockerfile` for the Python app, `docker-compose.yml` for app + Elasticsearch + Kibana (+ Cowrie). Outcome: `docker compose up` runs the whole thing.

**Phase 8 — Documentation & polish (2–3 days).** Goal: make it hireable. Tasks: architecture diagram, screenshots, demo GIF, detection-rule table with MITRE mapping, setup instructions, sample data, and a short write-up of a detected "incident." Outcome: a repo a recruiter can understand in 60 seconds.

**Example detection use cases to implement:** brute-force SSH (§5 R1), suspicious/off-hours login times (R4), port-scan detection (R5), malicious-IP lookup/enrichment (R6), failed-login threshold alerting (R1/R2), geo-anomaly / impossible-travel (R7).

### 5. Sample Detection Rules / Use Cases (with MITRE mapping)

1. **SSH brute force** — "≥5 failed SSH logins from the same source IP within 60 seconds." → **T1110.001 Password Guessing** (Credential Access, TA0006). This mirrors real SOC brute-force playbooks (cf. CrowdSec's `ssh-bf`: capacity 5, leakspeed 10s).
2. **Successful brute force** — "≥5 failed auth events **and** ≥1 successful auth from the same IP in the window." A high-severity escalation; based directly on CrowdSec's conditional scenario. → **T1110** + **T1078 Valid Accounts**.
3. **Password spraying** — "One source IP tries many *different* usernames with few attempts each across a longer window (e.g., 10+ distinct users in 10 min)." → **T1110.003 Password Spraying**.
4. **Off-hours / anomalous login time** — "Successful login outside a defined business-hours window (e.g., 00:00–05:00 local)." → **T1078 Valid Accounts** (possible account misuse).
5. **Port scan detection** — "Single source IP connects to N+ distinct ports/services on a host in a short window (from Zeek/Suricata/firewall logs)." → **T1046 Network Service Discovery**.
6. **Known-bad IP hit (threat-intel)** — "Any source IP with an AbuseIPDB confidence score ≥ 80 (or present in an OTX pulse / VT-flagged)." → generic enrichment; supports **T1595 Active Scanning** / initial access triage.
7. **Geo-anomaly / impossible travel** — "Two successful logins for the same user from geographically distant countries within a time too short to travel." → **T1078 Valid Accounts**.
8. **Web credential stuffing / login abuse** — "Many failed POST /login (HTTP 401/403) from one IP in a short window in Nginx/Apache logs." → **T1110.004 Credential Stuffing**.
9. **Suspicious user-agent / scanner fingerprint** — "Access-log requests with tool user-agents (curl, python-requests, sqlmap, nikto) hitting sensitive paths." → **T1059 / T1595**.
10. **New-user creation after brute force** — "useradd/adduser event shortly after a successful login from a flagged IP." → **T1136 Create Account** (Persistence).

Present these in your README as a table: Rule | Logic | Log source | Severity | MITRE technique. Detection engineers use the **Sigma** format (a generic YAML rule language) for exactly this — a stretch goal is to write your rules as Sigma and reference the public Sigma rule repos (SigmaHQ; mdecrevoisier's SIGMA-detection-rules maps 350+ rules to ATT&CK).

### 6. Project Structure (repo layout)

```
mini-siem/
├── README.md                  # overview, architecture diagram, screenshots, setup
├── .gitignore                 # .env, *.log, data/raw/, __pycache__/
├── .env.example               # variable NAMES only, no values
├── requirements.txt
├── docker-compose.yml
├── Dockerfile
├── docs/
│   ├── architecture.png       # data-flow diagram
│   ├── screenshots/           # Kibana dashboard, Slack alert, terminal
│   └── demo.gif               # 20–30s walkthrough
├── src/
│   ├── collectors/            # file tailer, cowrie reader
│   ├── parsers/               # regex parsers per source
│   ├── detections/            # rule engine + rule loader
│   ├── enrichment/            # abuseipdb.py, virustotal.py, otx.py (+ cache)
│   ├── alerting/              # slack.py, discord.py
│   └── main.py                # wires the pipeline together
├── rules/                     # YAML/Sigma detection rules
│   ├── ssh_bruteforce.yml
│   └── ...
├── data/
│   ├── samples/               # small, sanitized sample logs (safe to commit)
│   └── raw/                   # gitignored real/honeypot logs
└── tests/                     # unit tests for parsers & rules
```

**README best practices for a security portfolio project:**
- One-paragraph "what/why" at the top, then the architecture diagram.
- A "Detections implemented" table with MITRE mapping.
- Screenshots + demo GIF near the top (recruiters skim).
- Copy-paste setup: `git clone`, `cp .env.example .env`, `docker compose up`.
- A short "Sample incident" narrative showing a real detection.
- A "Skills demonstrated" and "Future work" section.
- Include small, **sanitized** sample logs so the project runs without secrets. Never commit real logs.

### 7. How to Generate / Source Test Data

**Public datasets (safe, labeled, free):**
- **SecRepo.com** — curated security data samples (Zeek/Bro, Squid, auth, Windows, malware traffic).
- **Splunk BOTS (Boss of the SOC), botsv1–botsv4** — rich, realistic incident datasets with attack activity; widely used for practice.
- **EVTX-ATTACK-SAMPLES (sbousseaden)** — ~200 Windows EVTX event samples mapped to MITRE ATT&CK at technique level. (mdecrevoisier's companion **EVTX-to-MITRE-Attack** repo provides 270+ Windows IOC indicators classified per tactic/technique.)
- **OTRF Security-Datasets (Mordor project)** — pre-recorded attack telemetry mapped to ATT&CK.
- **mdecrevoisier's SIGMA-detection-rules** — 350+ Sigma rules mapped to ATT&CK for testing your coverage.
- **Stratosphere IPS datasets** — netflow/pcap/logs from real malware captures.
- **CyberDefenders / Blue Team Labs Online** — guided blue-team exercises with data.

**Generate your own safely:**
- **Cowrie honeypot** — a medium/high-interaction SSH & Telnet honeypot (maintained by Michel Oosterhof) that logs brute-force attempts and full attacker shell sessions to JSON. Run it in an **isolated VM**; it produces authentic attack data. Warning: if you deliberately expose it to the internet you'll get real attacks within minutes — only do so on a disposable cloud VM you own, on a non-standard admin port, isolated from anything valuable.
- **Controlled lab attack** — spin up a Kali attacker VM + Ubuntu victim VM on an isolated host-only network; run an authorized brute-force (e.g., hydra) against your own SSH to generate `auth.log` entries. Only attack systems you own.
- **Synthetic log generator** — write a small Python script that emits realistic fake log lines (normal + injected attacks) so your pipeline has deterministic test data and you can commit a sanitized sample.

### 8. How to Present This on Resume / GitHub / LinkedIn

**Resume bullet examples (action verb + what + tools + outcome):**
- "Built a Python-based mini-SIEM that ingests and parses SSH/auth and web logs, applies 8 detection rules mapped to MITRE ATT&CK (T1110, T1046, T1078), and enriches suspicious IPs via the AbuseIPDB API."
- "Automated brute-force and port-scan detection with near-real-time Slack alerting, reducing manual log review from hours to seconds on test datasets."
- "Deployed the full stack (detection engine + Elasticsearch + Kibana + Cowrie honeypot) via Docker Compose; documented architecture, detections, and an example investigation on GitHub."
- "Analyzed real attacker telemetry from an internet-exposed Cowrie honeypot, identifying brute-force campaigns from multiple countries and cataloging attacker IOCs."

Use exact keywords ATS systems and recruiters scan for: SIEM, log analysis, MITRE ATT&CK, threat detection, incident response, Python, Splunk/ELK, IOC, threat intelligence, Docker.

**Artifacts to include:** architecture diagram, Kibana/Streamlit dashboard screenshots, a Slack/Discord alert screenshot, a short demo GIF/video, the detection-rule table, and a written incident walkthrough.

**Write-up / blog:** Publish a walkthrough on Medium, Dev.to, or a personal blog (GitHub Pages) explaining the problem, architecture, a detection deep-dive, and lessons learned. Link it from your LinkedIn and resume. A blog post + repo + LinkedIn post triples the visibility of the same work and gives interviewers something concrete to discuss.

### 9. Stretch Goals / Advanced Extensions
- **ML anomaly detection** — add an **Isolation Forest** (scikit-learn) to flag outliers (e.g., unusual login volume/time) without predefined rules. It's unsupervised (no labels needed), runs in near-linear time, and suits high-dimensional log features; tune the `contamination` parameter. Frame it as *augmenting*, not replacing, rule-based detection.
- **SOAR concepts** — add automated response: on a high-severity, high-abuse-score hit, auto-add the IP to a blocklist / call a firewall API (like fail2ban's model). SOAR = Security Orchestration, Automation and Response.
- **Cloud deployment** — deploy the honeypot + pipeline to AWS EC2 or Azure to collect real internet attack data and show cloud skills. Mind cost and isolation.
- **Threat-intel breadth** — add VirusTotal, OTX pulses, and Shodan enrichment with a unified scoring function and caching.
- **Web UI** — build a Streamlit or Flask front-end with live charts, IP drill-downs, and geolocation maps.
- **Sigma rules** — express detections in Sigma format and convert them to Elastic/Splunk queries with the Sigma CLI, demonstrating detection-as-code.

### 10. Learning Resources

**Free hands-on platforms/courses:**
- **TryHackMe — SOC Level 1 path** (recently revamped, practical: alert triage, SIEM, Windows log analysis, threat hunting); many rooms are free.
- **Blue Team Labs Online** — investigation-style blue-team challenges.
- **CyberDefenders** — DFIR/blue-team labs with real datasets; also has a SOC resume guide.
- **Hack The Box (Blue/Defensive tracks)** and **Cybrary** — supplementary.

**Books:**
- *Blue Team Handbook: SOC, SIEM, and Threat Hunting* — Don Murdoch (SOC/SIEM/detection-engineering playbook; updated O'Reilly edition covers a detection-development lifecycle and ATT&CK integration).
- *Practical Threat Detection Engineering* (Packt) — planning, developing, validating detections.
- *Practical Threat Intelligence and Data-Driven Threat Hunting* — ATT&CK + open-source tools.
- *Effective Threat Investigation for SOC Analysts* — examining threats via security logs.
- *Blue Team Field Manual (BTFM)* — tactical command reference aligned to NIST CSF.
- Beginner on-ramps: *Linux Basics for Hackers* (OccupyTheWeb), *Practical Packet Analysis* (Chris Sanders).

**GitHub repos / references:** MITRE ATT&CK (attack.mitre.org), SigmaHQ + mdecrevoisier's SIGMA-detection-rules, EVTX-ATTACK-SAMPLES, OTRF Security-Datasets, Atomic Red Team, "Awesome Threat Detection and Hunting" (0x4d31), Cowrie docs (docs.cowrie.org).

**Tool docs:** Elastic (ELK) docs, Wazuh docs, Cowrie docs, AbuseIPDB API docs, VirusTotal API docs, AlienVault OTX, scikit-learn IsolationForest, Streamlit docs.

### 11. Common Pitfalls & Tips

**What beginners get wrong:**
- **Scope creep** — trying to build a full enterprise SIEM. Ship v1 with 5–8 rules and one dashboard first.
- **No documentation** — an undocumented repo reads as "didn't finish." The README and diagram are half the value.
- **Detection with no explanation** — always explain the logic and threshold and map to MITRE; interviewers ask "why 5 in 60 seconds?"
- **Noisy alerts** — no tuning → alert fatigue. Add severity thresholds and dedup/cooldown.
- **Ignoring false positives** — call out FPs and how you'd tune; this shows analyst maturity.

**Security best practices while building:**
- **Never commit secrets.** Put API keys in a `.env` (gitignored) and load with python-dotenv; commit a `.env.example` with names only. Automated scanners find committed keys within minutes and bots exploit them fast.
- **If a key leaks, rotate it immediately** — deleting the commit is *not* enough; it remains in history/forks. Use `git filter-repo`/BFG to scrub history after rotating.
- **Add local secret scanning** (gitleaks/git-secrets pre-commit hooks) and enable GitHub secret scanning.
- **Never commit real or personal logs** (PII/IP addresses of real users). Commit only small sanitized samples; gitignore `data/raw/`.
- **Isolate the honeypot** — run in a disposable VM, segmented from your real network; if internet-exposed, use a cloud VM you own and never reuse credentials.
- **Don't expose Elasticsearch/Kibana** to the internet unauthenticated (a classic breach source).
- **Only attack systems you own/are authorized to test.**

**Keeping scope manageable so it actually ships:**
- Define "done" for v1 up front (the 6 bullet scope in §1).
- Timebox each phase; commit early and often.
- Get one end-to-end vertical slice working (one source → one rule → one alert) before adding breadth.
- Only start stretch goals after v1 is documented and pushed.

## Recommendations

**Stage 1 (Weeks 1–2): Ship a working vertical slice.** Build Idea 1 → then extend: ingest `auth.log` (or a SecRepo sample), parse SSH failed logins with regex, implement the brute-force rule (R1), and print a report. Benchmark to advance: pipeline correctly flags the known brute-force IP in a sample dataset.

**Stage 2 (Weeks 3–5): Turn it into the mini-SIEM.** Add 4–7 more rules (R2–R8) with MITRE mapping, AbuseIPDB enrichment with caching, and Slack/Discord alerting. Add Cowrie in an isolated VM (or use botsv/EVTX samples) for real data. Benchmark: end-to-end detect→enrich→alert works on live/honeypot data.

**Stage 3 (Week 6): Visualize + containerize + document.** Add the Kibana/Streamlit dashboard, Dockerize with Compose, write the README, diagram, screenshots, and a demo GIF, and publish a blog write-up. Benchmark: a stranger can `docker compose up` and reproduce your results from the README alone. **This is your shippable portfolio artifact — stop here and start applying.**

**Stage 4 (optional, Weeks 7+): Differentiate.** Add one stretch goal that matches your target role — ML anomaly detection (detection-engineer roles), cloud honeypot deployment (security-engineer roles), or Sigma-rule conversion (detection-as-code).

**Thresholds that change the plan:** If Elasticsearch is too heavy for your hardware (it wants a few GB RAM), switch the dashboard to Streamlit and note it in the README — don't let infra block shipping. If you can't safely expose a honeypot, use Splunk BOTS/EVTX datasets instead; the detection logic and write-up are identical in value. If you're short on time, cut to 5 rules and one log source — a finished 5-rule project beats an unfinished 10-rule one.

## Caveats
- **Some cited numbers may drift.** API free-tier limits change; AbuseIPDB (1,000/day free, 3,000/day for verified webmasters), VirusTotal (4/min, 500/day, non-commercial only), OTX (10,000 req/hr with key vs 1,000 without), and Shodan ($49 one-time membership, 100 query + 100 scan credits/mo) were current as of late 2025/2026 per vendor docs, but verify on each provider's site before relying on them. VirusTotal does not officially publish a monthly cap for the public tier, and Shodan's exact *free* query-credit number is not officially published (third-party sources cite ~50–100/month).
- **Wazuh vs ELK vs Splunk is a judgment call, not a rule.** My recommendation (custom Python + ELK/Kibana) optimizes for demonstrated skill; if your target job lists Splunk or Sentinel specifically, prioritize hands-on time in that tool instead.
- **Several supporting sources are individual blog posts/Medium walkthroughs**, which are useful for how-to detail but are not authoritative; the framework/tool facts are anchored to primary docs (MITRE, Cowrie, AbuseIPDB, scikit-learn, Elastic).
- **Time estimates assume ~10 hrs/week at intermediate level** and will vary with your familiarity with Docker and Elasticsearch specifically, which are the steepest parts of the learning curve.
- **Honeypot/attack activities carry real risk** if misconfigured. Treat isolation and "own-systems-only" as hard rules, not suggestions.
- **Resume metrics should be honest.** Phrases like "reduced review from hours to seconds" must reflect your actual test results; be ready to explain them precisely in interviews.