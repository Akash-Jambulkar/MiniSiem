# Sample Incident Walkthrough

Running the pipeline against the bundled `data/samples/auth.log` reproduces a
complete SSH compromise. This is the exact narrative you can screenshot for a
portfolio or discuss in an interview.

## Timeline (all timestamps UTC)

| Time (UTC)      | Event                                   | Rule fired                     | Severity  | MITRE ATT&CK |
|-----------------|-----------------------------------------|--------------------------------|-----------|--------------|
| 20:14 – 23:14   | Baseline: 10 legitimate `publickey` logins from `203.0.113.5` / `198.51.100.10` (owner). | — | — | — |
| **02:14:00**    | 20× `Failed password` from `203.0.113.42` at 2-sec cadence. | — | — | Enumeration |
| **02:14:08**    | Threshold crossed — 5 fails in ≤10s.    | `ssh_bruteforce`               | HIGH      | T1110.001    |
| **02:14:45**    | `Accepted password for root` from same IP after 20 fails. | `successful_bruteforce`      | CRITICAL  | T1110 + T1078 |
| **02:15:30**    | `useradd svcbackup UID=0` (backdoor account). | `new_user_after_login`     | HIGH      | T1136.001    |
| **02:22 – 02:26** | 13× fails from a **different** IP `198.51.100.17`, each with a distinct username (`alice, bob, carol, dave, eve, frank, grace, heidi, ivan, judy, mallory, nancy, oscar`). | `password_spraying` | HIGH | T1110.003 |

## Interpretation

- The `203.0.113.42` attacker executed the **full initial-access → persistence
  kill chain in ~90 seconds**. That's the profile of an automated exploitation
  script, not a manual attacker.
- The `198.51.100.17` activity is a *separate* actor probing multiple accounts
  with a short list of passwords per account — classic password spraying to
  avoid per-user lockouts.
- Without correlation, an analyst staring at raw `auth.log` would see ~35
  interleaved lines and easily miss the compromise. The pipeline **collapses
  ~35 events into 4 prioritised alerts**, each tagged with a MITRE technique.

## Investigation next steps (what a SOC analyst would do)

1. **Contain**: block `203.0.113.42` and `198.51.100.17` at the perimeter
   firewall; expire the `root` session; disable the `svcbackup` account.
2. **Enrich**: check AbuseIPDB score, country, ISP for both IPs. Pull historical
   requests from those IPs from the SIEM.
3. **Scope**: hunt for the same IPs across other hosts and any commands the
   attacker ran under the `root` session (would come from `auditd` /
   `execve` telemetry — a natural next log source to add to the pipeline).
4. **Eradicate**: rotate all SSH keys and passwords on the host; look for
   modified `authorized_keys`, cron jobs, systemd units created by
   `svcbackup`.
5. **Lessons learned**: was password-auth even needed on this host? Fail2ban
   installed? SSH exposed publicly by mistake? MFA on the bastion?

## Why this is a good portfolio artefact

- The narrative maps directly to the SOC-analyst day-to-day loop:
  **detect → triage → enrich → escalate → contain**.
- Every alert cites a MITRE technique — the industry's shared vocabulary.
- The rule logic is transparent (YAML, ~10 lines each) and defensible in an
  interview ("why 5 in 60 seconds?" → CrowdSec's published `ssh-bf` scenario).
- The data is synthetic and safe (RFC-5737 IPs), so anyone can reproduce it.
