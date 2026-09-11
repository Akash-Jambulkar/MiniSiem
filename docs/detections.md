# Detection Rules — deep dive

Every rule is a YAML file in [`rules/`](../rules). This document explains the
*why* behind each rule: the attacker behaviour it catches, the tuning knobs, and
common false-positive shapes to watch for.

## 1. `ssh_bruteforce` — T1110.001 Password Guessing
**Logic:** ≥5 failed SSH logins from one source IP in a 60-second window.

**Why this threshold?** CrowdSec's published `crowdsecurity/ssh-bf` leaky-bucket
scenario uses `capacity: 5, leakspeed: 10s`. Fewer than 5 attempts/minute is
common human typo behaviour; more than that is almost always automation.

**FPs:** legitimate users after a password rotation; brittle scripts with cached
old creds. Tune by raising `threshold` or shrinking `window_seconds`, or
whitelist your bastion IPs via a companion `field_match` rule.

## 2. `successful_bruteforce` — T1110 + T1078
**Logic:** ≥5 failed logins **followed by** ≥1 accepted login from the same IP
within 120s.

The `conditional` rule type captures the moment an attacker breaks through.
This is the single highest-signal alert in the pipeline: false positives are
rare because a legitimate user rarely fails 5+ times then succeeds inside 2
minutes without a password reset in between.

## 3. `password_spraying` — T1110.003
**Logic:** one source IP fails auth against ≥10 *distinct* usernames within 10
minutes.

Detects the inverse of brute force: few attempts per user, many users. Attackers
use spraying to avoid per-account lockouts. The `distinct_users` rule type
tracks the set of distinct `user` field values per source IP.

## 4. `web_credential_stuffing` — T1110.004
**Logic:** ≥20 POST `/login` requests returning 401/403 from one IP in 60s.

Web equivalent of brute force, using leaked-credential lists. Threshold is
higher (20 vs 5) because web apps have much higher benign login volume than
SSH.

## 5. `suspicious_user_agent` — T1595
**Logic:** access-log user-agent matches
`(sqlmap|nikto|nmap|hydra|masscan|dirbuster|gobuster|wpscan)`.

Cheap, high-signal reconnaissance detection. Attackers *can* change UAs — treat
this as a lower bound on scanner activity, not a comprehensive check.

## 6. `web_admin_probe` — T1595.003
**Logic:** request path matches `.env`, `/wp-admin`, `/phpmyadmin`, `/.git/`,
`/admin/config`, `/actuator`, `/boaform`.

These paths never appear in normal traffic; every hit is either a scanner or a
misconfigured internal tool.

## 7. `new_user_after_login` — T1136.001 Create Account
**Logic:** `useradd` event observed at all.

On a locked-down server, account creation should be a controlled operational
event. Any `useradd` outside a change window is worth reviewing. Combined with
alert 2 (successful brute force), this becomes the classic persistence step of
a full compromise chain.

## 8. `attacker_recon_command` — T1082
**Logic:** Cowrie session command matches
`(uname -a|whoami|id|cat /etc/passwd|wget |curl |chmod \+x)`.

Post-compromise discovery / payload-staging behaviour. The Cowrie honeypot's
JSON stream captures `cowrie.command.input` events verbatim, so we can regex
them exactly like any other field.

## Adding your own rule

1. Copy an existing YAML file in `rules/`.
2. Change `id`, `name`, `description`, `severity`, `mitre` metadata.
3. Pick a `logic.type` from `threshold` / `distinct_users` / `conditional` / `field_match`.
4. Update `match` / `follow_match` predicates.
5. Restart the pipeline — no Python changes needed.

## Rule-writing checklist

- [ ] Does the rule have a MITRE technique + tactic?
- [ ] Is the threshold justified by attacker behaviour, not guesswork?
- [ ] Have you thought about legitimate scenarios that could trigger it?
- [ ] Is severity aligned with actionability? (critical = wake someone up.)
- [ ] Does the rule name read cleanly in a Slack alert?
