# Pre-publish sanitization checklist

Run before every push that makes the repository (or a new version of it) public.
Last full check: 2026-11-20 (second pass after the tier 1 rules from the first agent run).

## Checklist

- [x] No secrets: API keys, Telegram bot token/chat id, SSH private keys, cloud keys.
      `.env` is git-ignored; `.env.example` holds placeholders only. Test values are dummies (`sk-ant-test`, `abc`).
- [x] No live data: no `cowrie.db`, `*.bak*` backups, `agent_usage.jsonl`, loader logs, Cowrie JSON logs,
      captured payloads or TTY recordings (all covered by `.gitignore`).
- [x] No infrastructure identifiers: no VPS public IP, management SSH port, hosting account, server
      hostname, Unix username or home path.
- [x] No honeypot fingerprint: the decoy hostname Cowrie presents was removed from the agent prompt,
      so the deployed sensor cannot be identified from this code.
- [x] No real attacker IPs. Code comments and tests use RFC 5737 documentation ranges.
- [x] No personal data beyond the author name in `LICENSE`.
- [x] IOCs: full SHA-256 of the two reviewed malware uploads (README table, `src/triage.py` rule
      constants), published on purpose as IOCs; other captured hashes only as prefixes; the empty-file
      hash. No attacker IPs, staging host or mail server address: rules and docs use placeholders.
- [x] Operator's own IPs: never in code. `self_test` reads `SELF_IPS` or the git-ignored
      `data/self_ips.txt`; examples use RFC 5737 ranges. The `mdrfckr` SSH key fragment in tests is a truncated, widely published campaign IOC.
- [x] Docs state what is done and what is planned; nothing claims an unverified feature.

## Commands used

```bash
# IPv4 addresses (expect only 192.0.2.x, 198.51.100.x, 203.0.113.x, 10.x, 172.x)
grep -rnoE "\b[0-9]{1,3}(\.[0-9]{1,3}){3}\b" . | awk -F: '{print $NF}' | sort | uniq -c
# identifiers (fill in your own VPS IP, port, hostname, username, email)
grep -rniE "<vps-ip>|<ssh-port>|<hostname>|<username>|<email>|/home/" .
# secret shapes
grep -rnE "sk-ant-[A-Za-z0-9_-]{10,}|[0-9]{8,10}:[A-Za-z0-9_-]{35}|AKIA[0-9A-Z]{16}|BEGIN [A-Z ]*PRIVATE KEY" .
# full hashes and SSH keys (review each hit)
grep -rnoE "\b[0-9a-f]{64}\b" . ; grep -rnoE "ssh-(rsa|ed25519) [A-Za-z0-9+/=]{20,}" .
# what git would actually commit
git status --ignored; git ls-files
```

Optional, before going public: `gitleaks detect --source .` or GitHub secret scanning.

## Findings of the 2026-11-20 pass (source: development copies of the code)

| Found | Where | Action |
|---|---|---|
| Decoy hostname of the live honeypot | `agent.py` system prompt | replaced with "a decoy hostname" |
| Real source IP of the high-volume probe | `tests/test_triage.py` | replaced with `198.51.100.61` |
| Real source IP of the recon bot | `triage.py` comment, `tests/test_triage.py` | comment reworded, test IP replaced with `198.51.100.157` |
| Real SMTP tunnel destination | `tests/test_triage.py`, `tests/test_agent.py` | replaced with `192.0.2.25` (port 25 kept) |
| Made-up but routable IPs (`45.x`, `61.x`, `66.x`, `77.x`, `88.x`, `99.x`) | `tests/test_agent.py` | replaced with `203.0.113.x` so no real host is implied |
| VPS IP, SSH port, username, hosting provider | internal deployment notes (`APPLY.md`, `STATE.md`) | notes not included; `deploy/` rewritten generically |
| API key / Telegram token | none found in code | `.env` git-ignored, `.env.example` added |
| `172.30.0.2` | test event fixtures | private Docker address, kept |

Second pass (tier 1 rules from the first agent run): the agent's verdicts named real source IPs, the
staging host and the SMTP target. None of them is in code, tests or docs; the staging URL is matched by
shape (`http://<host>:800/ol.sh`), the SMTP rule by port. Tests use `192.0.2.x`, `198.51.100.x`,
`203.0.113.x` and `2001:db8::` only.

Not included: `report.py` (a small read-only listing script on the server, superseded by
`triage.py --report`), internal state notes, the live database and all logs.
