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

1. **Known campaign by content**: `mdrfckr_ssh_key_injection` (matches `chattr -ia .ssh` or the key
   comment), `routeros_recon`. Matched by content because long variants have unique fingerprints.
2. **Noise**, only for sessions with no payload activity: `probe_echo_ok`, `recon_single` (exact
   allowlist of read-only recon commands, at most two per session), `empty_upload`, `no_activity`.
3. Everything else is `unknown`.

Payload signals apply to every kind and put the session in the tier 2 queue: dropper pattern
(`wget`/`curl`/`chmod +x`/`bash -c`/`./file`), first-seen upload or download hash, first-seen
tunnel target, first-seen fingerprint of an unclassified session.

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
