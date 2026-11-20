# Deployment notes

Target: a small Linux VPS (2 GB RAM is enough), Docker, Python 3.11+.

1. Run Cowrie in Docker (official image, Compose), JSON logging enabled, logs bind-mounted to the
   host (default path used here: `~/cowrie/var/log/cowrie/cowrie.json*`). Restrict egress first:
   see `docker-egress.md`.
2. Copy the contents of `src/` to `~/honeypot-agent/`.
3. `python3 loader.py` once by hand (creates `data/cowrie.db` from `schema.sql`), then
   `python3 triage.py --report`.
4. Add the cron lines from `crontab.example`.
5. For tier 2: `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`,
   `cp .env.example .env && chmod 600 .env`, add the key, then `agent.py check`,
   `agent.py analyze --dry-run`, `agent.py analyze --limit 1`.

Upgrades are additive: `schema.sql` uses `CREATE TABLE IF NOT EXISTS` and the loader migrates old
databases. Back up `data/cowrie.db` under the loader lock before an upgrade:
`flock /tmp/cowrie-loader.lock cp data/cowrie.db data/cowrie.db.bak`.
After changing fingerprint normalization or tier 1 rules:
`flock /tmp/cowrie-loader.lock python3 loader.py --reindex` then
`flock /tmp/cowrie-loader.lock python3 triage.py --rebuild`.

Not included in this repository: `report.py`, a small read-only listing script used on the
server during development (superseded by `triage.py --report`).
