#!/usr/bin/env python3
"""Ingest Cowrie JSON logs into SQLite.

- Incremental: remembers the byte offset per log file, reads only new lines.
- Rotation-safe: offsets are keyed by inode, so a renamed (rotated) file
  is finished from where we left off instead of re-read from the start.
- Idempotent: UNIQUE constraints + INSERT OR IGNORE, so re-running is harmless.
- Stdlib only, no dependencies.

Usage:
    python3 loader.py             # normal incremental run (cron)
    python3 loader.py --reindex   # forget offsets and re-read every log file; safe, used to
                                  # backfill columns added later (duration, fingerprint)

After ingestion, triage.py (tier 1) classifies the newly closed sessions. A triage failure is
printed to stderr and never fails the loader: ingestion is what must not stop.
"""
import glob
import json
import os
import sqlite3
import sys

from fingerprint import fingerprint

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_GLOB = os.environ.get(
    "COWRIE_LOG_GLOB", os.path.expanduser("~/cowrie/var/log/cowrie/cowrie.json*")
)
DB_PATH = os.environ.get("COWRIE_DB", os.path.join(BASE, "data", "cowrie.db"))
SCHEMA = os.path.join(BASE, "schema.sql")


def migrate(db):
    """Bring a database created by an older version up to date (additive only)."""
    cols = {r[1] for r in db.execute("PRAGMA table_info(sessions)")}
    if "fingerprint" not in cols:
        db.execute("ALTER TABLE sessions ADD COLUMN fingerprint TEXT")
    db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_fp ON sessions(fingerprint)")
    db.commit()


def duration_seconds(ev):
    """Cowrie writes duration_ms on this sensor; older versions wrote `duration` in seconds."""
    ms = ev.get("duration_ms")
    if ms is not None:
        return ms / 1000.0
    return ev.get("duration")


def handle(db, ev, touched):
    eid = ev.get("eventid", "")
    s = ev.get("session")
    ts = ev.get("timestamp")
    if not s or not ts:
        return

    # Every event carries the connection metadata; the first one creates the session.
    db.execute(
        "INSERT OR IGNORE INTO sessions (session, src_ip, src_port, dst_port, protocol, start_ts)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (s, ev.get("src_ip"), ev.get("src_port"), ev.get("dst_port"), ev.get("protocol"), ts),
    )

    if eid == "cowrie.client.version":
        db.execute("UPDATE sessions SET client_version = ? WHERE session = ?", (ev.get("version"), s))
    elif eid == "cowrie.client.kex":
        db.execute("UPDATE sessions SET hassh = ? WHERE session = ?", (ev.get("hassh"), s))
    elif eid in ("cowrie.login.success", "cowrie.login.failed"):
        db.execute(
            "INSERT OR IGNORE INTO logins (session, ts, username, password, success) VALUES (?, ?, ?, ?, ?)",
            (s, ts, ev.get("username"), ev.get("password"), int(eid.endswith("success"))),
        )
    elif eid == "cowrie.command.input":
        db.execute(
            "INSERT OR IGNORE INTO commands (session, ts, input) VALUES (?, ?, ?)",
            (s, ts, ev.get("input")),
        )
        touched.add(s)  # its fingerprint must be recomputed
    elif eid == "cowrie.session.file_download":
        db.execute(
            "INSERT OR IGNORE INTO downloads (session, ts, url, shasum, outfile) VALUES (?, ?, ?, ?, ?)",
            (s, ts, ev.get("url"), ev.get("shasum"), ev.get("outfile")),
        )
    elif eid == "cowrie.session.file_upload":
        db.execute(
            "INSERT OR IGNORE INTO uploads (session, ts, filename, shasum, outfile) VALUES (?, ?, ?, ?, ?)",
            (s, ts, ev.get("filename"), ev.get("shasum"), ev.get("outfile")),
        )
    elif eid == "cowrie.direct-tcpip.request":
        db.execute(
            "INSERT OR IGNORE INTO tunnels (session, ts, dst_ip, dst_port) VALUES (?, ?, ?, ?)",
            (s, ts, ev.get("dst_ip"), ev.get("dst_port")),
        )
    elif eid == "cowrie.session.closed":
        db.execute(
            "UPDATE sessions SET end_ts = ?, duration = ? WHERE session = ?",
            (ts, duration_seconds(ev), s),
        )


def ingest(db, path, touched):
    st = os.stat(path)
    row = db.execute("SELECT offset FROM ingest_state WHERE inode = ?", (st.st_ino,)).fetchone()
    offset = row[0] if row else 0
    if offset > st.st_size:  # file truncated or inode reused: start over
        offset = 0

    count = 0
    with open(path, "rb") as f:
        f.seek(offset)
        for line in f:
            if not line.endswith(b"\n"):  # line still being written, pick it up next run
                break
            offset += len(line)
            try:
                handle(db, json.loads(line), touched)
                count += 1
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

    db.execute(
        "INSERT INTO ingest_state (inode, path, offset) VALUES (?, ?, ?)"
        " ON CONFLICT(inode) DO UPDATE SET path = excluded.path, offset = excluded.offset",
        (st.st_ino, path, offset),
    )
    return count


def update_fingerprints(db, sessions):
    for s in sessions:
        cmds = [
            r[0]
            for r in db.execute("SELECT input FROM commands WHERE session = ? ORDER BY ts, id", (s,))
            if r[0] is not None
        ]
        db.execute("UPDATE sessions SET fingerprint = ? WHERE session = ?", (fingerprint(cmds), s))


def main():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=30)
    with open(SCHEMA) as f:
        db.executescript(f.read())
    migrate(db)

    if "--reindex" in sys.argv:
        db.execute("DELETE FROM ingest_state")
        db.commit()
        print("reindex: offsets cleared, re-reading all log files")

    total = 0
    touched = set()
    for path in sorted(glob.glob(LOG_GLOB)):
        n = ingest(db, path, touched)
        db.commit()
        if n:
            print(f"{os.path.basename(path)}: {n} events")
        total += n
    if touched:
        update_fingerprints(db, touched)
        db.commit()
    db.close()
    print(f"done, {total} new events" + (f", fingerprints refreshed for {len(touched)} sessions" if touched else ""))
    run_triage()


def run_triage():
    """Tier 1 hook. Imported here, inside the try, so even a broken triage.py cannot stop ingestion."""
    try:
        import triage

        stats = triage.run(DB_PATH)
        print(f"triage: {triage.summary(stats)}")
    except Exception as e:  # noqa: BLE001 - deliberate: log and carry on
        print(f"triage: FAILED ({type(e).__name__}: {e}); ingestion is unaffected", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
