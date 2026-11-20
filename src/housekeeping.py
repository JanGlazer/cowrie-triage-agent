#!/usr/bin/env python3
"""Honeypot housekeeping: log retention + low-disk alert via Telegram. Stdlib only.

Retention is conservative. A rotated log (cowrie.json.YYYY-MM-DD) is deleted only if
  1. it is older than --days, and
  2. loader.py has read it to the end (stored offset >= file size).
The active cowrie.json and anything not yet ingested are never touched.

Telegram credentials (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID) are read from the environment or
from the TELEGRAM_* lines of ./.env. Other keys in .env (e.g. the Anthropic key) are ignored.

Usage:
    python3 housekeeping.py --dry-run     # show what would happen, change nothing
    python3 housekeeping.py               # real run (cron, hourly)
"""
import argparse
import json
import os
import re
import shutil
import sqlite3
import sys
import time
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("COWRIE_DB", os.path.join(BASE, "data", "cowrie.db"))
LOG_DIR = os.environ.get("COWRIE_LOG_DIR", os.path.expanduser("~/cowrie/var/log/cowrie"))
ROTATED = re.compile(r"^cowrie\.json\.\d{4}-\d{2}-\d{2}$")


def load_env(path, prefix="TELEGRAM_"):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("export "):
                    line = line[7:]
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.startswith(prefix):
                    out[k] = v.strip().strip("\"'")
    except FileNotFoundError:
        pass
    return out


def credentials():
    creds = load_env(os.path.join(BASE, ".env"))
    for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        if os.environ.get(k):
            creds[k] = os.environ[k]
    return creds


def send_telegram(text, creds, timeout=10):
    """True only if Telegram accepted the message. Never raises, never prints the token."""
    token, chat = creds.get("TELEGRAM_BOT_TOKEN"), creds.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        print("telegram: TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set", file=sys.stderr)
        return False
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=json.dumps({"chat_id": chat, "text": text[:4000]}).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception as e:
        print(f"telegram: send failed ({type(e).__name__})", file=sys.stderr)
        return False


def prune(db, log_dir, days, now=None, dry_run=False):
    res = {"deleted": [], "kept_not_ingested": [], "failed": [], "bytes_freed": 0}
    cutoff = (now if now is not None else time.time()) - days * 86400
    for name in sorted(os.listdir(log_dir)):
        if not ROTATED.match(name):
            continue
        path = os.path.join(log_dir, name)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            continue
        if st.st_mtime > cutoff:
            continue
        row = db.execute("SELECT offset FROM ingest_state WHERE inode = ?", (st.st_ino,)).fetchone()
        if row is None or row[0] < st.st_size:
            res["kept_not_ingested"].append(name)
            continue
        if not dry_run:
            try:
                os.unlink(path)
            except OSError:
                res["failed"].append(name)
                continue
            # a freed inode can be reused by a new file: forget our offset for it
            db.execute("DELETE FROM ingest_state WHERE inode = ?", (st.st_ino,))
            db.commit()
        res["deleted"].append(name)
        res["bytes_freed"] += st.st_size
    return res


def check_disk(db, path, min_free_pct, notify, cooldown_hours=24.0, now=None, usage_fn=shutil.disk_usage):
    """Alert when free space drops below the threshold, at most once per cooldown.

    A failed delivery is not recorded, so it is retried on the next run. Recovering above the
    threshold resets the cooldown. Returns (free_pct, alerted).
    """
    now = now if now is not None else time.time()
    total, _used, free = usage_fn(path)[:3]
    free_pct = 100.0 * free / total if total else 0.0
    key = f"disk:{path}"

    if free_pct >= min_free_pct:
        db.execute("DELETE FROM alert_state WHERE key = ?", (key,))
        db.commit()
        return free_pct, False

    row = db.execute("SELECT last_sent FROM alert_state WHERE key = ?", (key,)).fetchone()
    if row and now - row[0] < cooldown_hours * 3600:
        return free_pct, False

    msg = (f"Disk low on honeypot VPS: {free_pct:.1f}% free "
           f"({free / 2**30:.1f} GiB of {total / 2**30:.1f} GiB) on {path}")
    if notify(msg):
        db.execute(
            "INSERT INTO alert_state (key, last_sent) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET last_sent = excluded.last_sent",
            (key, now),
        )
        db.commit()
        return free_pct, True
    return free_pct, False


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--days", type=float, default=30.0, help="delete rotated logs older than this")
    p.add_argument("--path", default="/", help="filesystem to watch for free space")
    p.add_argument("--min-free-pct", type=float, default=20.0)
    p.add_argument("--cooldown-hours", type=float, default=24.0)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    db = sqlite3.connect(DB_PATH, timeout=30)
    db.execute("CREATE TABLE IF NOT EXISTS ingest_state (inode INTEGER PRIMARY KEY, path TEXT, offset INTEGER NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS alert_state (key TEXT PRIMARY KEY, last_sent REAL NOT NULL)")

    res = prune(db, LOG_DIR, args.days, dry_run=args.dry_run)
    verb = "would delete" if args.dry_run else "deleted"
    print(f"prune: {verb} {len(res['deleted'])} file(s), {res['bytes_freed'] / 2**20:.1f} MiB; "
          f"kept (not fully ingested): {len(res['kept_not_ingested'])}")
    if res["failed"]:
        print(f"prune: could not delete {len(res['failed'])} file(s), permissions? {', '.join(res['failed'])}",
              file=sys.stderr)

    creds = credentials()
    if args.dry_run:
        notify = lambda m: (print(f"[dry-run] would send: {m}"), False)[1]  # noqa: E731
    else:
        notify = lambda m: send_telegram(m, creds)  # noqa: E731
    pct, alerted = check_disk(db, args.path, args.min_free_pct, notify, args.cooldown_hours)
    print(f"disk: {pct:.1f}% free on {args.path}" + ("  -> alert sent" if alerted else ""))
    db.close()
    return 1 if res["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
