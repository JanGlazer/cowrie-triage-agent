"""Tests for the loader update: run against a DB created by the OLD schema, like production."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time

import pytest

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, ROOT)
import housekeeping  # noqa: E402

OLD_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session TEXT PRIMARY KEY, src_ip TEXT, src_port INTEGER, dst_port INTEGER, protocol TEXT,
    client_version TEXT, hassh TEXT, start_ts TEXT, end_ts TEXT, duration REAL
);
CREATE TABLE IF NOT EXISTS logins (id INTEGER PRIMARY KEY, session TEXT NOT NULL, ts TEXT NOT NULL,
    username TEXT, password TEXT, success INTEGER NOT NULL, UNIQUE (session, ts, username, password));
CREATE TABLE IF NOT EXISTS commands (id INTEGER PRIMARY KEY, session TEXT NOT NULL, ts TEXT NOT NULL,
    input TEXT, UNIQUE (session, ts, input));
CREATE TABLE IF NOT EXISTS downloads (id INTEGER PRIMARY KEY, session TEXT NOT NULL, ts TEXT NOT NULL,
    url TEXT, shasum TEXT, outfile TEXT, UNIQUE (session, ts, url));
CREATE TABLE IF NOT EXISTS tunnels (id INTEGER PRIMARY KEY, session TEXT NOT NULL, ts TEXT NOT NULL,
    dst_ip TEXT, dst_port INTEGER, UNIQUE (session, ts, dst_ip, dst_port));
CREATE TABLE IF NOT EXISTS ingest_state (inode INTEGER PRIMARY KEY, path TEXT, offset INTEGER NOT NULL);
"""
KEY_A = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2 mdrfckr"
KEY_B = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ other"


def ev(session, eventid, ts, ip="203.0.113.7", **kw):
    d = {"session": session, "protocol": "ssh", "src_ip": ip, "src_port": 40000, "dst_ip": "172.30.0.2",
         "dst_port": 2222, "eventid": eventid, "sensor": "x", "uuid": "same", "timestamp": ts, "message": "m"}
    d.update(kw)
    return json.dumps(d)


def playbook(sid, key, t="2026-11-06T10:00:0"):
    return [
        ev(sid, "cowrie.session.connect", t + "0.000000Z"),
        ev(sid, "cowrie.login.success", t + "2.000000Z", username="root", password="x"),
        ev(sid, "cowrie.command.input", t + "3.000000Z", input=f'echo "{key}">>.ssh/authorized_keys'),
        ev(sid, "cowrie.session.file_download", t + "3.500000Z", url="redir", shasum="a8" * 32),
        ev(sid, "cowrie.session.closed", t + "4.000000Z", duration_ms=37077),
    ]


@pytest.fixture
def app(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    for f in ("loader.py", "schema.sql", "fingerprint.py", "triage.py"):
        shutil.copy(os.path.join(ROOT, f), d / f)
    logs = tmp_path / "logs"
    logs.mkdir()
    return d, logs


def run_loader(app_dir, logs, *args):
    env = dict(os.environ, COWRIE_LOG_GLOB=str(logs / "cowrie.json*"), COWRIE_DB=str(app_dir / "data" / "cowrie.db"))
    r = subprocess.run([sys.executable, "loader.py", *args], cwd=app_dir, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return sqlite3.connect(app_dir / "data" / "cowrie.db")


def write(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


def test_old_db_is_migrated_and_duration_backfilled(app):
    app_dir, logs = app
    (app_dir / "data").mkdir()
    old = sqlite3.connect(app_dir / "data" / "cowrie.db")           # production state: old schema,
    old.executescript(OLD_SCHEMA)                                     # session exists, duration NULL
    old.execute("INSERT INTO sessions (session, src_ip, start_ts, end_ts) VALUES ('s1','203.0.113.7','t','t2')")
    old.execute("INSERT INTO ingest_state VALUES (1, '/x/cowrie.json', 999999)")  # offsets say 'already read'
    old.commit()
    old.close()
    write(logs / "cowrie.json", playbook("s1", KEY_A))

    db = run_loader(app_dir, logs, "--reindex")
    row = db.execute("SELECT duration, fingerprint FROM sessions WHERE session='s1'").fetchone()
    assert row[0] == pytest.approx(37.077)
    assert row[1] and len(row[1]) == 16
    assert db.execute("SELECT COUNT(*) FROM commands").fetchone()[0] == 1       # no duplicates from reindex


def test_idempotent_and_reindex_safe(app):
    app_dir, logs = app
    write(logs / "cowrie.json", playbook("s1", KEY_A) + playbook("s2", KEY_B, t="2026-11-06T11:00:0"))
    db = run_loader(app_dir, logs)
    before = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("sessions", "commands", "logins", "downloads")}
    run_loader(app_dir, logs)
    db = run_loader(app_dir, logs, "--reindex")
    after = {t: db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in before}
    assert before == after == {"sessions": 2, "commands": 2, "logins": 2, "downloads": 2}


def test_same_playbook_different_key_same_fingerprint(app):
    app_dir, logs = app
    lines = playbook("s1", KEY_A) + playbook("s2", KEY_B, t="2026-11-06T11:00:0") + [
        ev("s3", "cowrie.session.connect", "2026-11-06T12:00:00.000000Z"),
        ev("s3", "cowrie.command.input", "2026-11-06T12:00:01.000000Z", input="uname -a"),
        ev("s4", "cowrie.session.connect", "2026-11-06T12:05:00.000000Z"),   # no commands at all
    ]
    write(logs / "cowrie.json", lines)
    db = run_loader(app_dir, logs)
    fp = dict(db.execute("SELECT session, fingerprint FROM sessions"))
    assert fp["s1"] == fp["s2"] and fp["s1"] != fp["s3"] and fp["s4"] is None


def test_uploads_are_recorded(app):
    app_dir, logs = app
    write(logs / "cowrie.json", [
        ev("u1", "cowrie.session.connect", "2026-11-07T04:00:00.000000Z"),
        ev("u1", "cowrie.session.file_upload", "2026-11-07T04:00:05.000000Z", filename="sshd",
           shasum="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", outfile="var/x"),
    ])
    db = run_loader(app_dir, logs)
    assert db.execute("SELECT filename, shasum FROM uploads").fetchall() == [
        ("sshd", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")]


def test_legacy_duration_field_still_works(app):
    app_dir, logs = app
    write(logs / "cowrie.json", [
        ev("o1", "cowrie.session.connect", "2026-11-07T04:00:00.000000Z"),
        ev("o1", "cowrie.session.closed", "2026-11-07T04:00:09.000000Z", duration=9.0),
    ])
    db = run_loader(app_dir, logs)
    assert db.execute("SELECT duration FROM sessions").fetchone()[0] == 9.0


# ---- housekeeping ----

def age(path, days):
    t = time.time() - days * 86400
    os.utime(path, (t, t))


def test_prune_only_old_rotated_and_fully_ingested(app):
    app_dir, logs = app
    write(logs / "cowrie.json.2026-09-01", playbook("a", KEY_A))
    write(logs / "cowrie.json.2026-11-05", playbook("b", KEY_B))
    write(logs / "cowrie.json", playbook("c", KEY_A))
    db = run_loader(app_dir, logs)
    write(logs / "cowrie.json.2026-09-02", playbook("d", KEY_B))   # old, NOT ingested
    for n in ("cowrie.json.2026-09-01", "cowrie.json.2026-09-02", "cowrie.json"):
        age(logs / n, 40)

    dry = housekeeping.prune(db, str(logs), 30, dry_run=True)
    assert dry["deleted"] == ["cowrie.json.2026-09-01"] and (logs / "cowrie.json.2026-09-01").exists()

    res = housekeeping.prune(db, str(logs), 30)
    assert res["deleted"] == ["cowrie.json.2026-09-01"] and res["kept_not_ingested"] == ["cowrie.json.2026-09-02"]
    for survivor in ("cowrie.json", "cowrie.json.2026-11-05", "cowrie.json.2026-09-02"):
        assert (logs / survivor).exists()
    assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 3    # DB keeps everything


def test_prune_reports_permission_errors(app, monkeypatch):
    app_dir, logs = app
    write(logs / "cowrie.json.2026-09-01", playbook("a", KEY_A))
    db = run_loader(app_dir, logs)
    age(logs / "cowrie.json.2026-09-01", 40)

    def deny(p):
        raise PermissionError

    monkeypatch.setattr(os, "unlink", deny)
    res = housekeeping.prune(db, str(logs), 30)
    assert res["failed"] == ["cowrie.json.2026-09-01"] and not res["deleted"]


def usage(pct):
    total = 100 * 2**30
    return lambda path: (total, total - int(total * pct / 100), int(total * pct / 100))


def test_disk_alert_cooldown_reset_and_retry(app):
    app_dir, logs = app
    db = run_loader(app_dir, logs)
    sent = []
    ok = lambda m: (sent.append(m), True)[1]  # noqa: E731
    t0 = 1_000_000.0
    assert housekeeping.check_disk(db, "/", 20, ok, now=t0, usage_fn=usage(50))[1] is False
    assert housekeeping.check_disk(db, "/", 20, ok, now=t0, usage_fn=usage(10))[1] is True
    assert housekeeping.check_disk(db, "/", 20, ok, now=t0 + 3600, usage_fn=usage(9))[1] is False
    assert housekeeping.check_disk(db, "/", 20, ok, now=t0 + 25 * 3600, usage_fn=usage(9))[1] is True
    housekeeping.check_disk(db, "/", 20, ok, now=t0 + 26 * 3600, usage_fn=usage(60))     # recovered
    assert housekeeping.check_disk(db, "/", 20, ok, now=t0 + 26 * 3600 + 1, usage_fn=usage(5))[1] is True
    assert len(sent) == 3

    calls = []
    flaky = lambda m: (calls.append(m), len(calls) > 1)[1]  # noqa: E731
    db.execute("DELETE FROM alert_state")
    assert housekeeping.check_disk(db, "/", 20, flaky, now=1.0, usage_fn=usage(5))[1] is False
    assert housekeeping.check_disk(db, "/", 20, flaky, now=2.0, usage_fn=usage(5))[1] is True


def test_env_loader_only_reads_telegram_keys(tmp_path):
    f = tmp_path / ".env"
    f.write_text('ANTHROPIC_API_KEY=sk-secret\nexport TELEGRAM_BOT_TOKEN="abc"\n# c\nTELEGRAM_CHAT_ID=42\n')
    assert housekeeping.load_env(str(f)) == {"TELEGRAM_BOT_TOKEN": "abc", "TELEGRAM_CHAT_ID": "42"}
