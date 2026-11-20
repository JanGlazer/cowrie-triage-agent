"""Behavioural fingerprint of a honeypot session (stdlib only).

A hash of the *normalized* command sequence. Two sessions that run the same playbook
with a different SSH key, IP or URL get the same fingerprint, so known campaigns can be
counted by plain code and only novel behaviour needs an LLM.
"""
import hashlib
import re

_SSH_KEY = re.compile(r"ssh-(?:rsa|dss|ed25519)\s+[A-Za-z0-9+/=]{40,}(?:\s+[\w.@-]+)?")
_URL = re.compile(r"(?:https?|ftp|tftp)://[^\s\"'`;|&]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_BLOB = re.compile(r"\b[A-Za-z0-9+/=]{32,}\b")
# Long digit runs: epoch timestamps used as scanner markers (echo 'SSHOLE_'"1793993208899"),
# random IDs. 8+ digits so ports, PIDs and sizes like `head -10` stay visible. No \b here on
# purpose: in SSHOLE_1793993208899 the digits follow '_', which is a word character.
_NUM = re.compile(r"(?<!\d)\d{8,}(?!\d)")
_WS = re.compile(r"\s+")

# SHA-256 of zero bytes: an empty upload, not a payload.
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def normalize(cmd):
    cmd = _SSH_KEY.sub("<SSHKEY>", cmd)
    cmd = _URL.sub("<URL>", cmd)
    cmd = _IPV4.sub("<IP>", cmd)
    cmd = _BLOB.sub("<BLOB>", cmd)
    cmd = _NUM.sub("<NUM>", cmd)
    return _WS.sub(" ", cmd).strip()


def fingerprint(commands):
    """16-hex-char fingerprint, or None when the session ran no commands."""
    if not commands:
        return None
    text = "\n".join(normalize(c) for c in commands)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
