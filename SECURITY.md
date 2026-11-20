# Security and responsible use

## What this project is

A **passive** research honeypot. Cowrie emulates an SSH server and a fake shell; attackers connect
to it on their own. This project only reads the resulting logs and analyses them.

- **No active attacks.** Nothing here scans, probes, counter-attacks or contacts attacker hosts.
- **Payloads are never executed or opened.** Cowrie itself downloads files that attackers request
  with `wget`/`curl` inside the fake shell (that is how payloads are captured); this project never
  fetches, runs or opens them. Captured files stay in Cowrie's download
  directory on the honeypot host, are referred to by SHA-256 only, and are not part of this repository.
  Planned enrichment uses hash lookups only; files are never uploaded to third-party services.
- **Containment.** The honeypot runs in Docker with outbound traffic limited to TCP 80/443, so it
  cannot be used to SSH-scan, brute-force or send mail. The real management SSH runs on a
  separate, non-standard port with key-only authentication.
- **The LLM agent has no ability to act.** Its tools are read-only database queries. It cannot run
  commands, reach the network or send alerts; alerting is plain code.

## Data handling

- The live database, raw logs and captured payloads are **not published**. This repository contains
  code, synthetic test data and aggregate statistics only.
- Attacker IP addresses are not published. Tests use RFC 5737 documentation addresses
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
- Hash prefixes in the README are indicators of compromise observed on this honeypot, shared in
  the usual way for public IOCs.
- Honeypot logs contain credentials attackers tried (mostly default or leaked password lists).
  They are kept on the honeypot host only and deleted by retention after ingestion.
- Secrets (API keys, bot tokens) live in a local `.env` with mode 600, which is git-ignored.
  `.env.example` contains placeholders only.

## Running your own

If you deploy a honeypot, check your hosting provider's acceptable-use policy, restrict egress,
keep the management SSH separate and patched, and never run captured binaries outside an isolated
analysis environment.

## Reporting

If you find a security issue in this code (for example a way to make the agent write to the
database or escape the untrusted-data encoding), please open a GitHub issue without exploit details
or contact the maintainer through the email on their GitHub profile.
