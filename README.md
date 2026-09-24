# Phishing Email Analyzer

A sample toolkit for triaging suspicious emails. It parses message
headers, walks the `Received` chain, and flags common phishing
indicators: `From` vs `Return-Path` mismatch, display-name spoofing,
suspicious URLs, and authentication results (SPF/DKIM/DMARC).

> Sample / educational project for security awareness and SOC triage
> workflows. Parses local `.eml` files only.

## Layout

- `analyzer/headers.py` — header parsing and Received-chain walk (day 1)
- `analyzer/detectors.py` — URL and display-name spoofing detectors (day 2)
- `analyzer/auth.py` — SPF/DKIM/DMARC result parsing (day 2)
- `analyzer/reporter.py` — triage verdict report (day 3)
- `samples/` — example messages (day 3)
- `tests/` — unit tests (day 3)
