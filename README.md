# Phishing Email Analyzer

A sample toolkit for triaging suspicious emails. It parses message
headers, walks the `Received` chain, and flags common phishing
indicators: `From` vs `Return-Path` mismatch, display-name spoofing,
suspicious URLs, and authentication results (SPF/DKIM/DMARC).

> Sample / educational project for security awareness and SOC triage
> workflows. Parses local `.eml` files only.

## Quick start

```bash
python -m analyzer.reporter  # (or import and call triage)
```

```python
from analyzer.headers import load_eml
from analyzer.reporter import triage, print_report

msg = load_eml("samples/suspicious.eml")
print_report(triage(msg, trusted_domains=["acme.example.com"]))
```

## Layout

- `analyzer/headers.py` — header parsing and Received-chain walk
- `analyzer/detectors.py` — URL and display-name spoofing detectors
- `analyzer/auth.py` — SPF/DKIM/DMARC result parsing
- `analyzer/reporter.py` — triage verdict report
- `samples/` — example messages (run with `pytest`)
- `tests/` — unit tests
