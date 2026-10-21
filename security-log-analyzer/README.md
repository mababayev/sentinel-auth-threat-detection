# Sentinel: Explainable Authentication Threat Detection

A reproducible, defensive cybersecurity project for analyzing authentication logs. Sentinel detects:
- **Password spraying:** one source attempts logins against many accounts within a time window.
- **Brute force:** repeated failures against one account from one source.
- **Success after failures:** a successful login after a suspicious failure burst.

Built with Python's standard library: no cloud accounts, API keys, or third-party packages.

## Quick start

```bash
python -m sentinel.cli examples/auth_events.csv --format table
python -m sentinel.cli examples/auth_events.csv --format json
python -m unittest discover -s tests -v
```

Run from the repository root with `PYTHONPATH=src` set, or install locally:

```bash
python -m pip install -e .
sentinel examples/auth_events.csv --format table
```

## Input schema
CSV columns: `timestamp,source_ip,username,outcome`. Timestamp must be ISO 8601 with a timezone, e.g. `2026-10-01T10:00:00+00:00`; outcome must be `success` or `failure`. Use **synthetic or authorized logs only**.

## Detection rules
Default window: 10 minutes.
- Brute force: >= 5 failed attempts from the same IP against the same username.
- Password spraying: >= 5 distinct usernames failed from the same IP.
- Success after failures: >= 3 failures from the same IP and username followed by a success.

Events are sorted chronologically. Alerts include supporting event counts and time ranges. These are heuristic signals, **not proof of compromise**.

## Limitations
- No geolocation, identity enrichment, or external threat intelligence.
- Shared IPs and corporate NAT can cause false positives.
- Detection thresholds are illustrative, not production-calibrated.
- This is an engineering portfolio demonstration, not published research.

## Suggested next experiments
1. Create labeled benign and attack simulations.
2. Measure precision/recall across different thresholds.
3. Compare sliding windows against session-based detection.
4. Document false positives on a permitted real-world dataset.

## Ethics and authorship
Built with AI assistance. Review, run, modify, and understand the code before presenting it. Do not claim independently authored code or research findings you did not produce.
