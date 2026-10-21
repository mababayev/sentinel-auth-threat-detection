"""Deterministic, explainable rules for authorized authentication logs."""
from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    source_ip: str
    username: str
    outcome: str


@dataclass(frozen=True)
class Alert:
    rule: str
    source_ip: str
    username: str
    start: str
    end: str
    count: int
    detail: str

    def to_dict(self):
        return asdict(self)


def load_events(path: str | Path) -> list[Event]:
    events = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"timestamp", "source_ip", "username", "outcome"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"CSV requires columns: {', '.join(sorted(required))}")
        for row_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("timestamp needs timezone")
                ip, username = row["source_ip"].strip(), row["username"].strip()
                outcome = row["outcome"].strip().lower()
                if not ip or not username or outcome not in {"success", "failure"}:
                    raise ValueError("invalid IP, username, or outcome")
                events.append(Event(timestamp, ip, username, outcome))
            except (ValueError, AttributeError, TypeError) as exc:
                raise ValueError(f"Invalid CSV row {row_number}: {exc}") from exc
    return sorted(events, key=lambda e: e.timestamp)


def detect(events: list[Event], window_minutes: int = 10,
           brute_threshold: int = 5, spray_threshold: int = 5,
           success_threshold: int = 3) -> list[Alert]:
    if min(window_minutes, brute_threshold, spray_threshold, success_threshold) < 1:
        raise ValueError("window and thresholds must be positive")
    window = timedelta(minutes=window_minutes)
    ordered = sorted(events, key=lambda e: e.timestamp)
    alerts: list[Alert] = []
    emitted: set[tuple[str, str, str]] = set()

    for event in ordered:
        recent = [e for e in ordered if event.timestamp - window <= e.timestamp <= event.timestamp]
        failures = [e for e in recent if e.outcome == "failure"]
        pair = [e for e in failures if e.source_ip == event.source_ip and e.username == event.username]
        source = [e for e in failures if e.source_ip == event.source_ip]

        def add(rule: str, username: str, relevant: list[Event], detail: str):
            key = (rule, event.source_ip, username)
            if key in emitted:
                return
            emitted.add(key)
            alerts.append(Alert(rule, event.source_ip, username,
                                relevant[0].timestamp.isoformat(), event.timestamp.isoformat(),
                                len(relevant), detail))

        if event.outcome == "failure":
            if len(pair) >= brute_threshold:
                add("brute_force", event.username, pair, "Repeated failed logins to one account")
            if len({e.username for e in source}) >= spray_threshold:
                add("password_spray", "*", source, "Failed logins across multiple accounts")
        elif event.outcome == "success":
            # Only failures strictly before the success count as prior failures.
            prior = [e for e in pair if e.timestamp < event.timestamp]
            if len(prior) >= success_threshold:
                add("success_after_failures", event.username, prior,
                    "Successful login after repeated failures")
    return alerts
