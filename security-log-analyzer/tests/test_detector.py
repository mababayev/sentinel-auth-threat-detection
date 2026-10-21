import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from sentinel.detector import Event, detect, load_events


def event(minute, user="alice", outcome="failure", ip="192.0.2.10"):
    return Event(datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(minutes=minute),
                 ip, user, outcome)


class DetectorTests(unittest.TestCase):
    def test_brute_force(self):
        alerts = detect([event(i) for i in range(5)])
        self.assertIn("brute_force", [a.rule for a in alerts])

    def test_password_spray(self):
        alerts = detect([event(i, user=f"user{i}") for i in range(5)])
        self.assertIn("password_spray", [a.rule for a in alerts])

    def test_success_after_failures(self):
        alerts = detect([event(i) for i in range(3)] + [event(4, outcome="success")])
        self.assertIn("success_after_failures", [a.rule for a in alerts])

    def test_no_alert_for_benign(self):
        self.assertEqual(detect([event(0), event(30)]), [])

    def test_window_limits_failures(self):
        self.assertNotIn("brute_force", [a.rule for a in detect([event(i * 20) for i in range(5)])])

    def test_invalid_csv(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.csv"
            p.write_text("timestamp,source_ip,username,outcome\nnot-a-date,192.0.2.1,a,failure\n")
            with self.assertRaisesRegex(ValueError, "row 2"):
                load_events(p)


if __name__ == "__main__":
    unittest.main()
