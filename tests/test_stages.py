"""Detection, correlation, log quality and metrics behave as documented."""

from datetime import datetime, timedelta, timezone

from triage_lab.correlate import correlate
from triage_lab.detections import Alert, load_rules, run_behavioural, run_signatures
from triage_lab.log_quality import LogQuality
from triage_lab.metrics import confusion
from triage_lab.schema import Event

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def ev(i, minutes, source, etype, user="bob.smith", **fields):
    t = T0 + timedelta(minutes=minutes)
    return Event(id=f"E{i}", ts=t.isoformat(), ingest_ts=(t + timedelta(seconds=10)).isoformat(),
                 source=source, event_type=etype, user=user, host="WS-BOB", src_ip="198.51.100.9", fields=fields)


CHAIN = [
    ev(1, 0, "email", "email_link_click", sender_internal=False, url="https://x.io", domain_age_days=3),
    ev(2, 10, "identity", "signin", result="success", device_new=True, country_new=False, country="AU"),
    ev(3, 20, "endpoint", "process_create", image="C:\\Windows\\System32\\net.exe",
       cmdline='net group "Domain Admins" /domain'),
    ev(4, 30, "cloud", "object_access", bucket="finance-reports", operation="GetObject", object_count=50),
]


def test_sigma_rules_fire_on_expected_events():
    alerts = run_signatures(CHAIN, load_rules())
    fired = {a.rule_id for a in alerts}
    assert "DET-001" in fired and "DET-004" in fired
    assert "DET-002" not in fired      # same country: below the signature's bar
    assert "DET-005" not in fired      # 50 objects: below the 100 threshold


def test_backup_account_is_filtered():
    e = ev(9, 0, "cloud", "object_access", user="svc-backup", bucket="finance-reports",
           operation="GetObject", object_count=900)
    assert not run_signatures([e], load_rules())


def test_behavioural_rule_catches_low_and_slow_chain():
    alerts = run_behavioural(CHAIN, 60)
    assert len(alerts) == 1 and alerts[0].event_ids == ["E1", "E2", "E3", "E4"]


def test_behavioural_rule_needs_order_and_window():
    late = CHAIN[:3] + [ev(4, 90, "cloud", "object_access", bucket="finance-reports",
                           operation="GetObject", object_count=50)]
    assert not run_behavioural(late, 60)


def test_correlation_groups_by_user_and_window():
    a = lambda i, m, user, tech, lvl="medium": Alert(f"A{i}", "R", "t", lvl, "signature", [tech],  # noqa: E731
                                                    (T0 + timedelta(minutes=m)).isoformat(), user, None, [f"E{i}"])
    incs = correlate([a(1, 0, "bob", "T1566.002"), a(2, 30, "bob", "T1069.002"),
                      a(3, 200, "bob", "T1530"), a(4, 5, "alice", "T1530")])
    assert len(incs) == 3
    bob = next(i for i in incs if i.user == "bob" and len(i.alert_ids) == 2)
    assert bob.in_order and bob.risk > next(i for i in incs if i.user == "alice").risk


def test_log_quality_flags_silent_hour():
    evs = [ev(i, i * 6, src, "x", user="bob", **{"sender": "a", "subject": "b", "result": "ok",
                                                  "image": "i", "cmdline": "c", "bucket": "b", "operation": "o"})
           for i in range(40) for src in ("email",)]
    evs += [ev(100 + i, i * 6, "cloud", "x", bucket="b", operation="o") for i in range(10)]   # cloud: first hour only
    evs.sort(key=lambda e: e.ts)
    lq = LogQuality(evs, {"errors_by_source": {}})
    second_hour = T0 + timedelta(hours=1, minutes=10)
    assert lq.window_score("cloud", second_hour, second_hour) < 0.6
    assert lq.window_score("email", second_hour, second_hour) > 0.6


def test_confusion_counts_false_close_as_false_negative():
    c = confusion([(True, "close"), (True, "escalate"), (False, "close"), (False, "escalate")])
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (1, 1, 1, 1)
    assert c["false_close_rate"] == 0.5
