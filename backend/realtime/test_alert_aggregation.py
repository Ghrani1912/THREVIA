#!/usr/bin/env python3
"""
Tests for ML-alert aggregation.

Alert *volume* and alert *rate* are different numbers.  A model whose FPR is
3.65% still looks catastrophic if every false-positive flow is stored as its own
document: one benign host on a 286k-flow Friday batch produces tens of thousands
of rows.  These tests pin the collapse behaviour that keeps the collection
proportional to incidents rather than to packets.

Runs two ways::

    python backend/realtime/test_alert_aggregation.py
    pytest backend/realtime/test_alert_aggregation.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.realtime.alert_writer import aggregate_ml_alerts  # noqa: E402


def _alert(src="10.0.0.1", dst="192.168.1.1", attack_type="Bot",
           severity="High", confidence=0.9, event_time="2026-09-16 10:00:00", **extra):
    doc = {
        "src_ip": src,
        "dst_ip": dst,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": confidence,
        "event_time": event_time,
    }
    doc.update(extra)
    return doc


def test_empty_input_is_a_no_op():
    assert aggregate_ml_alerts([]) == ([], 0)


def test_single_alert_passes_through_with_volume_context():
    docs, raw = aggregate_ml_alerts([_alert()])
    assert raw == 1
    assert len(docs) == 1
    assert docs[0]["flow_count"] == 1
    assert docs[0]["dst_ips"] == ["192.168.1.1"]
    assert docs[0]["dst_ip_count"] == 1


def test_one_benign_host_does_not_become_thousands_of_documents():
    """The headline fix: 5,000 flagged flows from one IP is one alert."""
    flow_alerts = [
        _alert(dst=f"192.168.1.{i % 50}", confidence=0.5 + (i % 7) / 100.0)
        for i in range(5000)
    ]
    docs, raw = aggregate_ml_alerts(flow_alerts)
    assert raw == 5000
    assert len(docs) == 1
    assert docs[0]["flow_count"] == 5000
    assert docs[0]["dst_ip_count"] == 50


def test_groups_split_on_src_ip_attack_type_and_severity():
    alerts = [
        _alert(src="10.0.0.1", attack_type="Bot"),
        _alert(src="10.0.0.1", attack_type="DDoS"),
        _alert(src="10.0.0.1", attack_type="Bot", severity="Critical"),
        _alert(src="10.0.0.2", attack_type="Bot"),
    ]
    docs, raw = aggregate_ml_alerts(alerts)
    assert raw == 4
    assert len(docs) == 4
    assert {tuple([d["src_ip"], d["attack_type"], d["severity"]]) for d in docs} == {
        ("10.0.0.1", "Bot", "High"),
        ("10.0.0.1", "DDoS", "High"),
        ("10.0.0.1", "Bot", "Critical"),
        ("10.0.0.2", "Bot", "High"),
    }


def test_representative_fields_come_from_the_strongest_flow():
    """Averaging confidence would hide the peak evidence for a triage decision."""
    alerts = [
        _alert(confidence=0.42, dst="a", event_time="2026-09-16 10:00:00"),
        _alert(confidence=0.97, dst="b", event_time="2026-09-16 10:05:00"),
        _alert(confidence=0.61, dst="c", event_time="2026-09-16 10:02:00"),
    ]
    docs, _ = aggregate_ml_alerts(alerts)
    assert len(docs) == 1
    assert docs[0]["confidence"] == 0.97
    assert docs[0]["max_confidence"] == 0.97
    assert docs[0]["dst_ip"] == "b"


def test_destination_sample_is_capped_but_the_count_stays_true():
    alerts = [_alert(dst=f"10.1.1.{i}") for i in range(200)]
    docs, _ = aggregate_ml_alerts(alerts, max_dst_samples=5)
    assert len(docs) == 1
    assert len(docs[0]["dst_ips"]) == 5
    assert docs[0]["dst_ip_count"] == 200


def test_destination_sample_deduplicates():
    alerts = [_alert(dst="same") for _ in range(10)]
    docs, _ = aggregate_ml_alerts(alerts)
    assert docs[0]["dst_ips"] == ["same"]
    assert docs[0]["dst_ip_count"] == 1


def test_seen_window_spans_the_group():
    alerts = [
        _alert(event_time="2026-09-16 10:04:00"),
        _alert(event_time="2026-09-16 10:00:00"),
        _alert(event_time="2026-09-16 10:09:00"),
    ]
    docs, _ = aggregate_ml_alerts(alerts)
    assert docs[0]["first_seen"] == "2026-09-16 10:00:00"
    assert docs[0]["last_seen"] == "2026-09-16 10:09:00"


def test_missing_and_malformed_fields_do_not_crash():
    """Streaming batches routinely carry nulls; aggregation must not be the crash."""
    alerts = [
        _alert(confidence=None, dst_ip=None, event_time=None),
        _alert(confidence="not-a-number"),
        _alert(confidence="0.8"),
        {"src_ip": None},
        {},
    ]
    docs, raw = aggregate_ml_alerts(alerts)
    assert raw == 5
    assert sum(d["flow_count"] for d in docs) == 5
    assert all(d["confidence"] is not None for d in docs)


def test_input_alerts_are_not_mutated():
    original = _alert()
    alerts = [original, _alert()]
    aggregate_ml_alerts(alerts)
    assert "flow_count" not in original
    assert "dst_ips" not in original
    assert set(original) == {"src_ip", "dst_ip", "attack_type", "severity",
                             "confidence", "event_time"}


def test_ground_truth_fields_survive_aggregation():
    """The CSV export reads these; aggregation must not drop them."""
    alerts = [_alert(ground_truth_label="1", ground_truth_cat="BENIGN"),
              _alert(ground_truth_label="1", ground_truth_cat="BENIGN")]
    docs, _ = aggregate_ml_alerts(alerts)
    assert docs[0]["ground_truth_label"] == "1"
    assert docs[0]["ground_truth_cat"] == "BENIGN"


# ── Standalone runner ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - report and keep going
            failed += 1
            print(f"  FAIL  {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"  ok    {name}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
