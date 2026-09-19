#!/usr/bin/env python3
"""
Tests for the spectral overlay's sample grid.

The spectral view plots one trace per attack family and an STFT of their
aggregate.  Both are only meaningful on a grid that is *uniform in time* — an
STFT frame is a window of equal-width time bins — so these tests pin two things:
the spacing per mode (10 s simulated, 60 s live), and the sample count that
follows from it (361 for a 60-minute pre-gate window, 61 for the escalated feed).

A grid rebuilt from the non-empty rows would pass neither: it would drift off the
bucket lattice the aggregation truncates to, and it would hand the transform a
sparse series instead of the real samples.

Runs two ways::

    python backend/api/test_bucket_grid.py
    pytest backend/api/test_bucket_grid.py -q
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.api.bucket_grid import (  # noqa: E402
    FIRST_SEEN_FORMAT,
    LIVE_BUCKET_SECONDS,
    SIMULATED_BUCKET_SECONDS,
    align_to_bucket,
    bucket_grid,
    bucket_iso_format,
    bucket_labels,
    bucket_seconds_for,
    parse_first_seen,
)

START = datetime(2026, 9, 18, 10, 1, 37)


def test_granularity_is_a_property_of_the_mode():
    assert bucket_seconds_for("simulated") == SIMULATED_BUCKET_SECONDS == 10
    assert bucket_seconds_for("live") == LIVE_BUCKET_SECONDS == 60
    # Anything unrecognised must not silently become a 10 s grid.
    assert bucket_seconds_for("nonsense") == LIVE_BUCKET_SECONDS


def test_sixty_minutes_at_ten_seconds_is_361_real_samples():
    """The headline contract: 360 ten-second intervals, both endpoints included."""
    grid = bucket_grid(START, 60, SIMULATED_BUCKET_SECONDS)
    assert len(grid) == 361
    assert (grid[-1] - grid[0]) == timedelta(minutes=60)


def test_live_stays_at_one_minute():
    grid = bucket_grid(START, 60, LIVE_BUCKET_SECONDS)
    assert len(grid) == 61
    assert (grid[-1] - grid[0]) == timedelta(minutes=60)


def test_grid_has_no_gaps_and_no_uneven_steps():
    """An STFT frame is only a spectrum if every bucket is the same width."""
    for seconds, expected in ((10, 361), (60, 61)):
        grid = bucket_grid(START, 60, seconds)
        steps = {(b - a).total_seconds() for a, b in zip(grid, grid[1:])}
        assert steps == {float(seconds)}, (seconds, steps)
        assert len(grid) == expected


def test_grid_anchors_on_the_bucket_lattice_the_aggregation_truncates_to():
    """A 10 s grid starts at :00, :10, ... and a 1 min grid at :00."""
    for seconds in (10, 60):
        grid = bucket_grid(START, 5, seconds)
        assert {g.second % seconds for g in grid} == {0}
        assert all(g.microsecond == 0 for g in grid)
    assert bucket_grid(START, 5, SIMULATED_BUCKET_SECONDS)[0] == datetime(2026, 9, 18, 10, 1, 30)
    assert bucket_grid(START, 5, LIVE_BUCKET_SECONDS)[0] == datetime(2026, 9, 18, 10, 1, 0)


def test_alignment_never_places_a_sample_after_the_window_start():
    """Anchoring floors, so the newest sample is never future-dated."""
    for seconds in (10, 30, 60):
        origin = align_to_bucket(START, seconds)
        assert origin <= START
        assert (START - origin) < timedelta(seconds=seconds)
        # Idempotent: aligning an already-aligned instant changes nothing.
        assert align_to_bucket(origin, seconds) == origin


def test_grid_length_follows_the_requested_window():
    assert len(bucket_grid(START, 5, SIMULATED_BUCKET_SECONDS)) == 31
    assert len(bucket_grid(START, 15, SIMULATED_BUCKET_SECONDS)) == 91
    assert len(bucket_grid(START, 5, LIVE_BUCKET_SECONDS)) == 6
    # Degenerate input still yields one usable sample rather than an empty axis.
    assert len(bucket_grid(START, 0, SIMULATED_BUCKET_SECONDS)) == 1


def test_labels_keep_seconds_at_sub_minute_granularity():
    """Six 10 s samples inside one minute must not all print as the same clock."""
    on_the_minute = datetime(2026, 9, 18, 10, 1, 0)
    labels = bucket_labels(bucket_grid(on_the_minute, 1, SIMULATED_BUCKET_SECONDS), SIMULATED_BUCKET_SECONDS)
    within_minute = [l for l in labels if l.startswith("2026-09-18T10:01:")]
    assert len(within_minute) == 6
    assert len(set(within_minute)) == 6
    assert within_minute == [f"2026-09-18T10:01:{s:02d}" for s in range(0, 60, 10)]
    # The unaligned case keeps its seconds too: a 10 s grid floors, never rounds.
    assert bucket_labels(bucket_grid(START, 1, SIMULATED_BUCKET_SECONDS), SIMULATED_BUCKET_SECONDS)[0] == "2026-09-18T10:01:30"


def test_labels_are_unique_and_sort_chronologically():
    """The dashboard sorts and de-duplicates these as strings."""
    for seconds in (10, 60):
        labels = bucket_labels(bucket_grid(START, 60, seconds), seconds)
        assert len(labels) == len(set(labels))
        assert labels == sorted(labels)


def test_label_format_carries_seconds_only_below_a_minute():
    assert bucket_iso_format(10).endswith(":%S")
    assert bucket_iso_format(60).endswith(":00")
    try:
        bucket_iso_format(90)
    except ValueError:
        pass
    else:  # pragma: no cover - the format would be ambiguous
        raise AssertionError("a 90 s bucket should be rejected, not formatted")


def test_parse_first_seen_handles_both_stored_shapes():
    assert parse_first_seen("2026-09-18 11:01:46") == datetime(2026, 9, 18, 11, 1, 46)
    assert parse_first_seen("  2026-09-18 11:01:46  ") == datetime(2026, 9, 18, 11, 1, 46)
    already = datetime(2026, 9, 18, 11, 1, 46)
    assert parse_first_seen(already) == already


def test_parse_first_seen_drops_garbage_rather_than_defaulting_to_now():
    """A bad timestamp at the live edge would look like an event that never was."""
    for bad in (None, "", "not-a-time", "2026-09-18T11:01:46", 12345, {"$date": "x"}):
        assert parse_first_seen(bad) is None


def test_first_seen_format_is_fixed_width_so_string_order_is_time_order():
    a = datetime(2026, 9, 18, 9, 5, 9).strftime(FIRST_SEEN_FORMAT)
    b = datetime(2026, 9, 18, 10, 0, 0).strftime(FIRST_SEEN_FORMAT)
    assert len(a) == len(b)
    assert a < b


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
