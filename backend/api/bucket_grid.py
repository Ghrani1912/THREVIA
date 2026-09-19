"""
Spectral-overlay sample grid
============================

The spectral telemetry view draws two things off one series: a trace per attack
family, and a short-time Fourier transform of their aggregate.  Both assume the
series is *uniform in time* -- an STFT frame is a window of equal-width time
bins, and a trace is only readable if equal x-distance means equal elapsed time.
Deriving the x-grid from whichever buckets happened to be non-empty breaks that
assumption silently, so the grid is computed here instead.

Granularity is a property of the source, not a caller-supplied parameter:

  ``simulated``  ``ml_alerts``, every pre-gate ML verdict. Each document carries
                 a real ``first_seen`` event time, so the overlay resolves to
                 10 s.  A 60-minute window is 361 real samples (360 intervals
                 plus both endpoints) instead of 61.
  ``live``       ``stream_alerts``, the escalated feed. Those documents *are*
                 per-minute window aggregates (``WINDOW_SECONDS=60``), so its
                 grid stays at one minute -- 61 samples per 60-minute window.
                 Sampling them faster would only interpolate.

Nothing here talks to MongoDB; ``main.py`` builds the aggregation around the same
constants these helpers derive from, and returns the grid so the dashboard never
has to guess the spacing.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Iterable, Optional, Sequence

# ml_alerts.first_seen is written by alert_writer.aggregate_ml_alerts from the
# per-flow event_time, which the stream simulator stamps as "%Y-%m-%d %H:%M:%S".
# Fixed width, so lexicographic order is chronological order and MongoDB can
# range-match the raw string without converting it first.
FIRST_SEEN_FORMAT = "%Y-%m-%d %H:%M:%S"

MODE_LIVE = "live"
MODE_SIMULATED = "simulated"

LIVE_BUCKET_SECONDS = 60
SIMULATED_BUCKET_SECONDS = 10

# Bucket label formats. Both are ISO-ish so the dashboard can slice a timestamp
# string to a clock face; the sub-minute one keeps seconds so two adjacent
# samples are never printed identically.
_BUCKET_ISO_SUB_MINUTE = "%Y-%m-%dT%H:%M:%S"
_BUCKET_ISO_MINUTE = "%Y-%m-%dT%H:%M:00"


def bucket_seconds_for(mode: str) -> int:
    """Bucket width in seconds for a spectral mode (`simulated` else `live`)."""
    return SIMULATED_BUCKET_SECONDS if mode == MODE_SIMULATED else LIVE_BUCKET_SECONDS


def bucket_iso_format(bucket_seconds: int) -> str:
    """strftime format for a bucket label at this granularity."""
    if bucket_seconds < 60:
        return _BUCKET_ISO_SUB_MINUTE
    if bucket_seconds % 60 == 0:
        return _BUCKET_ISO_MINUTE
    raise ValueError(f"unsupported bucket width: {bucket_seconds}s")


def parse_first_seen(value) -> Optional[datetime]:
    """Parse a stored ``first_seen``, tolerating a real datetime and garbage.

    Malformed rows are dropped rather than defaulted to "now": a bad timestamp
    placed at the live edge would look like an event that never happened.
    """
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value.strip(), FIRST_SEEN_FORMAT)
    except ValueError:
        return None


def align_to_bucket(moment: datetime, bucket_seconds: int) -> datetime:
    """Floor ``moment`` onto the bucket lattice so a grid starts on a bin edge.

    Alignment matters: the aggregation truncates every event to its own bin, and
    a grid anchored off-lattice would label samples half a bin away from the
    buckets they hold.  Anchoring is applied to the whole minute, so a 10 s grid
    starts at :00, :10, ... and a 1 min grid at :00.
    """
    floored = moment.replace(microsecond=0)
    return floored - timedelta(seconds=floored.second % bucket_seconds)


def bucket_grid(start_time: datetime, minutes: int, bucket_seconds: int) -> list[datetime]:
    """Uniform bucket boundaries covering ``minutes``, both endpoints included.

    60 minutes at 10 s -> 361 samples; at 60 s -> 61.
    """
    if bucket_seconds <= 0:
        raise ValueError("bucket_seconds must be positive")
    step = timedelta(seconds=bucket_seconds)
    origin = align_to_bucket(start_time, bucket_seconds)
    samples = max(1, int(minutes) * 60 // bucket_seconds + 1)
    return [origin + i * step for i in range(samples)]


def bucket_labels(grid: Sequence[datetime], bucket_seconds: int) -> list[str]:
    """The grid as the timestamp strings the dashboard plots and labels."""
    fmt = bucket_iso_format(bucket_seconds)
    return [moment.strftime(fmt) for moment in grid]


def window_bounds(grid: Iterable[datetime]) -> tuple[Optional[datetime], Optional[datetime]]:
    """First and last boundary of a grid (both ``None`` for an empty grid)."""
    bounds = list(grid)
    if not bounds:
        return None, None
    return bounds[0], bounds[-1]
