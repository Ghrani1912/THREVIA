#!/usr/bin/env python3
"""
Tests for the radar's threat sampling.

The scope's colour mix used to be decided by database tie order.  Every document
in a micro-batch shares one ``created_at``, and ``find().sort("created_at", -1)``
returns tied documents in whatever order the plan produces -- measured on this
stack, *reverse insertion* order, while the alert writer inserts a batch grouped
by ``(src_ip, attack_type, severity)`` with the Critical/DDoS groups first.  So
"the newest n documents" was each batch's Medium tail, and the radar drew almost
no Critical contacts while ~40% of every batch was Critical.

``_radar_sample`` samples each severity band separately, which makes the
composition of the pool a property of the code rather than of tie order.  These
tests pin that, plus the window and its fallback.

The fake collection below implements only the query shapes ``_radar_sample`` uses
(``severity`` equality, ``created_at`` range, sort, limit), so no MongoDB is
needed.  Importing the API module does need FastAPI, i.e. the API venv::

    backend/api/.venv/Scripts/python.exe backend/api/test_radar_sample.py
    backend/api/.venv/Scripts/python.exe -m pytest backend/api/test_radar_sample.py -q
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.api.main import RADAR_SEVERITY_ORDER, _radar_sample  # noqa: E402

NOW = datetime.utcnow()
FRESH = NOW - timedelta(seconds=10)
STALE = NOW - timedelta(hours=2)


def _doc(severity, src_ip, created_at=FRESH, **extra):
    doc = {"severity": severity, "src_ip": src_ip, "created_at": created_at}
    doc.update(extra)
    return doc


def _matches(doc, query):
    for key, want in query.items():
        if isinstance(want, dict) and "$gte" in want:
            if not (doc.get(key) and doc[key] >= want["$gte"]):
                return False
        elif doc.get(key) != want:
            return False
    return True


def _project(doc, projection):
    """Enough of Mongo's projection semantics for the shapes used here."""
    if not projection:
        return dict(doc)
    included = {k for k, v in projection.items() if v}
    if included:
        keep = set(included)
        if projection.get("_id", 1):
            keep.add("_id")
        return {k: v for k, v in doc.items() if k in keep}
    excluded = {k for k, v in projection.items() if not v}
    return {k: v for k, v in doc.items() if k not in excluded}


class _Cursor:
    def __init__(self, docs, query, projection=None):
        self._docs = [_project(d, projection) for d in docs if _matches(d, query)]
        self._limit = None

    def sort(self, spec):
        # Apply the spec right-to-left so the first key dominates, as Mongo does.
        for key, direction in reversed(list(spec)):
            self._docs.sort(key=lambda d: (d.get(key) is None, d.get(key)),
                            reverse=direction < 0)
        return self

    def limit(self, n):
        self._limit = n
        return self

    def __iter__(self):
        return iter(self._docs if self._limit is None else self._docs[:self._limit])


class _FakeCollection:
    """Just enough of pymongo's Collection for _radar_sample."""

    def __init__(self, docs):
        self.docs = list(docs)
        self.queries = []

    def find(self, query=None, projection=None):
        query = query or {}
        self.queries.append(query)
        return _Cursor(self.docs, query, projection)


# ── The defect ─────────────────────────────────────────────────────────────────

def test_band_dominated_batch_no_longer_hides_critical():
    """The regression: a batch the flat query reads as all-Medium.

    The Medium contacts are built to sort ahead of the Critical ones (as the real
    batches do, the tail being the Medium families), so "newest 6" sees one band
    only.  Sampling per band cannot be evicted that way.
    """
    docs = [_doc("Medium", f"10.0.0.{i}") for i in range(40)]          # sorts first
    docs += [_doc("Critical", f"192.168.{i}.1") for i in range(20)]

    flat = _radar_sample(_FakeCollection(docs), 6, None)[0]
    assert {d["severity"] for d in flat} == {"Medium"}, (
        "the flat query is expected to be band-dominated; that is the bug"
    )

    pool = _radar_sample(_FakeCollection(docs), 6, None, bands=RADAR_SEVERITY_ORDER)[0]
    seen = {d["severity"] for d in pool}
    assert seen == {"Critical", "Medium"}, seen
    assert sum(1 for d in pool if d["severity"] == "Critical") == 2


def test_every_band_present_gets_a_share():
    """Three populated bands, budget split three ways."""
    docs = ([_doc("Critical", f"192.168.0.{i}") for i in range(9)]
            + [_doc("High", f"172.16.0.{i}") for i in range(9)]
            + [_doc("Medium", f"10.0.0.{i}") for i in range(9)])
    pool = _radar_sample(_FakeCollection(docs), 9, None, bands=RADAR_SEVERITY_ORDER)[0]
    counts = {sev: sum(1 for d in pool if d["severity"] == sev) for sev in RADAR_SEVERITY_ORDER}
    assert counts == {"Critical": 3, "High": 3, "Medium": 3}, counts


def test_missing_band_is_not_an_error():
    """A corpus with no High severity yields a smaller pool, not a failure."""
    docs = [_doc("Critical", "192.168.0.1"), _doc("Medium", "10.0.0.1")]
    pool = _radar_sample(_FakeCollection(docs), 9, None, bands=RADAR_SEVERITY_ORDER)[0]
    assert {d["severity"] for d in pool} == {"Critical", "Medium"}


def test_pool_is_stable_across_identical_calls():
    """The same window must yield the same contacts twice.

    Ties are broken by src_ip precisely so this holds; without a secondary sort
    key the winner among tied documents is the index scan's decision, not ours.
    """
    docs = [_doc("Critical", f"192.168.{i}.1") for i in range(30)]
    col = _FakeCollection(docs)
    first = [d["src_ip"] for d in _radar_sample(col, 6, 5, bands=RADAR_SEVERITY_ORDER)[0]]
    second = [d["src_ip"] for d in _radar_sample(col, 6, 5, bands=RADAR_SEVERITY_ORDER)[0]]
    assert first == second
    assert first == sorted(first), "ties should resolve by src_ip ascending"


# ── The window, and what happens when it is empty ──────────────────────────────

def test_window_excludes_older_contacts():
    docs = ([_doc("Critical", f"192.168.0.{i}", FRESH) for i in range(2)]
            + [_doc("Critical", f"192.168.9.{i}", STALE) for i in range(2)])
    pool, used = _radar_sample(_FakeCollection(docs), 6, 5, bands=RADAR_SEVERITY_ORDER)
    assert used == 5
    assert all(d["created_at"] == FRESH for d in pool), "stale contacts leaked into the window"


def test_empty_window_falls_back_and_says_so():
    """A stopped pipeline is not the same as no alerts.

    The scope must keep showing the last thing that happened rather than emptying
    itself, but it has to report that it did, so nothing downstream claims a
    window the data does not have.
    """
    docs = [_doc("Critical", "192.168.0.1", STALE)]
    pool, used = _radar_sample(_FakeCollection(docs), 6, 1.0 / 3600, bands=RADAR_SEVERITY_ORDER)
    assert used is None, "the fallback must be reported, not hidden"
    assert len(pool) == 1

    pool, used = _radar_sample(_FakeCollection(docs), 6, 5, bands=RADAR_SEVERITY_ORDER)
    assert used is None and len(pool) == 1, "an empty window still falls back"


def test_disabled_window_returns_newest_stored():
    """window_minutes falsy = no window at all, and it reports None."""
    docs = [_doc("Critical", "192.168.0.1", STALE)]
    pool, used = _radar_sample(_FakeCollection(docs), 6, None, bands=RADAR_SEVERITY_ORDER)
    assert used is None and len(pool) == 1


# ── Query shape ────────────────────────────────────────────────────────────────

def test_unstratified_sample_projects_id_free_docs():
    """`_id` must never reach the JSON encoder."""
    col = _FakeCollection([dict(_doc("Nominal", "10.0.0.1"), _id=object())])
    pool, _ = _radar_sample(col, 6, 5)
    assert "_id" not in pool[0]


def test_stratified_sample_issues_one_query_per_band():
    """One query per band, so each band's budget is spent on that band alone."""
    col = _FakeCollection([_doc("Critical", "192.168.0.1")])  # keeps the window non-empty
    _radar_sample(col, 9, 5, bands=RADAR_SEVERITY_ORDER)
    assert [q.get("severity") for q in col.queries] == list(RADAR_SEVERITY_ORDER)
    assert all("created_at" in q for q in col.queries), "every band must share the window"


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
