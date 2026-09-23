#!/usr/bin/env python3
"""
Tests for the online / continual-learning layer.

Every test here answers a way this layer could make the detector *worse* than the
frozen model it sits behind, because that is the only interesting risk: an
adaptation layer that cannot be shown to be bounded, identity-safe, and
rate-controlled is a way to lose an argument with your own telemetry.

Runs two ways::

    python backend/realtime/test_online_learning.py
    pytest backend/realtime/test_online_learning.py -q
"""

from __future__ import annotations

import math
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.realtime.detection_policy import (  # noqa: E402
    Thresholds,
    classify_flow,
    severity_for,
)
from backend.realtime.online_learning import (  # noqa: E402
    N_BINS,
    OnlineLearningConfig,
    OnlineLearningPolicy,
    ScoreReference,
    ks_statistic,
    population_stability_index,
    verdict_label,
)

# The deployed artifact's cut (backend/realtime/thresholds.json).  Using the real
# value matters: the band and the severity rungs are all expressed relative to it.
DEPLOYED_CUT = 0.257502
CRITICAL_RUNG = 0.583068


def _policy(**cfg) -> OnlineLearningPolicy:
    thresholds = Thresholds(
        attack_threshold=DEPLOYED_CUT,
        severity_medium=DEPLOYED_CUT,
        severity_high=0.493131,
        severity_critical=CRITICAL_RUNG,
        source="test",
    )
    config = OnlineLearningConfig(state_path=None, **cfg)
    return OnlineLearningPolicy(thresholds=thresholds, config=config)


def _bell(rng: random.Random, n: int, shift: float = 0.0) -> list[float]:
    """A deterministic, bell-shaped score sample in [0, 1]."""
    out = []
    for _ in range(n):
        v = (rng.random() + rng.random() + rng.random()) / 3.0 + shift
        out.append(min(1.0, max(0.0, v)))
    return out


# ── Distribution statistics ───────────────────────────────────────────────────

def test_psi_and_ks_are_zero_for_identical_distributions():
    rng = random.Random(1)
    scores = _bell(rng, 4000)
    ref = ScoreReference(counts=_hist_counts(scores), n=len(scores))
    dist = ref.distribution()
    assert abs(population_stability_index(dist, dist)) < 1e-12
    assert abs(ks_statistic(dist, dist)) < 1e-12


def test_psi_grows_with_the_size_of_the_shift():
    rng = random.Random(2)
    base = _bell(rng, 4000)
    ref = ScoreReference(counts=_hist_counts(base), n=len(base)).distribution()
    values = []
    for shift in (0.0, 0.1, 0.25):
        sample = _bell(random.Random(2), 4000, shift=shift)
        values.append(population_stability_index(ref, _as_dist(_hist_counts(sample))))
    assert values[0] < values[1] < values[2]
    assert values[0] < 0.10, "an unshifted resample must not read as drift"


def _hist_counts(scores) -> list[int]:
    counts = [0] * N_BINS
    for p in scores:
        counts[min(N_BINS - 1, max(0, int(p * N_BINS)))] += 1
    return counts


def _as_dist(counts: list[int]) -> list[float]:
    total = float(sum(counts))
    return [c / total for c in counts]


def test_verdict_parsing_covers_both_polarities_and_rejects_nonsense():
    assert verdict_label("confirmed") == 1
    assert verdict_label("FALSE-POSITIVE") == 0
    assert verdict_label(" False Positive ") == 0
    assert verdict_label(1) == 1
    assert verdict_label("maybe") is None
    assert verdict_label(None) is None


# ── Identity safety ───────────────────────────────────────────────────────────

def test_layer_is_exactly_the_identity_before_any_evidence():
    """Shipping the layer must not change one alert until evidence exists."""
    policy = _policy()
    for p in (0.0, 0.01, DEPLOYED_CUT, 0.5, 0.999, 1.0):
        assert policy.adapt_score(p, None) == p, "no-evidence must be bit-exact identity"
        assert policy.shift_for(p) == 0.0
    assert policy.calibrator.updates == 0


def test_disabled_policy_is_a_passthrough_at_the_calibrated_cut():
    policy = _policy(enabled=False)
    policy.observe([0.9] * 500, batch_id=1, alert_count=100)
    policy.observe([0.9] * 500, batch_id=2, alert_count=100)
    assert policy.effective_threshold() == DEPLOYED_CUT
    assert policy.adapt_score(0.4) == 0.4


def test_cold_start_keeps_the_calibrated_anchor_and_bootstraps_a_reference():
    policy = _policy()
    record = policy.observe(_bell(random.Random(3), 500), batch_id=0, alert_count=10)
    assert policy.reference.source.startswith("bootstrap")
    assert policy.reference.n == 500
    assert policy.effective_threshold() == DEPLOYED_CUT
    assert record["threshold"] == DEPLOYED_CUT
    assert record["drift"] == "stable"


# ── Rate control ──────────────────────────────────────────────────────────────

def test_budget_controller_holds_the_alert_rate_when_the_score_scale_shifts():
    """The failure this layer exists to prevent: a fixed cut on shifted scores.

    Scores move up by 0.15 mid-stream.  The calibrated cut keeps flagging at the
    old rate (a flood); the adapted cut moves up and holds the budget.

    The ladder ceiling is raised for this test so it measures the controller
    rather than the band: on this shifted distribution the cut the budget demands
    is above the High rung, so with the default ceiling it would (correctly)
    saturate instead -- see test_budget_controller_stays_inside_the_band...
    """
    policy = _policy(target_alert_rate=0.05, window_size=1000, warmup_batches=1,
                     threshold_ceiling=1.0)
    rng = random.Random(7)
    for batch in range(6):
        policy.observe(_bell(rng, 500), batch_id=batch, alert_count=25)
    cut_before = policy.effective_threshold()

    latest: list[float] = []
    for batch in range(6, 20):
        latest = _bell(rng, 500, shift=0.15)
        policy.observe(latest, batch_id=batch, alert_count=25)

    cut_after = policy.effective_threshold()
    adapted_rate = sum(1 for p in latest if p >= cut_after) / len(latest)
    frozen_rate = sum(1 for p in latest if p >= DEPLOYED_CUT) / len(latest)

    assert cut_after > cut_before, "a sustained upward shift must raise the cut"
    assert frozen_rate > 0.15, "sanity: the frozen cut really is flooding"
    assert 0.02 <= adapted_rate <= 0.09, (
        f"adapted cut should hold the 5% budget, got {adapted_rate:.3f}"
    )


def test_budget_controller_stays_inside_the_band_and_reports_saturation():
    """A strict budget on an attack-dense stream must saturate, not mute the feed."""
    policy = _policy(target_alert_rate=1e-4, window_size=500, warmup_batches=1)
    rng = random.Random(11)
    for batch in range(40):
        policy.observe(_bell(rng, 500), batch_id=batch, alert_count=20)
    lo, hi = policy.threshold_bounds()
    high_rung = 0.493131
    assert abs(hi - high_rung) < 1e-9, (
        "the ceiling must default to the High rung, so a saturated budget still "
        "leaves a two-rung ladder above the cut"
    )
    assert lo <= policy.effective_threshold() <= hi
    assert abs(policy.effective_threshold() - hi) < 1e-3, (
        "an unreachable budget converges to the ceiling"
    )
    assert policy.budget_saturated is True
    record = policy.snapshot()
    assert record["operating_point"]["budget_saturated"] is True


def test_band_lower_bound_blocks_drifting_looser_than_the_validated_point():
    policy = _policy(target_alert_rate=0.5, window_size=500, warmup_batches=1)
    rng = random.Random(13)
    for batch in range(30):
        policy.observe(_bell(rng, 500), batch_id=batch, alert_count=250)
    lo, _ = policy.threshold_bounds()
    assert lo == DEPLOYED_CUT * 0.5
    assert policy.effective_threshold() >= lo


def test_prefilter_cannot_drop_a_row_the_gate_would_keep():
    policy = _policy()
    policy.learn_feedback([
        {"_id": str(i), "p_attack": 0.30, "verdict": "false_positive"} for i in range(60)
    ])
    t = policy.effective_threshold()
    pre = policy.prefilter_threshold()
    assert pre < t
    for p in [i / 200.0 for i in range(201)]:
        if policy.adapt_score(p) >= t:
            assert p >= pre, "the Spark-side prefilter dropped a kept row"


def test_adapted_threshold_never_grades_an_alert_low():
    """`severity_medium` must travel with `attack_threshold`.

    detection_policy documents that nothing reaching the alert pipeline is ever
    graded Low.  Raising the cut alone breaks that, so this pins the invariant for
    the adapted policy, at both ends of the band.
    """
    for target in (1e-5, 0.3):
        policy = _policy(target_alert_rate=target, window_size=200, warmup_batches=0)
        rng = random.Random(17)
        for batch in range(25):
            policy.observe(_bell(rng, 200), batch_id=batch, alert_count=5)
        effective = policy.apply_to_thresholds()
        t = effective.attack_threshold
        assert t == policy.effective_threshold()
        # The rung travels with the cut (that is the mechanism), so the invariant
        # is not "always Medium" -- it is that the bottom rung of the ladder sits
        # exactly at the operating point.
        assert effective.severity_medium == t
        assert all(
            severity_for(t + i / 100.0 * (1.0 - t), effective) != "Low"
            for i in range(101)
        )


# ── The calibrator ────────────────────────────────────────────────────────────

def test_calibrator_learns_a_false_positive_correction_and_flips_nothing_else():
    policy = _policy()
    before = policy.adapt_score(0.30)
    policy.learn_feedback([
        {"_id": str(i), "p_attack": 0.30, "verdict": "false_positive"} for i in range(200)
    ])
    after = policy.adapt_score(0.30)
    assert after < before, "repeated FP verdicts must push that band down"
    assert after < policy.effective_threshold(), "the corrected score should now fall below the cut"
    # A confident attack elsewhere is untouched: no evidence was given about it,
    # and the novelty feature (not the score itself) is what carries the learning.
    assert policy.adapt_score(0.99) > 0.9


def test_confidence_cannot_be_erased_within_the_shift_cap():
    """No amount of one-sided feedback may suppress an unambiguous detection."""
    policy = _policy()
    for i in range(5000):
        policy.learn_feedback([
            {"_id": f"fp{i}", "p_attack": 0.99, "verdict": "false_positive"}
        ])
    shift = policy.shift_for(0.99)
    assert -policy.config.max_logit_shift - 1e-9 <= shift <= policy.config.max_logit_shift + 1e-9
    assert policy.adapt_score(0.99) > policy.effective_threshold(), (
        "a capped residual must not be able to erase a definite detection"
    )


def test_feedback_is_deduplicated_and_unusable_rows_are_skipped():
    policy = _policy()
    rows = [{"_id": "a", "p_attack": 0.3, "verdict": "false_positive"}]
    assert policy.learn_feedback(rows) == 1
    assert policy.learn_feedback(rows) == 0, "a re-read of the same verdict must not count twice"
    assert policy.learn_feedback([
        {"_id": "b", "p_attack": 0.3, "verdict": "under_investigation"},
        {"_id": "c", "verdict": "false_positive"},
        {"_id": "d", "p_attack": None, "verdict": "confirmed"},
    ]) == 0
    assert policy.feedback_learned == 1


def test_nominal_negatives_respect_the_margin_and_the_drift_guard():
    policy = _policy()
    cut = policy.config.nominal_margin * policy.effective_threshold()
    scores = [0.0, cut * 0.5, cut, cut * 1.01, 0.9]
    taken = policy.learn_nominal_negatives(scores)
    assert taken == 3, "only scores at or below the margin x cut, and >=1 of them, qualify"
    assert policy.config.nominal_weight < policy.config.analyst_weight, (
        "heuristic labels must weigh less than human ones"
    )

    # Under severe drift, "scored low" is not evidence of benignity.
    policy.drift.verdict = "severe"
    before = policy.calibrator.updates
    assert policy.learn_nominal_negatives(scores) == 0
    assert policy.calibrator.updates == before

    policy.drift.verdict = "stable"
    assert policy.learn_nominal_negatives(scores) == 3


# ── Drift measurement ─────────────────────────────────────────────────────────

def test_drift_is_detected_then_re_anchored_after_it_persists():
    policy = _policy(window_size=600, warmup_batches=1, rebaseline_patience=3)
    rng = random.Random(23)
    for batch in range(4):
        policy.observe(_bell(rng, 600), batch_id=batch, alert_count=20)
    assert policy.drift.verdict == "stable"
    assert policy.drift.reanchors == 0

    verdicts = []
    for batch in range(4, 12):
        policy.observe(_bell(rng, 600, shift=0.3), batch_id=batch, alert_count=20)
        verdicts.append(policy.drift.verdict)
        if policy.drift.reanchors:
            break

    assert "shift" in verdicts or "severe" in verdicts, "a 0.3-scale move must register"
    assert policy.drift.reanchors >= 1, "a persisting shift must re-anchor the baseline"
    assert policy.drift.verdict == "stable", "after re-anchoring the baseline is current again"


def test_re_anchor_count_is_reported_for_operators():
    policy = _policy(window_size=400, warmup_batches=1, rebaseline_patience=2)
    rng = random.Random(29)
    for batch in range(30):
        policy.observe(_bell(rng, 400, shift=0.03 * batch), batch_id=batch, alert_count=10)
    snapshot = policy.snapshot()
    assert snapshot["drift"]["reanchors"] >= 3
    assert snapshot["reference"]["baseline_source"].endswith("|reanchored")


# ── Persistence and reporting ─────────────────────────────────────────────────

def test_state_round_trip_resumes_learning_and_reclamps_the_cut():
    policy = _policy()
    rng = random.Random(31)
    for batch in range(6):
        policy.observe(_bell(rng, 500), batch_id=batch, alert_count=25)
    policy.learn_feedback([
        {"_id": str(i), "p_attack": 0.30, "verdict": "false_positive"} for i in range(40)
    ])
    policy.learn_nominal_negatives([0.001] * 30)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "state.json"
        assert policy.save(path) is True
        resumed = OnlineLearningPolicy.load_or_new(path, thresholds=policy.thresholds,
                                                   config=policy.config)

    assert resumed.effective_threshold() == policy.effective_threshold()
    assert resumed.calibrator.w == policy.calibrator.w
    assert resumed.calibrator.updates == policy.calibrator.updates
    assert resumed.reference.n == policy.reference.n
    assert resumed.batches_observed == policy.batches_observed
    assert resumed.feedback_learned == policy.feedback_learned
    assert len(resumed.history) == len(policy.history)
    # And the resume must not re-learn verdicts it already consumed.
    assert resumed.learn_feedback([
        {"_id": str(i), "p_attack": 0.30, "verdict": "false_positive"} for i in range(40)
    ]) == 0

    # A checkpoint whose cut is outside the current band is re-clamped, never
    # restored out of band.
    tampered = policy.state_dict()
    tampered["threshold"] = 0.999
    strict = _policy(target_alert_rate=0.05, threshold_upper_ratio=1.2)
    strict.load_state(tampered)
    lo, hi = strict.threshold_bounds()
    assert strict.effective_threshold() == hi


def test_missing_or_malformed_checkpoint_starts_fresh_instead_of_raising():
    policy = _policy()
    assert OnlineLearningPolicy.load_or_new(
        "/nonexistent/threvia/learning.json", thresholds=policy.thresholds,
        config=policy.config,
    ).batches_observed == 0
    policy.load_state({"threshold": "not-a-number", "calibrator": {"w": "nope"}})
    assert policy.batches_observed == 0


# ── The decision itself (what the Spark foreachBatch loop runs per flow) ────

def test_classify_is_the_frozen_decision_until_evidence_exists():
    """The A/B baseline must be exact, not approximately equal."""
    policy = _policy()
    frozen = classify_flow(0.42, 0.9, policy.thresholds, attack_type_hint="DDoS")
    adapted = policy.classify(0.42, 0.9, policy.thresholds, attack_type_hint="DDoS")
    assert adapted["attack_type"] == frozen["attack_type"]
    assert adapted["severity"] == frozen["severity"]
    assert adapted["confidence"] == frozen["confidence"]
    assert adapted["bot_routed"] == frozen["bot_routed"]
    assert adapted["threshold_used"] == DEPLOYED_CUT
    assert adapted["score_shift"] == 0.0
    assert adapted["p_attack_raw"] == 0.42


def test_classify_decides_on_the_adapted_cut_and_keeps_an_audit_trail():
    """A raised rate-controlled cut must suppress what the frozen cut would raise."""
    policy = _policy(target_alert_rate=1e-5, window_size=200, warmup_batches=0)
    rng = random.Random(41)
    for batch in range(25):
        policy.observe(_bell(rng, 200), batch_id=batch, alert_count=1)

    cut = policy.effective_threshold()
    assert cut > 0.30, "this scenario needs the cut above the flow below"
    assert classify_flow(0.30, None, policy.thresholds) is not None, (
        "the frozen operating point would alert on this flow"
    )
    assert policy.classify(0.30, None, policy.thresholds) is None, (
        "the adapted operating point must actually decide, not just be reported"
    )

    verdict = policy.classify(cut + 0.01, None, policy.thresholds, attack_type_hint="DDoS")
    assert verdict is not None
    assert verdict["threshold_used"] == cut
    assert verdict["p_attack_raw"] == cut + 0.01
    assert abs(verdict["confidence"] - verdict["p_attack_adapted"]) < 1e-12
    assert verdict["score_shift"] == 0.0
    assert verdict["severity"] != "Low"
    assert verdict["learning_updates"] == 0


def test_classify_reports_a_nonzero_shift_once_labels_exist():
    policy = _policy()
    policy.learn_feedback([
        {"_id": str(i), "p_attack": 0.30, "verdict": "false_positive"} for i in range(200)
    ])
    below = policy.classify(0.30, None, policy.thresholds)
    assert below is None, "the residual pushed this band below the gate"
    above = policy.classify(0.95, None, policy.thresholds)
    assert above is not None
    assert above["score_shift"] < 0, "the shift must be visible on the alert itself"
    assert abs(above["p_attack_raw"] - 0.95) < 1e-12, "the raw model score is preserved for audit"


def test_note_alerts_folds_the_realized_rate_into_the_last_record():
    policy = _policy()
    record = policy.observe([0.1] * 100, batch_id=0)
    assert record["alerts"] is None, "the rate is unknown until the gate has run"
    updated = policy.note_alerts(4)
    assert updated["alerts"] == 4
    assert abs(updated["alert_rate"] - 0.04) < 1e-12
    assert policy.flows_alerted == 4
    assert policy.history[-1]["alerts"] == 4


def test_telemetry_carries_everything_the_dashboard_renders():
    policy = _policy()
    rng = random.Random(37)
    for batch in range(3):
        record = policy.observe(_bell(rng, 400), batch_id=batch, alert_count=10,
                                learned_feedback=2)
    for key in (
        "threshold", "calibrated_threshold", "threshold_delta", "threshold_bounds",
        "budget", "budget_saturated", "alert_rate_ema", "psi", "ks", "drift",
        "drift_reanchors", "novelty_mean", "calibrator_updates", "shift_mean",
        "weights_norm", "flows_scored", "batch_id",
    ):
        assert key in record, f"telemetry record is missing {key}"
    assert record["flow" + "s_scored"] == 1200
    assert len(policy.history) == 3
    snapshot = policy.snapshot()
    assert snapshot["operating_point"]["budget"] == policy.config.target_alert_rate
    assert snapshot["calibrator"]["identity"] is True
    assert snapshot["feedback"]["by_source"] == {}


def _report() -> int:
    tests = [
        (name, fn) for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failures += 1
            print(f"FAIL  {name}\n      {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"ERROR {name}\n      {type(exc).__name__}: {exc}")
        else:
            print(f"ok    {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_report())
