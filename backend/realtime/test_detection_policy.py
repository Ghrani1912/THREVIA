#!/usr/bin/env python3
"""
Tests for the Phase 4 detection policy.

Runs two ways::

    python backend/realtime/test_detection_policy.py     # standalone report
    pytest backend/realtime/test_detection_policy.py -q  # CI

Every assertion here maps to a specific false-positive defect found in the
streaming detector.  The names say which.
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.realtime.detection_policy import (  # noqa: E402
    DEFAULTS,
    SPIKE_CRITICAL_CONNECTIONS,
    SPIKE_HIGH_CONNECTIONS,
    Thresholds,
    calibrate_probability,
    classify_flow,
    load_thresholds,
    logit,
    severity_for,
    should_alert,
    sigmoid,
    spike_severity_for,
)

_ENV_KEYS = [
    "THREVIA_THRESHOLDS",
    "ML_THRESHOLD",
    "BOT_THRESHOLD",
    "BOT_TRAIN_PREVALENCE",
    "BOT_DEPLOY_PREVALENCE",
    "BOT_ROUTE_MAX_CONFIDENCE",
    # The spike feed's own ladder and emit gate.  Read at import time, so this
    # list only documents them -- but a policy env var read at import time is
    # exactly the kind that leaks between tests, so name them here.
    "SPIKE_HIGH_CONNECTIONS",
    "SPIKE_CRITICAL_CONNECTIONS",
]


@contextlib.contextmanager
def clean_env(**overrides: str):
    """Run a block with the policy env vars cleared, then restored.

    ``THREVIA_THRESHOLDS`` is additionally pointed at a path that does not
    exist, so these tests measure the *built-in* policy and stay independent of
    whatever ``backend/realtime/thresholds.json`` the checkout happens to carry
    (that artifact is now a promoted v3 operating point, and its numbers are
    deliberately not the built-in defaults).
    """
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    os.environ["THREVIA_THRESHOLDS"] = "/nonexistent/thresholds.json"
    os.environ.update(overrides)
    try:
        yield
    finally:
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v


# ── Probability helpers ────────────────────────────────────────────────────────


def test_logit_sigmoid_roundtrip():
    for p in (0.001, 0.01, 0.25, 0.5, 0.75, 0.99, 0.999):
        assert abs(sigmoid(logit(p)) - p) < 1e-9


def test_logit_is_finite_at_extremes():
    # The old code called math.log(p / (1 - p)) directly, which raises on 0/1.
    for p in (0.0, 1.0):
        assert math.isfinite(logit(p))


def test_calibrate_is_identity_when_prevalences_match():
    for p in (0.1, 0.4, 0.5, 0.9):
        assert abs(calibrate_probability(p, 0.2, 0.2) - p) < 1e-9


def test_calibrate_balanced_model_at_low_prevalence():
    # The exact correction the Bot specialist was missing: a 50/50 model's 0.50
    # becomes 0.05 once the real positive rate is 5%.
    assert abs(calibrate_probability(0.50, 0.50, 0.05) - 0.05) < 1e-9
    # ...and it must climb back to 0.50 only at a raw score of 0.95.
    assert abs(calibrate_probability(0.95, 0.50, 0.05) - 0.50) < 1e-9
    assert calibrate_probability(0.90, 0.50, 0.05) < 0.35


def test_calibrate_is_monotonic():
    prev = -1.0
    for i in range(51):
        val = calibrate_probability(i / 50.0, 0.5, 0.01)
        assert val >= prev - 1e-12, "calibration must not reorder scores"
        prev = val


# ── Threshold resolution ───────────────────────────────────────────────────────


def test_default_attack_threshold_is_the_tuned_one():
    """Regression: the live default used to be 0.25 — below the untuned 0.50."""
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent/thresholds.json"))
    assert th.attack_threshold == DEFAULTS["attack_threshold"] == 0.65
    assert th.attack_threshold > 0.50


def test_ml_threshold_env_is_still_honoured():
    """docker-compose / launch scripts set ML_THRESHOLD; that must still work."""
    with clean_env(ML_THRESHOLD="0.72"):
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert th.attack_threshold == 0.72


def test_thresholds_file_is_read_and_tolerates_bom_and_wrapper():
    with clean_env():
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "thresholds.json"
            cfg.write_text(
                json.dumps({"thresholds": {"attack_threshold": 0.81, "bot_threshold": 0.6}}),
                encoding="utf-8-sig",
            )
            th = load_thresholds(path=cfg)
            assert th.attack_threshold == 0.81
            assert th.bot_threshold == 0.6


def test_malformed_thresholds_file_falls_back_instead_of_raising():
    with clean_env():
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "thresholds.json"
            cfg.write_text("{ this is not json", encoding="utf-8")
            th = load_thresholds(path=cfg)
    assert th.attack_threshold == DEFAULTS["attack_threshold"]
    assert th.bot_threshold == DEFAULTS["bot_threshold"]


def test_unknown_keys_in_config_are_ignored():
    with clean_env():
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "thresholds.json"
            cfg.write_text(json.dumps({"attack_threshold": 0.7, "nonsense": 1}), encoding="utf-8")
            th = load_thresholds(path=cfg)
    assert th.attack_threshold == 0.7


def test_env_overriding_a_calibrated_file_is_loud_not_silent():
    """
    Silent env-beats-file drift is precisely how the live threshold ended up at
    0.25.  Env still wins, but it must say so.
    """
    import logging

    captured: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            captured.append(record.getMessage())

    handler = _Capture()
    policy_logger = logging.getLogger("backend.realtime.detection_policy")
    policy_logger.addHandler(handler)
    try:
        with clean_env(ML_THRESHOLD="0.30"):
            with tempfile.TemporaryDirectory() as tmp:
                cfg = Path(tmp) / "thresholds.json"
                cfg.write_text(json.dumps({"attack_threshold": 0.90}), encoding="utf-8")
                th = load_thresholds(path=cfg)
    finally:
        policy_logger.removeHandler(handler)

    assert th.attack_threshold == 0.30           # env still wins
    assert "ML_THRESHOLD" in th.source            # and the provenance records it
    assert any("overrides the calibrated value" in m for m in captured), captured


def test_bot_route_gating_can_be_enabled_by_env():
    with clean_env(BOT_ROUTE_MAX_CONFIDENCE="0.80"):
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert th.bot_route_max_confidence == 0.80


def test_bot_route_gating_accepts_none_as_explicitly_off():
    with clean_env(BOT_ROUTE_MAX_CONFIDENCE="none"):
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert th.bot_route_max_confidence is None


# ── The decision ───────────────────────────────────────────────────────────────


def test_below_threshold_produces_no_alert():
    # Explicit built-in policy: should_alert/classify_flow with no argument
    # resolve the *shipped* thresholds.json, which is a different operating
    # point by design.  These assertions are about the decision logic itself.
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert should_alert(0.30, th) is False
    assert classify_flow(0.30, 0.99, th) is None
    assert classify_flow(0.6499, 0.99, th) is None  # just under the tuned cut


def test_threshold_is_inclusive_and_malformed_scores_are_dropped():
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert should_alert(0.65, th) is True
    assert classify_flow(0.65, None, th)["severity"] == "High"
    assert classify_flow(None, None, th) is None
    assert classify_flow("not-a-number", None, th) is None
    assert classify_flow(float("nan"), None, th) is None


def test_shipped_threshold_artifact_names_the_gate_it_was_derived_for():
    """A gate model and its cut are not interchangeable across retrains.

    v3 at the v1 cut of 0.65 flags 0.16% of the clean BENIGN holdout and detects
    0 of 570 held-out Bot flows; v1 at v3's calibrated cut would flood.  The
    committed artifact records which gate it came from, and this test keeps a
    promoted gate and its operating point from silently drifting apart.
    (Numbers from backend/ml/eval_bot_behind_gate.py.)
    """
    artifact = Path(__file__).with_name("thresholds.json")
    if not artifact.is_file():
        return  # no calibration has been run in this checkout

    cfg = json.loads(artifact.read_text(encoding="utf-8-sig"))
    assert "gate_models_dir" in cfg, "artifact must record its gate model"
    assert Path(cfg["gate_models_dir"]).name.startswith("models_clean")
    assert Path(cfg["shared_models_dir"]).name.startswith("models_clean")

    th = cfg["thresholds"]
    assert 0.0 < th["attack_threshold"] < 1.0
    assert 0.0 < cfg["measured_fpr_pct"] < 10.0, cfg["measured_fpr_pct"]
    # The severity ladder is read off the same score, so it has to stay ordered
    # above the alert cut.  A rescaled gate whose ladder was not re-derived
    # leaves Critical/High permanently empty on the dashboard.
    assert th["attack_threshold"] <= th["severity_high"] <= th["severity_critical"]
    with clean_env():
        resolved = load_thresholds(path=artifact)
    assert abs(resolved.attack_threshold - th["attack_threshold"]) < 1e-9
    assert abs(resolved.severity_critical - th["severity_critical"]) < 1e-9


def test_bot_defaults_are_the_measured_optimum_not_the_intuitive_fix():
    """
    Two plausible Bot "fixes" were implemented and then measured to be harmful
    (backend/ml/measure_stream_fpr.py, demo_balanced_150k_fixed):

      * prior correction at the observed 2.22% prevalence demands a raw rf_bot
        score of 0.9778, which the model never emits -> 0 detections;
      * Tier-2 gating on P(attack) <= 0.80 retains 48 of 905 true Bots -> 857
        lost, because Bot flows are flagged *confidently*.

    Both are therefore off by default.  The unconditional raw 0.50 cut measured
    95.56% precision at 100% Bot recall and is what the defaults encode.
    """
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert th.apply_prevalence_correction is False
    assert th.bot_route_max_confidence is None      # ungated
    assert th.bot_threshold == 0.50                 # raw, not corrected


def test_raw_bot_score_0_50_labels_bot_by_default():
    """The measured rule: a raw 0.50 IS a Bot verdict (95.56% precise)."""
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    out = classify_flow(0.70, 0.50, th)
    assert out is not None
    assert out["attack_type"] == "Bot"
    assert out["p_bot_calibrated"] == 0.50
    assert out["bot_routed"] is True


def test_high_raw_bot_score_detects_bot():
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    out = classify_flow(0.70, 0.99, th)
    assert out["attack_type"] == "Bot"
    assert out["bot_routed"] is True
    assert out["p_bot_calibrated"] >= th.bot_threshold


def test_bot_verdict_still_requires_a_bot_score():
    """Ungated must not mean unconditional: a low rf_bot score is not a Bot."""
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert classify_flow(0.70, 0.10, th)["attack_type"] != "Bot"
    assert classify_flow(0.70, 0.49, th)["attack_type"] != "Bot"
    assert classify_flow(0.70, None, th)["attack_type"] != "Bot"


def test_gating_is_opt_in_and_then_protects_confident_verdicts():
    """Gating is available for teams who prefer it, but it costs 95% of Bot recall."""
    gated = Thresholds(bot_route_max_confidence=0.80)
    # Inside the ambiguous band the Bot verdict still wins.
    assert classify_flow(0.78, 0.99, gated)["attack_type"] == "Bot"
    # Outside it, a confident verdict is no longer relabelled.
    out = classify_flow(0.99, 0.999, gated, attack_type_hint="DDoS")
    assert out["attack_type"] == "DDoS"
    assert out["bot_routed"] is False
    assert out["p_bot_calibrated"] is None


def test_prior_correction_is_opt_in_and_would_silence_the_bot_model():
    """
    The correction is mathematically valid for a calibrated posterior, but an RF
    probability is a tree-vote fraction — so enabling it at the measured 2.22%
    prevalence would reject a raw 0.99.  Kept as a documented, available knob.
    """
    corrected = Thresholds(apply_prevalence_correction=True, bot_deploy_prevalence=0.0222)
    assert corrected.raw_bot_score_needed() > 0.97        # raised from a raw 0.50
    assert classify_flow(0.70, 0.95, corrected)["attack_type"] != "Bot"
    # ...while the shipped default accepts the very same score.
    assert classify_flow(0.70, 0.95, Thresholds())["attack_type"] == "Bot"


def test_infiltration_label_is_suppressed_to_manual_review_by_default():
    """Step 6 mitigation: 980/986 Infiltration labels were false on the streamed
    corpus (76% of all remaining FPs).  Default policy routes them to manual
    review instead of auto-flagging."""
    out = classify_flow(0.70, None, Thresholds(), attack_type_hint="Infiltration")
    assert out["attack_type"] == "Infiltration"
    assert out["auto_alert"] is False
    assert out["review_reason"] == "infiltration_label_suppressed"
    # Suppression must not change the confidence/severity that a reviewer sees.
    assert out["confidence"] == 0.70
    assert out["severity"] == "High"


def test_bot_accepted_verdicts_are_not_suppressed():
    """A confident Bot verdict outranks the descriptive multiclass label, so it
    is a real Bot detection and must keep auto-alerting.  (The specialist is
    consulted for every flagged flow; when it accepts, attack_type is Bot and
    the suppression never sees an Infiltration label.)"""
    th = Thresholds()
    out = classify_flow(0.70, 0.99, th, attack_type_hint="Infiltration")
    assert out["attack_type"] == "Bot"
    assert out["auto_alert"] is True


def test_infiltration_suppression_is_opt_out():
    """The suppression is a deliberate policy; operators can disable it via env
    (SUPPRESS_INFILTRATION=false) if their traffic mix differs."""
    th = load_thresholds(overrides={"suppress_infiltration": False})
    out = classify_flow(0.70, None, th, attack_type_hint="Infiltration")
    assert out["auto_alert"] is True


def test_other_labels_are_never_suppressed():
    th = Thresholds()
    for hint in ("DDoS", "Bot", "PortScan", "Attack (unclassified)"):
        out = classify_flow(0.70, None, th, attack_type_hint=hint)
        assert out["auto_alert"] is True, hint


def test_multiclass_hint_describes_but_never_labels_benign_as_an_alert():
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    assert classify_flow(0.90, None, th, "DDoS")["attack_type"] == "DDoS"
    assert classify_flow(0.90, None, th, "BENIGN")["attack_type"] == "Attack (unclassified)"
    assert classify_flow(0.90, None, th, None)["attack_type"] == "Attack (unclassified)"
    assert classify_flow(0.90, None, th, "  ")["attack_type"] == "Attack (unclassified)"


def test_severity_ladder_unchanged():
    th = Thresholds()
    assert severity_for(0.99, th) == "Critical"
    assert severity_for(0.85, th) == "Critical"
    assert severity_for(0.70, th) == "High"
    assert severity_for(0.50, th) == "Medium"
    assert severity_for(0.10, th) == "Low"


# ── Spike severity ladder ──────────────────────────────────────────────────────
# stream_alerts grade a connection count, not a probability, so they run through
# spike_severity_for rather than severity_for.  The cutoffs used to be inlined in
# streaming_detector._severity; the dashboard now prints them in its radar legend,
# which is why they live in the policy module where both can read them.


def test_spike_ladder_boundaries():
    """Each rung starts *at* its cutoff, inclusive."""
    assert spike_severity_for(SPIKE_HIGH_CONNECTIONS - 1) == "Medium"
    assert spike_severity_for(SPIKE_HIGH_CONNECTIONS) == "High"
    assert spike_severity_for(SPIKE_CRITICAL_CONNECTIONS - 1) == "High"
    assert spike_severity_for(SPIKE_CRITICAL_CONNECTIONS) == "Critical"


def test_spike_ladder_is_total_and_monotonic():
    """No count is ungraded, and severity never falls as the count grows."""
    order = {"Medium": 0, "High": 1, "Critical": 2}
    counts = [0, 1, 49, 50, 199, 200, 201, 499, 500, 501, 5_000]
    grades = [spike_severity_for(c) for c in counts]
    assert all(g in order for g in grades)
    assert [order[g] for g in grades] == sorted(order[g] for g in grades)


def test_spike_emit_gate_is_not_a_severity_rung():
    """The 50-count gate decides *whether* an alert exists; the ladder decides
    how bad it is.  Medium is the ladder's floor -- it must not degrade to some
    "below-gate" grade, because the legend prints the gate as Medium's range
    ("spike 50-199 conn/window") and a rung below Medium would make that a lie.
    """
    assert spike_severity_for(1) == "Medium"
    assert spike_severity_for(50) == "Medium"
    assert spike_severity_for(199) == "Medium"


def test_spike_cutoffs_are_ordered():
    """A Critical rung below the High rung would make High unreachable."""
    assert 0 < SPIKE_HIGH_CONNECTIONS < SPIKE_CRITICAL_CONNECTIONS


def test_low_rung_is_unreachable_behind_the_deployed_gate():
    """Why the radar draws no Low blips, and the legend lists no Low row.

    severity_medium *is* the deployed attack_threshold, so the lowest P(attack)
    that can produce an ml_alert is already banded Medium: the ladder's bottom
    rung cannot reach the dashboard.  Measured on this checkout's ml_alerts:
    {Critical, High, Medium}, never Low.
    """
    artifact = Path(__file__).with_name("thresholds.json")
    if not artifact.is_file():
        return  # no calibration has been run in this checkout
    with clean_env():
        th = load_thresholds(path=artifact)
    assert th.severity_medium == th.attack_threshold


def test_defaults_are_detectable_as_not_deployed():
    """An unreadable artifact must be distinguishable from a real calibration.

    load_thresholds never raises -- it silently falls back to DEFAULTS -- so the
    API can only flag "these bands are not the deployed ones" by comparing the
    numbers or by reading ``source``.  It does both; if either stopped working
    the radar legend would print default cuts as if they were live.
    """
    missing = Path("/nonexistent/thresholds.json")
    with clean_env():
        fallback = load_thresholds(path=missing)
    assert fallback.source == "defaults"
    assert fallback.severity_medium == DEFAULTS["severity_medium"]

    artifact = Path(__file__).with_name("thresholds.json")
    if not artifact.is_file():
        return
    with clean_env():
        deployed = load_thresholds(path=artifact)
    assert deployed.source != "defaults"
    assert deployed.severity_critical != DEFAULTS["severity_critical"]


def test_policy_reports_the_raw_score_it_demands():
    """Operators need to know what the cut means on the raw rf_bot scale."""
    with clean_env():
        th = load_thresholds(path=Path("/nonexistent.json"))
    # Correction off => the raw cut *is* the operating point.
    assert abs(th.raw_bot_score_needed() - th.bot_threshold) < 1e-12
    assert "P(attack) >= 0.65" in th.describe()
    assert "every flagged flow" in th.describe()


def test_policy_is_serialisable_for_logging_and_artifacts():
    th = Thresholds()
    assert json.loads(json.dumps(th.as_dict()))["attack_threshold"] == 0.65


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
