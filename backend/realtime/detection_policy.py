"""
Detection Policy — thresholds, prior calibration and tier routing
=================================================================
Pure-Python decision logic for Phase 4 Pipeline C (``streaming_detector.py``).

Why this module exists
----------------------
The Phase 4 detector made three decisions that, together, produced the bulk of
the false-positive volume seen downstream:

1. **Wrong operating point.** ``ML_THRESHOLD`` defaulted to ``0.25`` while the
   offline sweep in ``backend/ml/threshold_test.py`` recommended ``0.65`` — and
   the documented run command pinned it there with ``export ML_THRESHOLD=0.25``.
   0.25 is below the untuned 0.50 baseline; measured end-to-end on the streamed
   corpus it costs 42.7% FPR where 0.65 costs 3.3%.

2. **Ground-truth label leakage in the labelling path.** ``attack_type`` was
   derived from the stream's ``label`` / ``attack_cat`` columns (the answer
   key), not from model output, and those columns were also persisted as
   ``ground_truth_label`` / ``ground_truth_cat``.  Any per-attack-type FP
   breakdown computed from that stream measures the simulator's labels, not the
   classifier.

This module fixes (1) and makes (2) impossible: every decision below is a
function of model probabilities only.

A correction worth recording, because the obvious guess is wrong
---------------------------------------------------------------
The Bot specialist *looked* like the obvious second culprit: it ran
unconditionally, used a hard 0.5 cut from a model trained on a 50/50 balanced
set, and was checked before every other label.  Two plausible-sounding fixes
were implemented and both were measured to be **harmful** on the corpus that
``stream_simulator`` actually replays (``demo_balanced_150k_fixed``, 113,928
flows; measured by ``backend/ml/measure_stream_fpr.py``):

* **Prior correction** (re-basing a 50/50 posterior onto the observed
  ``P(Bot | flagged) = 0.0222``): demands a raw rf_bot score of 0.9778, which
  the model never emits -> **0 Bot detections**.  The reason is that a Random
  Forest's ``probability`` is a *tree-vote fraction*, not a calibrated
  posterior, so the Bayesian odds re-basing does not apply.  It remains
  available via ``apply_prevalence_correction`` but is **off by default**.
* **Tier-2 gating** (consult Bot only when ``P(attack) <= 0.80``, per the
  docstring in ``train_bot_classifier.py``): retains 48 of 905 true Bot flows
  -> **857 true Bots lost**, 5.3% recall.  Bot flows are flagged *confidently*
  by the binary RF, so they are not in the ambiguous band.  Gating is therefore
  also **off by default** (``bot_route_max_confidence = None``).

What the measurements show the Bot path should do:

| raw cut | rule | labelled Bot | truly Bot | precision | Bot recall |
|---------|------|--------------|-----------|-----------|------------|
| **0.50** | ungated | 947 | 905 | **95.56%** | **100.00%** |
| 0.60 | ungated | 549 | 549 | 100.00% | 60.66% |
| 0.50 | gated <= 0.80 | 48 | 48 | 100.00% | 5.30% |

So the original unconditional 0.50 cut was already at the measured optimum, the
Bot bucket was only 4.42% impure, and the Bot specialist was **not** a
meaningful source of false positives.  The dashboard's former "BOT CLUSTER ML
FPR 28.10%" is not reproducible from any artifact in this repository.  What the
Bot path genuinely lacked was *observability* (its probability was discarded, so
nobody could have known the above) — hence ``p_bot``, ``p_bot_calibrated`` and
``bot_routed`` are now persisted on every alert, and the cut is configurable and
re-derivable rather than implied by a hard ``prediction``.

Deployment notes
----------------
* Thresholds resolve in this order: explicit argument → ``THREVIA_THRESHOLDS``
  env var → ``backend/realtime/thresholds.json`` → environment overrides
  (``ML_THRESHOLD``, ``BOT_THRESHOLD``, ...) → built-in defaults.
  ``thresholds.json`` is produced by ``backend/ml/calibrate_thresholds.py``,
  which derives the cut from a benign-heavy holdout instead of guessing.
* The built-in defaults are the values ``threshold_test.py`` measured on
  CIC-2017 Friday BENIGN.  They are a sane starting point, not a substitute for
  running the calibration on your own traffic.

Dependencies: none (stdlib only, so it is importable without Spark).
"""

from __future__ import annotations

import json
import logging
import math
import os
from dataclasses import dataclass, asdict, fields
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Built-in defaults ──────────────────────────────────────────────────────────
# attack_threshold  : P(attack) required to raise an ML alert.  Measured on the
#                     streamed corpus: T=0.25 -> FPR 42.95%, T=0.65 -> FPR 3.23%
#                     at a 1.44 pp recall cost.  The old runtime value (0.25) sat
#                     below the untuned 0.50 baseline and was not an operating
#                     point anyone chose -- it was typed into a launch command.
# bot_threshold     : raw rf_bot score required to accept the Bot verdict.
#                     0.50 is the measured optimum (95.56% precision at 100%
#                     Bot recall); 0.60 buys 100% precision for 39% of recall.
# bot_train_prev    : positive rate of the set rf_bot was trained on (50/50).
# bot_deploy_prev   : P(Bot | flow already flagged by the binary RF).  Measured
#                     0.0222 on the streamed corpus.  Only consulted when
#                     apply_prevalence_correction is on.
# apply_prevalence_correction: OFF by default.  An RF probability is a tree-vote
#                     fraction, not a calibrated posterior, so re-basing it onto
#                     deployment odds over-corrects into silence (see module
#                     docstring for the measurement).  Enable only for a model
#                     whose probabilities have actually been calibrated.
# bot_route_max_conf: OFF by default (None = always route).  Gating the Bot
#                     specialist on "binary RF unsure" costs 857 of 905 true Bot
#                     detections, because Bot flows are flagged confidently.
# suppress_infiltration: ON by default — a deliberate mitigation, not a tuning
#                     choice.  On the streamed corpus, 980 of 986 flows the
#                     multiclass RF labelled "Infiltration" were truly BENIGN:
#                     that label alone accounts for 76% of all remaining false
#                     positives.  The independent held-out evaluation agrees
#                     (7.44% of BENIGN rows receive the Infiltration label).
#                     Suppressed flows are NOT discarded: they are routed to a
#                     manual-review bucket instead of auto-flagging.  Bot-routed
#                     flows keep their Bot verdict regardless.
DEFAULTS: dict[str, Any] = {
    "attack_threshold": 0.65,
    "bot_threshold": 0.50,
    "bot_train_prevalence": 0.50,
    "bot_deploy_prevalence": 0.05,
    "apply_prevalence_correction": False,
    "bot_route_max_confidence": None,
    "severity_critical": 0.85,
    "severity_high": 0.65,
    "severity_medium": 0.40,
    "suppress_infiltration": True,
}

# Environment overrides (name → Thresholds field).  ``ML_THRESHOLD`` is kept
# because docker-compose / launch scripts already use it.
_ENV_MAP = {
    "ML_THRESHOLD": "attack_threshold",
    "BOT_THRESHOLD": "bot_threshold",
    "BOT_TRAIN_PREVALENCE": "bot_train_prevalence",
    "BOT_DEPLOY_PREVALENCE": "bot_deploy_prevalence",
    "BOT_ROUTE_MAX_CONFIDENCE": "bot_route_max_confidence",
    "SEVERITY_CRITICAL": "severity_critical",
    "SEVERITY_HIGH": "severity_high",
    "SEVERITY_MEDIUM": "severity_medium",
    "SUPPRESS_INFILTRATION": "suppress_infiltration",
}

DEFAULT_THRESHOLDS_PATH = Path(__file__).with_name("thresholds.json")

_EPS = 1e-9


# ── Numeric helpers ────────────────────────────────────────────────────────────


def logit(p: float, eps: float = _EPS) -> float:
    """log(p / (1-p)) with the probability clamped away from 0 and 1."""
    p = min(1.0 - eps, max(eps, float(p)))
    return math.log(p / (1.0 - p))


def sigmoid(x: float) -> float:
    """Numerically stable logistic function."""
    if x >= 0.0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def calibrate_probability(
    p: float,
    train_prevalence: float,
    deploy_prevalence: float,
) -> float:
    """
    Re-base a posterior learned at one class prior onto another prior.

    A classifier trained on a balanced set estimates P(y=1 | x) *at that
    prevalence*.  Odds shift linearly with the prior odds, so::

        odds_deploy = odds_train * (prev_deploy / (1 - prev_deploy))
                                / (prev_train  / (1 - prev_train))

    which in log-odds form is ``logit(p) + logit(prev_d) - logit(prev_t)``.

    A balanced Bot model at ``prev_train = 0.5`` therefore needs a raw score of
    ~0.95 to clear 0.5 once ``prev_deploy = 0.05`` — which is exactly the
    correction whose absence produced the Bot FPR.
    """
    shift = logit(deploy_prevalence) - logit(train_prevalence)
    return sigmoid(logit(p) + shift)


def severity_for(p_attack: float, thresholds: "Thresholds") -> str:
    """Map P(attack) onto the operational severity ladder."""
    if p_attack >= thresholds.severity_critical:
        return "Critical"
    if p_attack >= thresholds.severity_high:
        return "High"
    if p_attack >= thresholds.severity_medium:
        return "Medium"
    return "Low"


# ── Threshold container ────────────────────────────────────────────────────────


@dataclass
class Thresholds:
    """Resolved decision policy for Pipeline C."""

    attack_threshold: float = DEFAULTS["attack_threshold"]
    bot_threshold: float = DEFAULTS["bot_threshold"]
    bot_train_prevalence: float = DEFAULTS["bot_train_prevalence"]
    bot_deploy_prevalence: float = DEFAULTS["bot_deploy_prevalence"]
    apply_prevalence_correction: bool = DEFAULTS["apply_prevalence_correction"]
    bot_route_max_confidence: float | None = DEFAULTS["bot_route_max_confidence"]
    severity_critical: float = DEFAULTS["severity_critical"]
    severity_high: float = DEFAULTS["severity_high"]
    severity_medium: float = DEFAULTS["severity_medium"]
    suppress_infiltration: bool = DEFAULTS["suppress_infiltration"]
    source: str = "defaults"

    def effective_bot_logit_shift(self) -> float:
        """Log-odds shift applied to the Bot model's raw score."""
        if not self.apply_prevalence_correction:
            return 0.0
        return logit(self.bot_deploy_prevalence) - logit(self.bot_train_prevalence)

    def raw_bot_score_needed(self) -> float:
        """Raw (uncalibrated) rf_bot score equivalent to ``bot_threshold``.

        Useful for logging and for reasoning about what the policy demands of
        the model, since the raw score is what the sweep scripts report.
        """
        return sigmoid(logit(self.bot_threshold) - self.effective_bot_logit_shift())

    def describe(self) -> str:
        route = (
            "every flagged flow"
            if self.bot_route_max_confidence is None
            else f"P(attack) <= {self.bot_route_max_confidence:.2f}"
        )
        bot_term = (
            f"justified rd_bot raw score >= {self.raw_bot_score_needed():.3f}"
            if self.apply_prevalence_correction
            else f"raw rf_bot score >= {self.bot_threshold:.2f}"
        )
        return (
            f"[policy src={self.source}] "
            f"alert if P(attack) >= {self.attack_threshold:.2f}; "
            f"Tier-2 Bot consulted for {route} and accepted on {bot_term}"
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# Field annotations are strings at runtime (``from __future__ import annotations``).
_OPTIONAL_FLOAT_FIELDS = {"bot_route_max_confidence"}
_BOOL_FIELDS = {"apply_prevalence_correction"}
_NULLISH = ("", "none", "null", "never", "off")


def _coerce(field_name: str, raw: Any) -> Any:
    """Cast a raw config/env value to the dataclass field's declared type."""
    if field_name in _OPTIONAL_FLOAT_FIELDS:
        if raw is None or str(raw).strip().lower() in _NULLISH:
            return None
        return float(raw)
    if field_name in _BOOL_FIELDS:
        return str(raw).strip().lower() in ("1", "true", "yes", "on")
    if field_name == "source":
        return str(raw)
    if field_name in {f.name for f in fields(Thresholds)}:
        return float(raw)
    return raw


def load_thresholds(
    path: str | os.PathLike | None = None,
    overrides: dict[str, Any] | None = None,
) -> Thresholds:
    """
    Resolve the detection policy from file → env → defaults.

    Never raises: a malformed or unreadable config logs a warning and falls back
    to the built-in defaults rather than taking the streaming job down.
    """
    values: dict[str, Any] = {}
    source = "defaults"
    from_file: set[str] = set()

    candidate = path or os.getenv("THREVIA_THRESHOLDS") or DEFAULT_THRESHOLDS_PATH
    try:
        candidate_path = Path(candidate)
        if candidate_path.is_file():
            with candidate_path.open(encoding="utf-8-sig") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                # Tolerate a wrapper produced by calibrate_thresholds.py
                loaded = loaded.get("thresholds", loaded)
                valid = {f.name for f in fields(Thresholds)}
                values.update({k: v for k, v in loaded.items() if k in valid})
                from_file = set(values)
                source = str(candidate_path)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        logger.warning("Could not read threshold config %s (%s) — using defaults", candidate, exc)

    env_overrides: list[str] = []
    for env_name, field_name in _ENV_MAP.items():
        raw = os.getenv(env_name)
        if raw is not None and str(raw).strip() != "":
            # An env var silently beating a calibrated artifact is exactly how
            # this pipeline drifted to an unchosen operating point before.
            if field_name in from_file:
                logger.warning(
                    "Env %s=%s overrides the calibrated value for %s from %s",
                    env_name, raw, field_name, source,
                )
            values[field_name] = _coerce(field_name, raw)
            env_overrides.append(env_name)

    if env_overrides:
        source = f"{source}+env({','.join(env_overrides)})"

    for key, raw in (overrides or {}).items():
        if raw is not None:
            values[key] = raw
            source = "caller"

    kwargs: dict[str, Any] = {}
    for f in fields(Thresholds):
        if f.name == "source" or f.name not in values:
            continue
        try:
            kwargs[f.name] = _coerce(f.name, values[f.name])
        except (TypeError, ValueError):
            logger.warning("Ignoring invalid threshold %s=%r", f.name, values[f.name])

    return Thresholds(source=source, **kwargs)


# ── The decision itself ────────────────────────────────────────────────────────


def classify_flow(
    p_attack: float,
    p_bot: float | None = None,
    thresholds: Thresholds | None = None,
    attack_type_hint: str | None = None,
) -> dict[str, Any] | None:
    """
    Decide whether a scored flow is an alert, and if so what to call it.

    Parameters
    ----------
    p_attack
        ``probability[1]`` from the binary RF (attack vs BENIGN).
    p_bot
        ``probability[1]`` from the Bot specialist, or ``None`` if it was not
        consulted.
    attack_type_hint
        Label from the multiclass RF (e.g. ``"DDoS"``).  Used only as a
        *description*; it can never flip the alert decision.  Ground-truth
        columns must never be passed here.
    thresholds
        Resolved policy; loaded from config when omitted.

    Returns
    -------
    ``None`` when the flow is below threshold.  Otherwise a dict with
    ``attack_type``, ``severity``, ``confidence``, ``p_bot_calibrated`` and
    ``bot_routed``.
    """
    th = thresholds or load_thresholds()

    try:
        p_attack = float(p_attack)
    except (TypeError, ValueError):
        return None
    if math.isnan(p_attack):
        return None

    if p_attack < th.attack_threshold:
        return None

    gate = th.bot_route_max_confidence
    bot_routed = p_bot is not None and (gate is None or p_attack <= gate)

    p_bot_cal: float | None = None
    if bot_routed:
        try:
            raw_bot = float(p_bot)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            raw_bot = math.nan
        if not math.isnan(raw_bot):
            p_bot_cal = (
                calibrate_probability(
                    raw_bot, th.bot_train_prevalence, th.bot_deploy_prevalence
                )
                if th.apply_prevalence_correction
                else raw_bot
            )

    if p_bot_cal is not None and p_bot_cal >= th.bot_threshold:
        # Bot outranks a *descriptive* multiclass label, but only inside the
        # low-confidence band — a confident DDoS verdict is never relabelled.
        attack_type = "Bot"
    elif attack_type_hint and attack_type_hint.strip() and attack_type_hint.strip().upper() not in (
        "BENIGN",
        "NORMAL",
        "ATTACK",
    ):
        attack_type = attack_type_hint.strip()
    else:
        attack_type = "Attack (unclassified)"

    verdict = {
        "attack_type": attack_type,
        "severity": severity_for(p_attack, th),
        "confidence": p_attack,
        "p_bot_calibrated": p_bot_cal,
        "bot_routed": bool(bot_routed),
        "auto_alert": True,
    }

    # Infiltration suppression (see DEFAULTS note): the multiclass label is
    # wrong far more often than right on benign traffic.  Route to manual
    # review instead of auto-flagging.  If the Bot specialist had accepted the
    # flow, attack_type would already be "Bot", so no extra check is needed.
    if th.suppress_infiltration and attack_type == "Infiltration":
        verdict["auto_alert"] = False
        verdict["review_reason"] = "infiltration_label_suppressed"

    return verdict


def should_alert(p_attack: float, thresholds: Thresholds | None = None) -> bool:
    """Cheap threshold test usable inside a Spark ``filter``."""
    th = thresholds or load_thresholds()
    try:
        return float(p_attack) >= th.attack_threshold
    except (TypeError, ValueError):
        return False


__all__ = [
    "DEFAULTS",
    "DEFAULT_THRESHOLDS_PATH",
    "Thresholds",
    "calibrate_probability",
    "classify_flow",
    "load_thresholds",
    "logit",
    "severity_for",
    "should_alert",
    "sigmoid",
]
