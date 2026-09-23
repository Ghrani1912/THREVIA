"""
Online / continual learning layer for Pipeline C
================================================
The gate model is a Random Forest trained and evaluated on **one** corpus.  Its
offline accuracy and recall are therefore estimates of performance *on that
corpus's feature distribution and class prior*, not properties of the model.  Put
it in front of traffic that was not in the corpus and three things break, all of
them silently:

1. **The operating point stops meaning what it meant.**  ``attack_threshold``
   was chosen so that a chosen fraction of a *benign holdout* falls below it.  If
   live traffic scores even slightly higher -- a different capture window, a
   different tool, a shifted feature scale -- the same cut flags a different, and
   possibly orders-of-magnitude larger, fraction of flows.  Nothing in the code
   notices.
2. **The scores stop being comparable.**  A tree-vote fraction is not a
   calibrated posterior; its scale is a property of the training set.  Comparing
   today's scores against a histogram from last month measures the training set,
   not the network.
3. **Nothing about the deployment is ever fed back.**  Analyst verdicts, the
   benign majority of the stream, the drift itself -- all discarded.

This module is the piece that was missing.  It sits between the model's raw
score and the alert decision and has three cooperating parts, ordered by how much
they can change behaviour:

``ScoreReference`` / ``DriftMonitor``  -- *measurement only, no decisions.*
    A fixed-bin histogram of the score distribution, a frozen baseline to compare
    against, and two standard statistics: **PSI** (population stability index;
    the rule of thumb is <0.10 stable, 0.10-0.25 moderate, >0.25 a significant
    shift) and the **KS** statistic between the two CDFs.  Reports a verdict per
    window and records when the baseline itself was re-anchored.

``OnlineLearningPolicy`` threshold controller  -- *label-free, rate-controlled.*
    Holds the fraction of scored flows that alert at a budget (``target_alert_rate``)
    by tracking the ``1 - budget`` quantile of the recent score distribution --
    the adaptive-conformal idea (Gibbs & Candès), where the quantile *is* the
    score-dependent bound and the error-feedback update keeps the realized rate on
    target even when the score distribution moves.  On a fixed corpus this is
    nearly inert; on real traffic it is what stops a shifted score scale from
    turning into an alert flood.

``OnlineLogisticCalibrator``  -- *supervised, bounded.*
    An online logistic regression in log-odds space, learned from analyst verdicts
    and from the stream's benign majority, applied as a **residual** on top of the
    frozen model::

        adapted_logit = clip(logit(p) + w . phi(p, p_bot, novelty, drift))

    with ``w = 0`` at construction, so the layer is *exactly* the identity
    function until evidence arrives, and ``|w . phi| <= max_logit_shift``, so no
    amount of bad feedback can make it fabricate or erase a detection.  AdaGrad
    per-coordinate steps, L2 plus exponential forgetting so evidence from a regime
    that no longer exists fades out.

What this deliberately does **not** do
--------------------------------------
* **No self-training on its own predictions.**  The tempting version of "online
  learning" for an IDS is to feed confident predictions back as labels.  That is
  confirmation bias with a drift-driven amplifier: the model's own errors become
  its training set, and it becomes *more* confident, not more correct.  The only
  labels this layer accepts are (a) human verdicts, and (b) flows that scored far
  below the operating point -- see the nominal-negative note below.
* **No refitting of the gate model.**  Retraining a Random Forest online is not
  something a micro-batch should do, and swapping the model out from under a
  running query is how you get an unmeasurable deployment.  The weights stay
  frozen; what adapts is the decision boundary and the calibration.  When you do
  want the weights to move, the artifact this layer emits is what a scheduled
  offline retrain should consume (see ``state_dict()``, which is the full
  reproducible learning state).

The nominal-negative rule and its guard
---------------------------------------
Real streams are overwhelmingly benign, and those flows are the only large source
of *certain* negatives: a flow at ``p <= 0.10 x threshold`` is deep in the
reference distribution's bulk, not near a decision boundary.  They are used at a
down-weighted ``nominal_weight`` (default 0.25) to reflect that they are
heuristic rather than human labels.  They are **blocked while the drift verdict is
severe**: if the score distribution has moved that far, "scored low" no longer
means "benign" -- a novel attack family the model does not recognise scores low --
and teaching the calibrator to suppress low scorers would be teaching it to
suppress the novel attacks.  ``nominal_negatives_blocked_on_drift`` controls this.

Where the thresholds come from
------------------------------
``calibrated_threshold`` is the artifact-derived cut (``thresholds.json``, via
``detection_policy.load_thresholds``) and is the *anchor*, not a suggestion: the
adapted cut is always clamped to
``[calibrated x threshold_lower_ratio, min(calibrated x threshold_upper_ratio,
threshold_ceiling)]``, and ``threshold_ceiling`` defaults to the ladder's High
rung so the adapted cut can never climb into the band above it.  The band exists
because the budget
target alone is not a safety property -- on an attack-dense stream a strict rate
budget would happily suppress the very alerts the budget is supposed to ration,
so the controller saturates at the ceiling and telemetry says so
(``budget_saturated``) rather than quietly muting the feed.  The lower bound
prevents the opposite failure: drifting *looser* than an operating point whose
false-positive rate nobody validated.

Dependencies: stdlib only (``detection_policy`` is stdlib too), so this module is
importable and testable without Spark.
"""

from __future__ import annotations

import json
import logging
import math
import os
import tempfile
from collections import Counter, deque
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from backend.realtime.detection_policy import (
    Thresholds,
    classify_flow,
    load_thresholds,
    logit,
    sigmoid,
)

logger = logging.getLogger(__name__)

# Bin count for the reference/observation histograms.  20 bins over [0, 1] is the
# resolution PSI's 0.10/0.25 rule of thumb was defined at, and it is coarse
# enough that a 1,000-tree vote fraction quantises into it sanely.
N_BINS = 20
_BIN_WIDTH = 1.0 / N_BINS
_EPS = 1e-9
# Masks a p of 0 or 1 (a tree vote fraction can be exactly 0 or 1) for logit().
_LOGIT_EPS = 1e-6

_DEFAULT_STATE_PATH = "/tmp/threvia_learning_state.json"


# ── Score histogram helpers ────────────────────────────────────────────────────


def _bin_of(p: float) -> int:
    """Index of ``p`` in the fixed [0, 1] bin lattice (clamped, finite-safe)."""
    if not math.isfinite(p):
        return 0
    return min(N_BINS - 1, max(0, int(p * N_BINS)))


def _histogram(scores: Iterable[float]) -> list[int]:
    counts = [0] * N_BINS
    for p in scores:
        counts[_bin_of(float(p))] += 1
    return counts


def _as_distribution(counts: Sequence[int]) -> list[float]:
    """Normalise bin counts to a probability mass per bin."""
    total = float(sum(counts))
    if total <= 0:
        return [0.0] * len(counts)
    return [c / total for c in counts]


def _cdf(dist: Sequence[float]) -> list[float]:
    out: list[float] = []
    acc = 0.0
    for mass in dist:
        acc += mass
        out.append(min(1.0, acc))
    return out


def population_stability_index(
    reference: Sequence[float],
    observed: Sequence[float],
    eps: float = 1e-4,
) -> float:
    """PSI between two per-bin probability masses.

    ``sum((obs - ref) * ln(obs / ref))`` over bins, with both sides floored at
    ``eps`` so an empty bin yields a large-but-finite contribution instead of an
    error.  Interpretation (industry rule of thumb, not a theorem):
    <0.10 no meaningful shift, 0.10-0.25 moderate, >0.25 significant.
    """
    total = 0.0
    for r, o in zip(reference, observed):
        r = max(float(r), eps)
        o = max(float(o), eps)
        total += (o - r) * math.log(o / r)
    return total


def ks_statistic(reference: Sequence[float], observed: Sequence[float]) -> float:
    """Maximum absolute gap between two CDFs (two-sample KS, binned).

    Binned rather than exact: the reference is stored as a histogram so it stays
    constant-size in the checkpoint, and at 20 bins the discretisation error is far
    below the thresholds this is compared against.
    """
    a, b = _cdf(reference), _cdf(observed)
    return max((abs(x - y) for x, y in zip(a, b)), default=0.0)


def _quantile(sorted_scores: Sequence[float], q: float) -> float:
    """Linear-interpolated quantile of an already-sorted sequence."""
    if not sorted_scores:
        return float("nan")
    q = min(1.0, max(0.0, q))
    if len(sorted_scores) == 1:
        return float(sorted_scores[0])
    pos = q * (len(sorted_scores) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_scores) - 1)
    frac = pos - lo
    return float(sorted_scores[lo]) * (1.0 - frac) + float(sorted_scores[hi]) * frac


# ── Configuration ──────────────────────────────────────────────────────────────


@dataclass
class OnlineLearningConfig:
    """Tunables for the adaptive layer.

    Defaults are chosen to be *slow and bounded* rather than fast: this layer sits
    in front of a detector whose operating point was measured, and an adaptation
    whose effects cannot be explained after the fact is worse than no adaptation.
    """

    enabled: bool = True

    # ── rate control (label-free) ──
    # Fraction of scored flows allowed to alert.  The default is the rate the
    # deployed cut produces on the calibration stream (~2.5%); re-derive it by
    # measuring the alert rate at ``calibrated_threshold`` on your own traffic.
    # NOTE: this is a *target*, subordinate to the band below.  A stream with a
    # high attack prior cannot be pushed to an arbitrarily low rate without
    # discarding real detections, so the controller saturates and says so.
    target_alert_rate: float = 0.025
    # EMA pull toward the budget-quantile cut, per observed batch.
    threshold_step: float = 0.25
    # Band around ``calibrated_threshold`` the adapted cut may live in.
    threshold_lower_ratio: float = 0.5
    threshold_upper_ratio: float = 4.0
    # Optional absolute cap (e.g. the severity ladder's top rung).
    threshold_ceiling: float | None = None
    # Minimum window before the controller may move, and batches to wait before
    # the drift machinery is allowed to re-anchor the baseline.
    min_window: int = 64
    warmup_batches: int = 2
    window_size: int = 2000

    # ── drift ──
    psi_alert: float = 0.25
    psi_severe: float = 0.5
    ks_alert: float = 0.15
    rebaseline_patience: int = 5
    rebaseline_alpha: float = 0.25

    # ── residual calibrator (supervised) ──
    max_logit_shift: float = 1.5
    calibrator_lr: float = 0.08
    calibrator_l2: float = 2e-3
    calibrator_decay: float = 0.01
    nominal_margin: float = 0.10
    nominal_weight: float = 0.25
    analyst_weight: float = 1.0
    max_negatives_per_batch: int = 256
    nominal_negatives_blocked_on_drift: bool = True

    # ── bookkeeping ──
    history_size: int = 240
    state_path: str | None = None
    save_every_batches: int = 1

    @classmethod
    def from_env(cls) -> "OnlineLearningConfig":
        """Build a config from the detector's environment variables."""

        def _flag(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            if raw is None or str(raw).strip() == "":
                return default
            return str(raw).strip().lower() in ("1", "true", "yes", "on")

        def _num(name: str, default: float) -> float:
            raw = os.getenv(name)
            if raw is None or str(raw).strip() == "":
                return default
            try:
                return float(raw)
            except ValueError:
                logger.warning("Ignoring non-numeric %s=%r", name, raw)
                return default

        ceiling = os.getenv("ONLINE_LEARNING_CEILING")
        return cls(
            enabled=_flag("ONLINE_LEARNING", True),
            target_alert_rate=_num("ONLINE_LEARNING_TARGET_RATE", cls.target_alert_rate),
            threshold_step=_num("ONLINE_LEARNING_STEP", cls.threshold_step),
            max_logit_shift=_num("ONLINE_LEARNING_MAX_SHIFT", cls.max_logit_shift),
            threshold_ceiling=float(ceiling) if ceiling not in (None, "") else None,
            state_path=os.getenv("ONLINE_LEARNING_STATE", _DEFAULT_STATE_PATH),
        )


# ── Reference distribution ────────────────────────────────────────────────────


@dataclass
class ScoreReference:
    """A fixed-size histogram of a score distribution, plus its provenance.

    Two roles, deliberately separated:

    * **Baseline** -- frozen snapshot the current window is compared against to
      measure drift.  Re-anchored only by ``DriftMonitor``, and only after the
      shift has persisted (otherwise a permanently shifted deployment would report
      "drift" forever, which measures the baseline's age rather than the network).
    * **Prior** -- which scores are dense and which are in the tail, used for the
      novelty feature and for a cold-start operating point when no calibrated
      threshold exists.
    """

    counts: list[int] = field(default_factory=lambda: [0] * N_BINS)
    n: int = 0
    source: str = "empty"

    def distribution(self) -> list[float]:
        return _as_distribution(self.counts)

    def density(self, p: float) -> float:
        """Probability mass per unit score at ``p``."""
        return self.distribution()[_bin_of(p)] / _BIN_WIDTH

    def quantile(self, q: float) -> float:
        """Score at quantile ``q``, interpolated inside the containing bin."""
        dist = self.distribution()
        if sum(dist) <= 0:
            return float("nan")
        target = min(1.0, max(0.0, q))
        acc = 0.0
        for i, mass in enumerate(dist):
            if mass <= 0:
                continue
            if acc + mass >= target:
                frac = (target - acc) / mass
                return _BIN_WIDTH * (i + min(1.0, max(0.0, frac)))
            acc += mass
        return 1.0

    def reanchor(self, observed: Sequence[int], alpha: float) -> None:
        """Move the baseline toward ``observed`` by ``alpha`` (EWMA on counts)."""
        for i, c in enumerate(observed):
            if i >= len(self.counts):
                break
            self.counts[i] = int(round((1.0 - alpha) * self.counts[i] + alpha * c))
        self.n = sum(self.counts)
        self.source = f"{self.source.split('|reanchored')[0]}|reanchored"

    def replace_with(self, observed: Sequence[int], source: str) -> None:
        self.counts = [int(c) for c in observed]
        self.n = sum(self.counts)
        self.source = source

    def novelty(self, p: float) -> float:
        """Negative log relative density, clamped to [0, 5].

        ~0 for scores in the dense bulk of the reference, rising toward 5 for
        scores the reference barely (or never) produced.  This is the feature that
        lets the calibrator say "I have no experience of this region" instead of
        extrapolating a verdict from regions it does know.
        """
        d = max(self.density(p), 1e-3)
        return min(5.0, max(0.0, math.log(1.0 / d)))

    def to_dict(self) -> dict[str, Any]:
        return {"counts": list(self.counts), "n": self.n, "source": self.source}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScoreReference":
        counts = list(data.get("counts") or [0] * N_BINS)
        if len(counts) != N_BINS:
            counts = (counts + [0] * N_BINS)[:N_BINS]
        return cls(counts=counts, n=int(data.get("n") or sum(counts)),
                   source=str(data.get("source") or "restored"))


@dataclass
class DriftReport:
    """Per-window drift measurement."""

    psi: float = 0.0
    ks: float = 0.0
    verdict: str = "unobserved"   # unobserved | stable | shift | severe
    streak: int = 0
    rebaselined: bool = False
    reanchors: int = 0
    novelty_mean: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Residual calibrator ───────────────────────────────────────────────────────

# Feature layout, in order.  Kept as a constant because the weight vector is
# persisted and a silent reordering would misread a restored checkpoint.
_CAL_FEATURES = (
    "bias",
    "logit_p_minus_anchor",   # score relative to the calibrated operating point
    "bot_evidence",           # p_bot - 0.5 (0 when the specialist was not consulted)
    "novelty",                # how far outside the reference distribution the score is
    "drift",                  # clipped PSI, so the residual can shrink when the
                              # comparison it was learned against is stale
)


@dataclass
class OnlineLogisticCalibrator:
    """Bounded online logistic regression applied as a log-odds residual.

    Why a residual and not a replacement model: the gate's ranking is the asset
    (it is what the offline evaluation measured), and a small linear correction on
    top of it can only nudge that ranking, never invert it wholesale.  With
    ``w = 0`` the mapping is the identity -- the tests assert exact equality, not
    approximate -- so shipping this layer cannot change the detector's behaviour
    until there is evidence to justify a change.

    Optimiser: AdaGrad on the log-loss, so features that fire rarely still get a
    usable step size, plus L2 and per-update exponential decay for forgetting.
    The decay is what makes this *tracking* rather than accumulating: labels from
    a traffic regime that no longer exists should not dominate forever.
    """

    n_features: int = len(_CAL_FEATURES)
    lr: float = 0.08
    l2: float = 2e-3
    decay: float = 0.01
    max_shift: float = 1.5
    w: list[float] = field(default_factory=lambda: [0.0] * len(_CAL_FEATURES))
    grad_sq: list[float] = field(default_factory=lambda: [0.0] * len(_CAL_FEATURES))
    updates: int = 0
    positives: int = 0
    negatives: int = 0
    _shift_sum: float = 0.0

    # ── feature construction ──

    def features(
        self,
        p_attack: float,
        p_bot: float | None = None,
        novelty: float = 0.0,
        psi: float = 0.0,
    ) -> list[float]:
        z = logit(min(1.0 - _LOGIT_EPS, max(_LOGIT_EPS, float(p_attack))))
        bot = 0.0 if p_bot is None else (float(p_bot) - 0.5)
        return [
            1.0,
            z,
            bot,
            float(novelty),
            min(1.0, max(0.0, float(psi))),
        ]

    def raw_shift(self, phi: Sequence[float]) -> float:
        return sum(wi * xi for wi, xi in zip(self.w, phi))

    def shift(self, phi: Sequence[float]) -> float:
        """The residual actually applied, clipped to ``max_shift`` logits."""
        return max(-self.max_shift, min(self.max_shift, self.raw_shift(phi)))

    def transform(self, p_attack: float, phi: Sequence[float]) -> float:
        """Apply the residual to a probability."""
        z = logit(min(1.0 - _LOGIT_EPS, max(_LOGIT_EPS, float(p_attack))))
        return sigmoid(z + self.shift(phi))

    # ── learning ──

    def learn(self, phi: Sequence[float], label: int, weight: float = 1.0) -> float:
        """One AdaGrad step on the weighted log-loss.  Returns the gradient norm."""
        label = 1 if label else 0
        pred = sigmoid(self.raw_shift(phi))
        err = (pred - label) * float(weight)
        if abs(err) < 1e-12:
            return 0.0

        norm = 0.0
        for i, x in enumerate(phi):
            g = err * x + self.l2 * self.w[i]
            self.grad_sq[i] += g * g
            step = self.lr * g / (math.sqrt(self.grad_sq[i]) + 1e-8)
            self.w[i] -= step
            # Forgetting: shrink every weight toward zero a little on each update.
            self.w[i] *= (1.0 - self.decay)
            norm += g * g
        self.updates += 1
        self.positives += label
        self.negatives += 0 if label else 1
        return math.sqrt(norm)

    def shift_norm(self) -> float:
        return math.sqrt(sum(w * w for w in self.w))

    def to_dict(self) -> dict[str, Any]:
        return {
            "features": list(_CAL_FEATURES),
            "w": list(self.w),
            "grad_sq": list(self.grad_sq),
            "updates": self.updates,
            "positives": self.positives,
            "negatives": self.negatives,
            "max_shift": self.max_shift,
        }

    def load_dict(self, data: dict[str, Any]) -> None:
        feats = list(data.get("features") or [])
        if feats and feats != list(_CAL_FEATURES):
            logger.warning(
                "Calibrator checkpoint feature order %s != %s — ignoring weights",
                feats, list(_CAL_FEATURES),
            )
        else:
            w = list(data.get("w") or [])
            g = list(data.get("grad_sq") or [])
            if len(w) == self.n_features:
                self.w = [float(x) for x in w]
            if len(g) == self.n_features:
                self.grad_sq = [float(x) for x in g]
        self.updates = int(data.get("updates") or 0)
        self.positives = int(data.get("positives") or 0)
        self.negatives = int(data.get("negatives") or 0)


# ── The adaptive policy ───────────────────────────────────────────────────────


class OnlineLearningPolicy:
    """The whole layer: observe → measure drift → control the rate → re-rank.

    The object is driver-side state for a Spark ``foreachBatch`` handler, so every
    method is synchronous, allocation-light, and free of dependencies beyond the
    standard library.  ``observe()`` is the only method called on every batch;
    ``learn_feedback()`` is called on a slower timer.
    """

    def __init__(
        self,
        thresholds: Thresholds | None = None,
        config: OnlineLearningConfig | None = None,
        calibrated_threshold: float | None = None,
    ):
        self.config = config or OnlineLearningConfig()
        th = thresholds or load_thresholds()
        self.thresholds = th

        # The anchor.  Everything the layer does is expressed relative to this, so
        # it is stored explicitly rather than read back from `thresholds` later
        # (the caller may replace the policy's Thresholds object per batch).
        anchor = calibrated_threshold
        if anchor is None:
            anchor = th.attack_threshold
        self.calibrated_threshold = float(anchor)
        self.threshold = self.calibrated_threshold

        self.reference = ScoreReference()
        self.baseline = ScoreReference()
        self.drift = DriftReport()

        self.calibrator = OnlineLogisticCalibrator(
            lr=self.config.calibrator_lr,
            l2=self.config.calibrator_l2,
            decay=self.config.calibrator_decay,
            max_shift=self.config.max_logit_shift,
        )

        self._window: deque[float] = deque(maxlen=self.config.window_size)
        self._window_sorted: list[float] = []
        self._window_dirty = True

        self.batches_observed = 0
        self.flows_scored = 0
        self.flows_alerted = 0
        self.alert_rate_ema: float | None = None
        self.last_target_threshold: float | None = None
        self.budget_saturated = False
        self._shift_sum = 0.0
        self._shift_count = 0
        self._last_batch_size = 0
        self.history: deque[dict[str, Any]] = deque(maxlen=self.config.history_size)
        self.feedback_learned = 0
        self.feedback_by_source: Counter[str] = Counter()
        self.nominal_negative_flow = 0
        self._seen_feedback: deque[str] = deque(maxlen=4096)
        self._seen_feedback_set: set[str] = set()
        self.saved_at: str | None = None
        self._batch_id: int | None = None

    # ── properties ──

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled)

    def threshold_bounds(self) -> tuple[float, float]:
        """The band the adapted cut is clamped to, derived from the anchor.

        The upper bound defaults to the severity ladder's **High** rung, not
        infinity and not the Critical rung.  Adapting past the top rung would
        collapse the ladder into a single band -- every alert would grade
        Critical, and the word would stop describing anything -- so the ceiling is
        set where the ladder still has room above it.  On an attack-dense stream a
        strict budget therefore saturates at High-dominant alerting (with
        ``budget_saturated`` telling you it saturated) rather than either muting
        the feed or relabelling everything as a critical incident.
        """
        lo = self.calibrated_threshold * self.config.threshold_lower_ratio
        ceiling = self.config.threshold_ceiling
        if ceiling is None:
            ceiling = getattr(self.thresholds, "severity_high", None)
        if ceiling is None:
            ceiling = 1.0
        hi = min(self.calibrated_threshold * self.config.threshold_upper_ratio,
                 float(ceiling))
        if hi < lo:  # pathological config; keep a usable (degenerate) band
            hi = lo
        return max(0.0, lo), min(1.0, hi)

    def effective_threshold(self) -> float:
        """The cut the detector should gate on right now."""
        if not self.enabled:
            return self.calibrated_threshold
        lo, hi = self.threshold_bounds()
        return max(lo, min(hi, self.threshold))

    def prefilter_threshold(self) -> float:
        """Cheapest Spark-side filter that cannot drop a row the gate would keep.

        The exact test is ``adapted_score(p) >= t``, and the residual is bounded by
        ``max_logit_shift``, so any row that could pass satisfies
        ``logit(p) >= logit(t) - max_shift``.  Filtering on that keeps the expensive
        Bot specialist off rows that cannot be alerts, without changing the answer.
        """
        t = self.effective_threshold()
        z = logit(min(1.0 - _LOGIT_EPS, max(_LOGIT_EPS, t)))
        return max(0.0, min(1.0, sigmoid(z - self.config.max_logit_shift)))

    def apply_to_thresholds(self, thresholds: Thresholds | None = None) -> Thresholds:
        """Return ``Thresholds`` with the operating point replaced by the adapted one.

        ``severity_medium`` moves with ``attack_threshold`` on purpose.
        ``detection_policy`` documents the invariant that a flow reaching the alert
        pipeline is never graded ``Low``, which holds *because*
        ``severity_medium == attack_threshold`` in the calibrated artifact.  Raise
        the cut without raising that rung and every alert between the two becomes a
        ``Low`` severity alert -- a band nothing in the pipeline has ever emitted.
        """
        base = thresholds or self.thresholds
        t = self.effective_threshold()
        return replace(base, attack_threshold=t, severity_medium=t)

    # ── decision-side API ──

    def adapt_score(self, p_attack: float | None, p_bot: float | None = None) -> float:
        """The score the alert decision is actually made on.

        Exact identity while the calibrator has no evidence (``w == 0``), and
        bounded in log-odds afterwards.
        """
        if p_attack is None:
            return 0.0
        try:
            p = float(p_attack)
        except (TypeError, ValueError):
            return 0.0
        if not self.enabled or not math.isfinite(p):
            return p
        if not any(self.calibrator.w):
            return p  # identity fast path; also guarantees bit-exactness
        phi = self.calibrator.features(
            p, p_bot=p_bot, novelty=self.reference.novelty(p), psi=self.drift.psi
        )
        return self.calibrator.transform(p, phi)

    def classify(
        self,
        p_attack: float | None,
        p_bot: float | None = None,
        thresholds: Thresholds | None = None,
        attack_type_hint: str | None = None,
    ) -> dict[str, Any] | None:
        """The detector's per-flow decision, with the adaptive layer applied.

        This is the whole decision path in one place -- adapted score, adapted
        operating point, ``detection_policy``'s verdict -- so the glue the Spark
        ``foreachBatch`` loop runs is exercisable without Spark, and the returned
        dict carries the audit trail an operator needs to explain any alert after
        the fact (raw score, adapted score, the cut that was used, and how much
        evidence the residual had).

        Returns ``None`` when the flow is below the gate, exactly like
        ``classify_flow``.
        """
        base = thresholds or self.thresholds
        effective = self.apply_to_thresholds(base)
        p_decision = self.adapt_score(p_attack, p_bot)
        verdict = classify_flow(
            p_decision, p_bot, effective, attack_type_hint=attack_type_hint
        )
        if verdict is None:
            return None
        raw = None
        try:
            raw = None if p_attack is None else float(p_attack)
        except (TypeError, ValueError):
            raw = None
        verdict["p_attack_raw"] = raw
        verdict["p_attack_adapted"] = p_decision
        verdict["score_shift"] = None if raw is None else (p_decision - raw)
        verdict["threshold_used"] = effective.attack_threshold
        verdict["calibrated_threshold"] = self.calibrated_threshold
        verdict["learning_updates"] = self.calibrator.updates
        return verdict

    def shift_for(self, p_attack: float, p_bot: float | None = None) -> float:
        """Signed log-odds residual applied to ``p_attack`` (0.0 when identity)."""
        p = float(p_attack)
        if not self.enabled or not any(self.calibrator.w):
            return 0.0
        phi = self.calibrator.features(
            p, p_bot=p_bot, novelty=self.reference.novelty(p), psi=self.drift.psi
        )
        return self.calibrator.shift(phi)

    # ── observation ──

    def observe(
        self,
        scores: Sequence[float],
        batch_id: int | None = None,
        alert_count: int | None = None,
        learned_feedback: int = 0,
    ) -> dict[str, Any]:
        """Ingest one batch of scored flows and update the decision point.

        ``scores`` must be the scores of **all** flows in the batch, not just the
        alerts -- the budget is a fraction of scored traffic, and a pool of alerts
        alone cannot measure it.

        Returns the telemetry record for this batch, which the caller persists;
        the dashboard's learning panel is rendered entirely from these records.
        """
        self._batch_id = batch_id
        self.batches_observed += 1
        clean = [float(s) for s in scores if s is not None and math.isfinite(float(s))]
        n = len(clean)
        self.flows_scored += n
        self._last_batch_size = n
        if alert_count is not None:
            note = self.note_alerts(alert_count)
            if note is None:
                rate = (int(alert_count) / n) if n else 0.0
                self.alert_rate_ema = (
                    rate if self.alert_rate_ema is None
                    else 0.9 * self.alert_rate_ema + 0.1 * rate
                )

        if n:
            self._window.extend(clean)
            self._window_dirty = True
            if self.reference.source == "empty":
                # Cold start: the first observed batch is the only available
                # statement about "what this deployment's traffic looks like".
                # Recorded as such, because it is a weaker claim than a reference
                # derived from the calibration artifact's benign holdout.
                self.reference.replace_with(
                    _histogram(clean), f"bootstrap:batch{batch_id if batch_id is not None else '?'}"
                )
                self.baseline.replace_with(list(self.reference.counts), self.reference.source)
                self.threshold = self._initial_threshold()
            self._update_drift()
            self._update_threshold()

        record = self._telemetry(learned_feedback=learned_feedback)
        self.history.append(record)
        return record

    def prime_reference(self, scores: Sequence[float], source: str = "prime") -> int:
        """Seed the baseline from a known-good score sample.

        The strongest available reference is the score distribution of the
        calibration artifact's *benign* holdout, because that is the population the
        deployed cut was derived from.  When a deployment has that sample, priming
        with it makes the first drift measurement meaningful instead of comparing
        live traffic against the first live batch -- a baseline whose only virtue is
        that it arrived first.

        Returns the number of scores accepted.
        """
        clean = [float(s) for s in scores if s is not None and math.isfinite(float(s))]
        if not clean:
            return 0
        self.reference.replace_with(_histogram(clean), source)
        self.baseline.replace_with(list(self.reference.counts), source)
        self.threshold = self._initial_threshold()
        logger.info(
            "Online learning: reference primed from %s (%d scores); p50=%.4f p99=%.4f",
            source, len(clean), self.reference.quantile(0.5), self.reference.quantile(0.99),
        )
        return len(clean)

    def note_alerts(self, alert_count: int) -> dict[str, Any] | None:
        """Fold a batch's realized alert count into the record ``observe`` returned.

        The rate the detector *actually* achieves is known only after the gate has
        run, i.e. after ``observe`` has already produced its telemetry record.  This
        updates the counters and the last record in place so the persisted row
        reports the realized rate rather than a placeholder.
        """
        n = self._last_batch_size
        if n <= 0:
            return None
        count = int(alert_count)
        self.flows_alerted += count
        rate = count / n
        self.alert_rate_ema = (
            rate if self.alert_rate_ema is None
            else 0.9 * self.alert_rate_ema + 0.1 * rate
        )
        record = self.history[-1] if self.history else None
        if record is not None:
            record["alerts"] = count
            record["alert_rate"] = rate
            record["alert_rate_ema"] = self.alert_rate_ema
        return record

    def _initial_threshold(self) -> float:
        """Cold-start cut: the calibrated anchor when there is one, else the
        budget quantile of the bootstrapped reference."""
        if self.calibrated_threshold > 0:
            return self.calibrated_threshold
        q = self.reference.quantile(1.0 - self.config.target_alert_rate)
        return q if math.isfinite(q) else 0.5

    def _update_drift(self) -> None:
        """Measure the window against the baseline and re-anchor when the shift sticks."""
        if self.reference.n == 0:
            self.drift.verdict = "unobserved"
            return
        observed = _as_distribution(_histogram(self._window))
        ref = self.baseline.distribution()
        psi = population_stability_index(ref, observed)
        ks = ks_statistic(ref, observed)

        if psi >= self.config.psi_severe:
            verdict = "severe"
        elif psi >= self.config.psi_alert or ks >= self.config.ks_alert:
            verdict = "shift"
        else:
            verdict = "stable"

        rebaselined = False
        if verdict != "stable" and self.batches_observed > self.config.warmup_batches:
            self.drift.streak += 1
            if self.drift.streak >= self.config.rebaseline_patience:
                # The shift is not a blip.  Re-anchor so the *next* comparison
                # measures further movement rather than the age of the baseline,
                # and count the re-anchor: a rising count is the signal that the
                # deployment is not the one the model was measured on.
                self.baseline.reanchor(_histogram(self._window), self.config.rebaseline_alpha)
                self.reference.reanchor(_histogram(self._window), self.config.rebaseline_alpha)
                self.drift.reanchors += 1
                self.drift.streak = 0
                rebaselined = True
                verdict = "stable"
                logger.warning(
                    "Online learning: score distribution re-anchored after %d drifted "
                    "windows (PSI=%.3f, KS=%.3f). The deployed traffic no longer matches "
                    "the baseline this detector was calibrated against.",
                    self.config.rebaseline_patience, psi, ks,
                )
        else:
            self.drift.streak = 0

        self.drift.psi = psi
        self.drift.ks = ks
        self.drift.verdict = verdict
        self.drift.rebaselined = rebaselined
        self.drift.novelty_mean = (
            sum(self.reference.novelty(p) for p in self._window) / len(self._window)
            if self._window else 0.0
        )

    def _update_threshold(self) -> None:
        """Track the ``1 - budget`` quantile of the *adapted* score distribution.

        Run in adapted space on purpose: the calibrator moves the scores, so
        controlling the raw quantile would leave the two mechanisms fighting --
        the calibrator would lower scores while the controller kept the raw cut
        pinned, and the realized alert rate would drift away from the budget
        without either part being wrong.
        """
        if len(self._window) < self.config.min_window:
            return
        if self.batches_observed <= self.config.warmup_batches:
            return

        # Neutral p_bot in the window: the Bot specialist is only scored above the
        # prefilter, so the controller cannot see its value for most flows.  The
        # bot feature is bounded by |w_bot| * 0.5, i.e. a fraction of the residual
        # budget, so the rate estimate stays honest.
        adapted = sorted(self.adapt_score(p, None) for p in self._window)
        target = _quantile(adapted, 1.0 - self.config.target_alert_rate)
        if not math.isfinite(target):
            return

        lo, hi = self.threshold_bounds()
        clamped = max(lo, min(hi, target))
        self.budget_saturated = abs(clamped - target) > 1e-9
        self.last_target_threshold = float(target)
        step = self.config.threshold_step
        self.threshold = self.threshold + step * (clamped - self.threshold)
        self.threshold = max(lo, min(hi, self.threshold))

    # ── supervision ──

    def learn_feedback(self, rows: Iterable[dict[str, Any]]) -> int:
        """Learn from labelled verdicts (analyst feedback).

        Each row needs ``p_attack`` and a verdict in one of two polarities:
        ``confirmed``/``attack``/``true_positive`` -> attack; ``false_positive``/
        ``benign``/``fp`` -> benign.  Rows without a usable score are skipped rather
        than guessed at.  Duplicate ids are ignored so a re-read of the feedback
        collection cannot double-count.
        """
        learned = 0
        for row in rows:
            rid = row.get("_id") or row.get("id")
            rid = str(rid) if rid is not None else None
            if rid is not None:
                if rid in self._seen_feedback_set:
                    continue
                if len(self._seen_feedback) == self._seen_feedback.maxlen:
                    self._seen_feedback_set.discard(self._seen_feedback[0])
                self._seen_feedback.append(rid)
                self._seen_feedback_set.add(rid)

            label = _verdict_label(row.get("verdict") or row.get("label"))
            if label is None:
                logger.warning("Online learning: unusable feedback verdict %r", row.get("verdict"))
                continue
            p = row.get("p_attack")
            if p is None:
                continue
            try:
                p = float(p)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(p):
                continue

            weight = row.get("weight")
            if weight is None:
                weight = self.config.analyst_weight
            source = str(row.get("source") or "analyst")
            self._learn_one(p, row.get("p_bot"), label, float(weight), source)
            learned += 1
        if learned:
            logger.info(
                "Online learning: %d labelled verdicts consumed (%d total; %s)",
                learned, self.feedback_learned,
                ", ".join(f"{k}={v}" for k, v in sorted(self.feedback_by_source.items())),
            )
        return learned

    def learn_nominal_negatives(self, scores: Sequence[float]) -> int:
        """Use the stream's clearly-benign majority as down-weighted negatives.

        Guarded twice: only scores at or below ``nominal_margin`` x the current cut
        qualify (deep in the bulk, not near the boundary), and the whole path is
        skipped while the drift verdict is severe -- in a severe shift a low score
        is not evidence of benignity, it is evidence that the model is looking at
        traffic it has never seen.
        """
        if not self.enabled or not scores:
            return 0
        if (self.config.nominal_negatives_blocked_on_drift
                and self.drift.verdict == "severe"):
            return 0
        cut = self.config.nominal_margin * self.effective_threshold()
        taken = 0
        for s in scores:
            if taken >= self.config.max_negatives_per_batch:
                break
            try:
                p = float(s)
            except (TypeError, ValueError):
                continue
            if not math.isfinite(p) or p > cut:
                continue
            self._learn_one(p, None, 0, self.config.nominal_weight, "nominal")
            taken += 1
        if taken:
            self.nominal_negative_flow += taken
        return taken

    def _learn_one(
        self,
        p_attack: float,
        p_bot: Any,
        label: int,
        weight: float,
        source: str,
    ) -> None:
        try:
            p_bot = None if p_bot is None else float(p_bot)
        except (TypeError, ValueError):
            p_bot = None
        phi = self.calibrator.features(
            p_attack,
            p_bot=p_bot,
            novelty=self.reference.novelty(p_attack),
            psi=self.drift.psi,
        )
        self.calibrator.learn(phi, label, weight)
        self.feedback_learned += 1
        self.feedback_by_source[source] += 1
        self._shift_sum += self.calibrator.shift(phi)
        self._shift_count += 1

    # ── reporting ──

    def _telemetry(self, learned_feedback: int = 0) -> dict[str, Any]:
        lo, hi = self.threshold_bounds()
        return {
            "type": "learning_telemetry",
            "batch_id": self._batch_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "flows_scored": self.flows_scored,
            "flows_in_batch": self._last_batch_size,
            "alerts": None,
            "alert_rate": None,
            "window_size": len(self._window),
            "threshold": self.effective_threshold(),
            "calibrated_threshold": self.calibrated_threshold,
            "threshold_delta": self.effective_threshold() - self.calibrated_threshold,
            "threshold_bounds": [lo, hi],
            "budget": self.config.target_alert_rate,
            "budget_saturated": self.budget_saturated,
            "alert_rate_ema": self.alert_rate_ema,
            "psi": self.drift.psi,
            "ks": self.drift.ks,
            "drift": self.drift.verdict,
            "drift_reanchors": self.drift.reanchors,
            "novelty_mean": self.drift.novelty_mean,
            "calibrator_updates": self.calibrator.updates,
            "calibrator_positives": self.calibrator.positives,
            "calibrator_negatives": self.calibrator.negatives,
            "shift_mean": (self._shift_sum / self._shift_count) if self._shift_count else 0.0,
            "weights_norm": self.calibrator.shift_norm(),
            "learned_feedback": learned_feedback,
        }

    def snapshot(self, include_history: bool = False) -> dict[str, Any]:
        """Full state for the API/dashboard (and for a human reading a checkpoint)."""
        lo, hi = self.threshold_bounds()
        t = self.effective_threshold()
        snapshot: dict[str, Any] = {
            "type": "learning_state",
            "enabled": self.enabled,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "batches_observed": self.batches_observed,
            "flows_scored": self.flows_scored,
            "flows_alerted": self.flows_alerted,
            "operating_point": {
                "calibrated_threshold": self.calibrated_threshold,
                "threshold": t,
                "threshold_delta": t - self.calibrated_threshold,
                "bounds": [lo, hi],
                "target_quantile_threshold": self.last_target_threshold,
                "budget": self.config.target_alert_rate,
                "budget_saturated": self.budget_saturated,
                "alert_rate_ema": self.alert_rate_ema,
                "anchor_source": self.thresholds.source,
            },
            "drift": self.drift.to_dict(),
            "calibrator": {
                "features": list(_CAL_FEATURES),
                "weights": list(self.calibrator.w),
                "weights_norm": self.calibrator.shift_norm(),
                "max_logit_shift": self.config.max_logit_shift,
                "mean_shift": (self._shift_sum / self._shift_count) if self._shift_count else 0.0,
                "updates": self.calibrator.updates,
                "positives": self.calibrator.positives,
                "negatives": self.calibrator.negatives,
                "identity": not any(self.calibrator.w),
            },
            "feedback": {
                "learned": self.feedback_learned,
                "by_source": dict(self.feedback_by_source),
                "nominal_negatives": self.nominal_negative_flow,
            },
            "reference": {
                **self.reference.to_dict(),
                "baseline_source": self.baseline.source,
                "bins": N_BINS,
                "quantiles": {
                    "p50": self.reference.quantile(0.5),
                    "p90": self.reference.quantile(0.9),
                    "p99": self.reference.quantile(0.99),
                },
            },
        }
        if include_history:
            snapshot["history"] = list(self.history)
        return snapshot

    # ── persistence ──

    def state_dict(self) -> dict[str, Any]:
        """Everything needed to resume learning, plus the last telemetry window."""
        return {
            "version": 1,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            "config": asdict(self.config),
            "calibrated_threshold": self.calibrated_threshold,
            "threshold": self.threshold,
            "thresholds_source": self.thresholds.source,
            "batches_observed": self.batches_observed,
            "flows_scored": self.flows_scored,
            "flows_alerted": self.flows_alerted,
            "alert_rate_ema": self.alert_rate_ema,
            "last_target_threshold": self.last_target_threshold,
            "budget_saturated": self.budget_saturated,
            "reference": self.reference.to_dict(),
            "baseline": self.baseline.to_dict(),
            "drift": self.drift.to_dict(),
            "calibrator": self.calibrator.to_dict(),
            "feedback_learned": self.feedback_learned,
            "feedback_by_source": dict(self.feedback_by_source),
            "nominal_negative_flow": self.nominal_negative_flow,
            "shift_accumulator": [self._shift_sum, self._shift_count],
            "seen_feedback_ids": list(self._seen_feedback),
            "history": list(self.history),
        }

    def save(self, path: str | os.PathLike | None = None) -> bool:
        """Atomically persist the learning state.  Never raises.

        Atomic because the writer is a streaming job that may be killed at any
        moment: a truncated checkpoint would be silently loaded as "no learning"
        on the next start, which is worse than a stale one.
        """
        target = Path(path or self.config.state_path or _DEFAULT_STATE_PATH)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(target.parent), prefix=".learning-", suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.state_dict(), fh)
            os.replace(tmp, target)
            self.saved_at = datetime.now(timezone.utc).isoformat()
            return True
        except OSError as exc:
            logger.warning("Could not persist online-learning state to %s: %s", target, exc)
            return False

    def load_state(self, data: dict[str, Any]) -> None:
        """Restore learning state produced by ``state_dict()``.

        Deliberately tolerant: a checkpoint written by an older config restores
        what it can and re-clamps the operating point to the *current* band, so a
        changed bound cannot resurrect an out-of-band threshold.
        """
        if not isinstance(data, dict):
            return
        try:
            self.calibrated_threshold = float(
                data.get("calibrated_threshold", self.calibrated_threshold)
            )
            self.threshold = float(data.get("threshold", self.calibrated_threshold))
            self.batches_observed = int(data.get("batches_observed") or 0)
            self.flows_scored = int(data.get("flows_scored") or 0)
            self.flows_alerted = int(data.get("flows_alerted") or 0)
            rate = data.get("alert_rate_ema")
            self.alert_rate_ema = None if rate is None else float(rate)
            target = data.get("last_target_threshold")
            self.last_target_threshold = None if target is None else float(target)
            self.budget_saturated = bool(data.get("budget_saturated"))
            self.reference = ScoreReference.from_dict(data.get("reference") or {})
            self.baseline = ScoreReference.from_dict(data.get("baseline") or {})
            self._restore_drift(data.get("drift") or {})
            self.calibrator.load_dict(data.get("calibrator") or {})
            self.feedback_learned = int(data.get("feedback_learned") or 0)
            self.feedback_by_source = Counter(data.get("feedback_by_source") or {})
            self.nominal_negative_flow = int(data.get("nominal_negative_flow") or 0)
            acc = data.get("shift_accumulator") or [0.0, 0]
            self._shift_sum, self._shift_count = float(acc[0]), int(acc[1])
            for rid in data.get("seen_feedback_ids") or []:
                rid = str(rid)
                self._seen_feedback.append(rid)
                self._seen_feedback_set.add(rid)
            for record in data.get("history") or []:
                self.history.append(record)
        except (TypeError, ValueError) as exc:
            logger.warning("Ignoring malformed online-learning state: %s", exc)
            return

        lo, hi = self.threshold_bounds()
        self.threshold = max(lo, min(hi, self.threshold))
        if self.reference.n == 0:
            # A restored policy with no reference restarts drift measurement from
            # the next window rather than pretending the baseline survived.
            logger.warning("Online-learning state had no usable reference — will bootstrap.")

    def _restore_drift(self, data: dict[str, Any]) -> None:
        self.drift = DriftReport(
            psi=float(data.get("psi") or 0.0),
            ks=float(data.get("ks") or 0.0),
            verdict=str(data.get("verdict") or "unobserved"),
            streak=int(data.get("streak") or 0),
            rebaselined=bool(data.get("rebaselined")),
            reanchors=int(data.get("reanchors") or 0),
            novelty_mean=float(data.get("novelty_mean") or 0.0),
        )

    @classmethod
    def load_or_new(
        cls,
        path: str | os.PathLike | None = None,
        thresholds: Thresholds | None = None,
        config: OnlineLearningConfig | None = None,
    ) -> "OnlineLearningPolicy":
        """Resume from a checkpoint when one exists, otherwise start fresh."""
        cfg = config or OnlineLearningConfig.from_env()
        policy = cls(thresholds=thresholds, config=cfg)
        target = path or cfg.state_path or _DEFAULT_STATE_PATH
        try:
            with open(target, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            logger.info("Online learning: no checkpoint at %s — starting fresh", target)
            return policy
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Online learning: unreadable checkpoint %s (%s) — starting fresh",
                           target, exc)
            return policy
        policy.load_state(data)
        logger.info(
            "Online learning resumed from %s: threshold %.4f (anchor %.4f), "
            "%d calibrator updates, %d labelled verdicts, %d re-anchors",
            target, policy.effective_threshold(), policy.calibrated_threshold,
            policy.calibrator.updates, policy.feedback_learned, policy.drift.reanchors,
        )
        return policy

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            f"<OnlineLearningPolicy enabled={self.enabled} t={self.effective_threshold():.4f} "
            f"anchor={self.calibrated_threshold:.4f} psi={self.drift.psi:.3f} "
            f"drift={self.drift.verdict} updates={self.calibrator.updates}>"
        )


# ── Feedback helpers ──────────────────────────────────────────────────────────

_ATTACK_VERDICTS = {
    "confirmed", "confirm", "attack", "true_positive", "tp", "malicious",
    "escalated", "escalate",
}
_BENIGN_VERDICTS = {
    "false_positive", "fp", "benign", "clean", "normal", "dismissed", "dismiss",
}


def _verdict_label(raw: Any) -> int | None:
    """Map a verdict string onto a binary label, or ``None`` when unusable."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return 1 if float(raw) > 0.5 else 0
    text = str(raw).strip().lower().replace(" ", "_").replace("-", "_")
    if text in _ATTACK_VERDICTS:
        return 1
    if text in _BENIGN_VERDICTS:
        return 0
    return None


def verdict_label(raw: Any) -> int | None:
    """Public form of ``_verdict_label`` (used by the API to validate input)."""
    return _verdict_label(raw)


# The MongoDB document key the current learning state is upserted under; the API
# reads it by name, so it lives here rather than in either caller.
LEARNING_STATE_KEY = "policy"

__all__ = [
    "DriftReport",
    "LEARNING_STATE_KEY",
    "N_BINS",
    "OnlineLearningConfig",
    "OnlineLearningPolicy",
    "OnlineLogisticCalibrator",
    "ScoreReference",
    "ks_statistic",
    "population_stability_index",
    "verdict_label",
]
