"""
eval_bot_behind_gate.py — is v3 a net win, once the Tier-2 Bot path is counted?
==============================================================================
``model_metrics.json`` ends its v3 verdict with the one number it could not
supply:

    "v3 trades Tier-1 Bot recall for cross-environment DDoS discrimination.
     Bot is nominally covered by the Tier-2 rf_bot_binary specialist, so this
     must be re-measured on the v3 gate before switching models."

That is what this script measures.  "Behind the gate" is literal: in
``backend/realtime/detection_policy.py`` the Bot specialist is only consulted
for flows the Tier-1 *binary* model already flagged as an attack.  A Bot flow
the gate rejects is never offered to the specialist, so the operative
end-to-end Bot recall is

    P(gate flags the flow)  AND  P(rf_bot scores it >= bot_threshold)

which is a *product-shaped* quantity and therefore extremely sensitive to the
gate's Bot recall.  The previously quoted "95.56% precision / 100% recall" for
the specialist was measured standalone, with no gate in front of it, so it says
nothing about this.

Everything is reported at MATCHED C2 FALSE-POSITIVE RATE, not at a fixed
P(attack) cut: v2 and v3 rescaled the scores, so the same cut sits at a
different FPR for each model, and comparing recall at a fixed cut mostly
measures the rescaling (see compare_at_matched_fpr.py).

Holdouts
--------
  C2      corpus/friday_benign_c2   286,785 BENIGN, temporal, 0% training overlap
                                     -> sets the operating point and the FP cost
  C1-Bot  corpus/friday_bot_test       570 Bot, session split, 0% overlap
                                     -> the end-to-end Bot recall
  C1-DDoS corpus/friday_ddos_test   38,348 DDoS, session split
                                     -> confirms the gate did not break DDoS
  DDOS19  corpus/ddos2019_test     306,201 rows, CIC-DDoS2019's own testing
                                     split, 0.000% fingerprint overlap with
                                     training -> the clean cross-environment probe
                                     that motivated v3 in the first place

Usage:
  docker exec threvia-spark-master bash -c "export PYTHONPATH=/workspace && \\
    /opt/spark/bin/spark-submit --master spark://spark-master:7077 \\
    --driver-memory 2g --executor-memory 2g \\
    --conf spark.executor.cores=2 \\
    /workspace/backend/ml/eval_bot_behind_gate.py"

  Optional env:
    MODELS='v1:.../models_clean,v3:.../models_clean_v3'
    BOT_MODEL=<path to rf_bot_binary>       BOT_CUT=0.50
    TARGET_FPRS=0.005,0.01,0.02,0.03,0.05  SWEEP_CUTS=0.30,...,0.90
    DEPLOYED_CUT=0.65                      JSON_OUT=/tmp/bot_gate.json
"""

import json
import os
import sys

sys.path.insert(0, '/workspace')

from pyspark.sql import SparkSession, functions as F
from pyspark.ml import PipelineModel
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.evaluation import BinaryClassificationEvaluator
from pyspark.ml.functions import vector_to_array

HDFS_ROOT = 'hdfs://namenode:8020/threvia'
BASE      = f'{HDFS_ROOT}/models_clean'

DEFAULT_MODELS = f'v1:{BASE},v3:{HDFS_ROOT}/models_clean_v3'
MODELS_SPEC    = os.getenv('MODELS', DEFAULT_MODELS)
BOT_MODEL      = os.getenv('BOT_MODEL', f'{BASE}/rf_bot_binary')

C1_BOT   = f'{HDFS_ROOT}/corpus/friday_bot_test'
C1_DDOS  = f'{HDFS_ROOT}/corpus/friday_ddos_test'
C2_BEN   = f'{HDFS_ROOT}/corpus/friday_benign_c2'
DDOS19   = f'{HDFS_ROOT}/corpus/ddos2019_test'

FEAT_COL   = 'scaled_features'
LABEL_COL  = 'Label'
BINARY_COL = 'is_attack'

BOT_CUT = float(os.getenv('BOT_CUT', '0.50'))

# 0.0365 is v1's own measured C2 FPR at the deployed cut T=0.65, so the
# comparison includes the operating point that is actually in production.
TARGET_FPRS = [float(x) for x in
               os.getenv('TARGET_FPRS',
                         '0.005,0.01,0.02,0.0365,0.05').split(',')]

SWEEP_CUTS = [float(x) for x in
              os.getenv('SWEEP_CUTS', '0.30,0.40,0.50,0.60,0.65,0.70,0.80,0.90').split(',')]

DEPLOYED_CUT = float(os.getenv('DEPLOYED_CUT', '0.65'))
JSON_OUT     = os.getenv('JSON_OUT', '')


def get_spark():
    return (
        SparkSession.builder.appName('Threvia-EvalBotBehindGate')
        .config('spark.sql.shuffle.partitions', '16')
        .config('spark.ui.enabled', 'false')
        # Standalone executors do not inherit the driver's environment.
        .config('spark.executorEnv.PYTHONPATH', '/workspace')
        .getOrCreate()
    )


def sep(msg=''):
    print('\n' + '=' * 78)
    if msg:
        print(f'  {msg}')
        print('=' * 78)


def main():
    spark = get_spark()
    spark.sparkContext.setLogLevel('ERROR')

    from backend.processing.schema_maps import (
        CANONICAL_FEATURE_COLS, LABEL_NORMALISE, label_lookup_key)
    from backend.ml.train_clean_corpus import clean_and_scale_external
    from pyspark.sql.types import StringType

    norm_map = {label_lookup_key(k): v for k, v in LABEL_NORMALISE.items()}
    bc = spark.sparkContext.broadcast(norm_map)
    # The key-collapsing rule is inlined rather than referenced: a UDF closure
    # that names a backend.* function forces the executor to import the package,
    # and in standalone mode executors do not inherit the driver's PYTHONPATH
    # (ModuleNotFoundError: No module named 'backend').  Keep this closure
    # dependency-free so `--master spark://...` works.
    label_udf = F.udf(
        lambda raw: bc.value.get(
            ''.join('-' if ord(c) > 126 else c for c in raw.strip()).upper(),
            raw.strip()) if raw else None,
        StringType(),
    )
    feat_cols = [c for c in CANONICAL_FEATURE_COLS if c != 'Label']

    versions = []
    for item in MODELS_SPEC.split(','):
        name, path = item.split(':', 1)
        versions.append((name.strip(), path.strip()))

    sep('Configuration')
    print(f'  shared scaler/medians : {BASE}')
    for n, p in versions:
        print(f'  {n:<21}: {p}')
    print(f'  Tier-2 Bot specialist : {BOT_MODEL}  (cut {BOT_CUT:.2f})')
    print(f'  matched C2 FPR targets: {TARGET_FPRS}')

    pipe = PipelineModel.load(f'{BASE}/scaler_pipeline')
    med_row = spark.read.parquet(f'{BASE}/imputer_medians').first()
    medians = dict(med_row.asDict()) if med_row else {}
    rf_bot = RandomForestClassificationModel.load(BOT_MODEL)

    def prep_raw(path):
        """Clean + scale a CSV-derived holdout on the saved scaler/medians."""
        df = clean_and_scale_external(
            spark, spark.read.parquet(path), feat_cols, pipe, label_udf,
            fill_map=medians)
        return df

    def prep_prescaled(path):
        """Holdouts written by build_corpus_v3.py already carry scaled_features."""
        return spark.read.parquet(path)

    def score(df, rf_bin, keep_raw=False):
        """binary RF (the gate) + Bot specialist -> narrow, cacheable frame."""
        out = (rf_bin.transform(df)
               .withColumn('p_attack', vector_to_array(F.col('probability'))[1]))
        if keep_raw:
            out = out.withColumn('raw_bin', F.col('rawPrediction'))
        out = out.drop('probability', 'rawPrediction', 'prediction')
        out = (rf_bot.transform(out)
               .withColumn('p_bot', vector_to_array(F.col('probability'))[1])
               .drop('probability', 'rawPrediction', 'prediction'))
        keep = [LABEL_COL, BINARY_COL, 'p_attack', 'p_bot']
        if keep_raw:
            keep.append('raw_bin')
        return out.select(*keep).cache()

    def cells(df, t):
        """One job: counts by (benign?, gate-passed?, Bot-labelled?) at cut t.

        Returns (n_all, n_gate, n_gate_and_bot, n_benign, n_benign_gate), so a
        mixed holdout like CIC-DDoS2019 yields both its attack recall and the
        false-positive rate the cut would cost on its own BENIGN rows.
        """
        rows = (df.select(
                    F.when(F.col(BINARY_COL) == 0, 1).otherwise(0).alias('ben'),
                    F.when(F.col('p_attack') >= t, 1).otherwise(0).alias('g'),
                    F.when(F.col('p_bot') >= BOT_CUT, 1).otherwise(0).alias('b'))
                .groupBy('ben', 'g', 'b').count().collect())

        def total(**kw):
            return sum(r['count'] for r in rows
                       if all(r[k] == v for k, v in kw.items()))

        return (total(), total(g=1), total(g=1, b=1),
                total(ben=1), total(ben=1, g=1))

    results = {}

    # ── per-version scoring ───────────────────────────────────────────────────
    for name, vdir in versions:
        sep(f'Scoring holdouts with {name}  ({vdir}/rf_binary)')
        try:
            rf_bin = RandomForestClassificationModel.load(f'{vdir}/rf_binary')
        except Exception as exc:
            print(f'  SKIP — {exc}')
            continue

        c2 = score(prep_raw(C2_BEN), rf_bin)
        bot = score(prep_raw(C1_BOT), rf_bin)
        ddos = score(prep_raw(C1_DDOS), rf_bin)
        # CIC-DDoS2019 is pre-scaled; keep rawPrediction for the AUC.
        ddos19 = score(prep_prescaled(DDOS19), rf_bin, keep_raw=True)

        n_c2 = c2.count()
        n_bot = bot.count()
        n_ddos = ddos.count()
        n_d19 = ddos19.count()
        n_d19_atk = ddos19.filter(F.col(BINARY_COL) == 1).count()
        print(f'  C2 BENIGN {n_c2:,} | C1 Bot {n_bot:,} | C1 DDoS {n_ddos:,} | '
              f'DDOS19 {n_d19:,} (attack {n_d19_atk:,})')

        auc_d19 = BinaryClassificationEvaluator(
            labelCol=BINARY_COL, rawPredictionCol='raw_bin',
            metricName='areaUnderROC').evaluate(ddos19)
        print(f'  DDOS19 ROC-AUC (cross-environment DDoS vs BENIGN): {auc_d19:.4f}')

        # ── raw-cut sweep (same cut for every model: the misleading view) ─────
        print(f'\n  raw-cut sweep — {"T":>5} | {"C2 FPR":>8} | {"gate Bot rec":>12} | '
              f'{"e2e Bot rec":>11} | {"Bot-lab C2 FP":>13} | {"DDoS rec":>9} | '
              f'{"DDOS19 rec":>11} | {"DDOS19 ben FPR":>15}')
        print('  ' + '-' * 110)
        sweep = []
        for t in SWEEP_CUTS:
            c2_n, c2_gate, c2_bot, _, _ = cells(c2, t)
            _, bot_gate, bot_e2e, _, _ = cells(bot, t)
            _, dd_gate, _, _, _ = cells(ddos, t)
            _, d19_gate, _, n_d19_ben, d19_ben_gate = cells(ddos19, t)
            row = dict(
                T=t,
                c2_fpr=c2_gate / c2_n,
                c2_botlab_fp=c2_bot,
                gate_bot_recall=bot_gate / n_bot,
                e2e_bot_recall=bot_e2e / n_bot,
                ddos_recall=dd_gate / n_ddos,
                ddos19_recall=d19_gate / n_d19_atk if n_d19_atk else 0.0,
                ddos19_benign_fpr=(d19_ben_gate / n_d19_ben) if n_d19_ben else 0.0,
            )
            sweep.append(row)
            print(f'  {"":>7}{t:>5.2f} | {row["c2_fpr"] * 100:>7.2f}% | '
                  f'{row["gate_bot_recall"] * 100:>11.2f}% | '
                  f'{row["e2e_bot_recall"] * 100:>10.2f}% | '
                  f'{row["c2_botlab_fp"]:>13,} | '
                  f'{row["ddos_recall"] * 100:>8.2f}% | '
                  f'{row["ddos19_recall"] * 100:>10.2f}% | '
                  f'{row["ddos19_benign_fpr"] * 100:>14.2f}%')

        # ── matched-FPR operating points (the honest comparison) ─────────────
        print('\n  matched-C2-FPR operating points:')
        matched = {}
        for target in TARGET_FPRS:
            t = c2.approxQuantile('p_attack', [1.0 - target], 0.0005)[0]
            c2_n, c2_gate, c2_bot, _, _ = cells(c2, t)
            _, bot_gate, bot_e2e, _, _ = cells(bot, t)
            _, dd_gate, _, _, _ = cells(ddos, t)
            _, d19_gate, _, n_d19_ben, d19_ben_gate = cells(ddos19, t)
            matched[target] = dict(
                T=t,
                c2_fpr=c2_gate / c2_n,
                c2_botlab_fp=c2_bot,
                gate_bot_recall=bot_gate / n_bot,
                e2e_bot_recall=bot_e2e / n_bot,
                ddos_recall=dd_gate / n_ddos,
                ddos19_recall=d19_gate / n_d19_atk if n_d19_atk else 0.0,
                ddos19_benign_fpr=(d19_ben_gate / n_d19_ben) if n_d19_ben else 0.0,
            )
            m = matched[target]
            print(f'    target {target * 100:>4.2f}% -> T={m["T"]:.3f} '
                  f'(C2 FPR {m["c2_fpr"] * 100:.2f}%) | '
                  f'gate Bot {m["gate_bot_recall"] * 100:.1f}% -> '
                  f'e2e Bot {m["e2e_bot_recall"] * 100:.1f}% | '
                  f'Bot-lab C2 FP {m["c2_botlab_fp"]:,} | '
                  f'DDoS {m["ddos_recall"] * 100:.1f}% | '
                  f'DDOS19 {m["ddos19_recall"] * 100:.2f}% | '
                  f'DDOS19 ben FPR {m["ddos19_benign_fpr"] * 100:.2f}%')

        # ── the currently deployed cut, for reference ────────────────────────
        c2_n, c2_gate, c2_bot, _, _ = cells(c2, DEPLOYED_CUT)
        _, bot_gate, bot_e2e, _, _ = cells(bot, DEPLOYED_CUT)
        _, dd_gate, _, _, _ = cells(ddos, DEPLOYED_CUT)
        _, d19_gate, _, n_d19_ben, d19_ben_gate = cells(ddos19, DEPLOYED_CUT)
        deployed = dict(
            T=DEPLOYED_CUT,
            c2_fpr=c2_gate / c2_n,
            c2_botlab_fp=c2_bot,
            gate_bot_recall=bot_gate / n_bot,
            e2e_bot_recall=bot_e2e / n_bot,
            ddos_recall=dd_gate / n_ddos,
            ddos19_recall=d19_gate / n_d19_atk if n_d19_atk else 0.0,
            ddos19_benign_fpr=(d19_ben_gate / n_d19_ben) if n_d19_ben else 0.0,
        )
        print(f'\n  at the deployed cut T={DEPLOYED_CUT:.2f}: '
              f'C2 FPR {deployed["c2_fpr"] * 100:.2f}% | '
              f'gate Bot {deployed["gate_bot_recall"] * 100:.1f}% -> '
              f'e2e Bot {deployed["e2e_bot_recall"] * 100:.1f}% | '
              f'Bot-lab C2 FP {deployed["c2_botlab_fp"]:,} | '
              f'DDoS {deployed["ddos_recall"] * 100:.1f}% | '
              f'DDOS19 {deployed["ddos19_recall"] * 100:.2f}% | '
              f'DDOS19 ben FPR {deployed["ddos19_benign_fpr"] * 100:.2f}%')

        results[name] = dict(
            model_dir=vdir,
            ddos19_auc=auc_d19,
            supports=dict(c2=n_c2, bot=n_bot, ddos=n_ddos, ddos19=n_d19,
                          ddos19_attack=n_d19_atk),
            sweep=sweep,
            matched_fpr={str(k): v for k, v in matched.items()},
            deployed=deployed,
        )

        for df in (c2, bot, ddos, ddos19):
            df.unpersist()

        spark.sparkContext._jvm.System.gc()

    if len(results) < 2:
        print('\nNeed at least two scorable versions.')
        spark.stop()
        sys.exit(1)

    # ── verdict ──────────────────────────────────────────────────────────────
    sep('VERDICT — end-to-end Bot detection at matched C2 FPR')
    names = list(results.keys())
    hdr = f'  {"target C2 FPR":<16}' + ''.join(f'{n:>26}' for n in names)
    print(hdr)
    print('  ' + '-' * (16 + 26 * len(names)))
    for target in TARGET_FPRS:
        key = str(target)
        if any(key not in results[n]['matched_fpr'] for n in names):
            continue
        line = f'  {target * 100:>13.2f}%  '
        for n in names:
            m = results[n]['matched_fpr'][key]
            line += f'  e2eBot {m["e2e_bot_recall"] * 100:>6.1f}% '
            line += f'(T={m["T"]:.3f}, DDoS19 {m["ddos19_recall"] * 100:>5.1f}%/'
            line += f'{m["ddos19_benign_fpr"] * 100:>5.1f}% FPR)'
        print(line)

    print()
    for target in TARGET_FPRS:
        key = str(target)
        if any(key not in results[n]['matched_fpr'] for n in names):
            continue
        vals = {n: results[n]['matched_fpr'][key]['e2e_bot_recall'] for n in names}
        best = max(vals, key=lambda k: vals[k])
        d19 = {n: results[n]['matched_fpr'][key]['ddos19_recall'] for n in names}
        best_d19 = max(d19, key=lambda k: d19[k])
        print(f'  at {target * 100:.2f}% C2 FPR: best end-to-end Bot = {best} '
              f'({vals[best] * 100:.1f}%), best DDOS19 DDoS = {best_d19} '
              f'({d19[best_d19] * 100:.2f}%)')

    print("""
  Reading it: the Tier-2 specialist is only consulted for flows the Tier-1
  binary gate has already flagged, so a version whose gate misses Bot flows
  loses them before the specialist is ever asked.  The end-to-end column above
  is therefore the number that decides whether a v3 switch keeps Bot
  detection alive; the DDOS19 column is the cross-environment gain v3 buys.
""")

    if JSON_OUT:
        with open(JSON_OUT, 'w', encoding='utf-8') as fh:
            json.dump(results, fh, indent=2)
        print(f'  wrote {JSON_OUT}')

    spark.stop()
    sys.exit(0)


if __name__ == '__main__':
    main()
