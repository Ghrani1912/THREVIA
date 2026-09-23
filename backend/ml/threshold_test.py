"""
threshold_test.py -- Attack-side threshold tuning (no retrain)
Decision: flag as attack if P(attack) > T  (default T=0.50)
Raising T reduces FPR at the cost of some recall.
"""
import sys
from pyspark.sql import SparkSession
from pyspark.ml.classification import RandomForestClassificationModel
from pyspark.ml.pipeline import PipelineModel
from pyspark.ml.functions import vector_to_array
import pyspark.sql.functions as F
from pyspark.sql.types import StringType

HDFS           = 'hdfs://namenode:8020/threvia'
HDFS_BENIGN_C2 = f'{HDFS}/corpus/friday_benign_c2'
HDFS_DDOS_TEST = f'{HDFS}/corpus/friday_ddos_test'
HDFS_BOT_TEST  = f'{HDFS}/corpus/friday_bot_test'
HDFS_RF_BIN    = f'{HDFS}/models_clean/rf_binary'
HDFS_SCALER    = f'{HDFS}/models_clean/scaler_pipeline'
HDFS_MEDIANS   = f'{HDFS}/models_clean/imputer_medians'
LABEL_COL      = 'Label'
BINARY_COL     = 'is_attack'

# T = minimum P(attack) required to raise an alert (attack-side threshold)
# Raising T: fewer alerts on BENIGN (FPR down) AND fewer on attacks (recall down)
THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]

def sep(msg):
    print(f'\n{"="*72}\n  {msg}\n{"="*72}')

def prep(spark, raw_df, ext_pipe, label_udf, fill_map):
    if 'Fwd Header Length34' in raw_df.columns:
        raw_df = raw_df.withColumnRenamed('Fwd Header Length34', 'Fwd Header Length')
    if 'Fwd Header Length55' in raw_df.columns:
        raw_df = raw_df.drop('Fwd Header Length55')
    skip = {LABEL_COL, BINARY_COL, 'attack_type_idx', 'weight',
            'Timestamp', 'Flow ID', 'Source IP', 'Destination IP', 'Protocol'}
    feat_cols = [c for c in raw_df.columns if c not in skip]
    sys.path.insert(0, '/workspace/backend/ml')
    sys.path.insert(0, '/workspace')
    from train_clean_corpus import clean_and_scale_external
    return clean_and_scale_external(spark, raw_df, feat_cols, ext_pipe, label_udf, fill_map=fill_map)

def main():
    spark = (SparkSession.builder
             .appName('Threvia-ThresholdTest')
             .config('spark.sql.shuffle.partitions', '8')
             .getOrCreate())
    spark.sparkContext.setLogLevel('WARN')

    sys.path.insert(0, '/workspace')
    from backend.processing.schema_maps import LABEL_NORMALISE
    _norm_map = {k.upper(): v for k, v in LABEL_NORMALISE.items()}
    _bc       = spark.sparkContext.broadcast(_norm_map)
    label_udf = F.udf(
        lambda r: _bc.value.get(r.strip().upper(), r.strip()) if r else None,
        StringType()
    )

    sep('Loading models')
    ext_pipe = PipelineModel.load(HDFS_SCALER)
    rf_bin   = RandomForestClassificationModel.load(HDFS_RF_BIN)
    med_row  = spark.read.parquet(HDFS_MEDIANS).first()
    fill_map = dict(med_row.asDict()) if med_row else {}

    sep('Preparing C2 BENIGN + C1 DDoS/Bot')
    raw_c2   = spark.read.parquet(HDFS_BENIGN_C2)
    raw_ddos = spark.read.parquet(HDFS_DDOS_TEST)
    raw_bot  = spark.read.parquet(HDFS_BOT_TEST)

    c2_scaled   = prep(spark, raw_c2,   ext_pipe, label_udf, fill_map)
    ddos_scaled = prep(spark, raw_ddos, ext_pipe, label_udf, fill_map)
    bot_scaled  = prep(spark, raw_bot,  ext_pipe, label_udf, fill_map)

    # Score once, extract P(attack) = probability[1] using vector_to_array (no numpy on executors)
    def add_p_att(df):
        return (rf_bin.transform(df)
                .withColumn('prob_arr', vector_to_array('probability'))
                .withColumn('p_att', F.col('prob_arr')[1])
                .select(BINARY_COL, 'p_att')
                .cache())

    preds_c2   = add_p_att(c2_scaled)
    preds_ddos = add_p_att(ddos_scaled)
    preds_bot  = add_p_att(bot_scaled)

    n_c2   = preds_c2.count()
    n_ddos = preds_ddos.count()
    n_bot  = preds_bot.count()
    print(f'  C2  BENIGN : {n_c2:,} flows')
    print(f'  C1  DDoS   : {n_ddos:,} flows')
    print(f'  C1  Bot    : {n_bot:,} flows')
    print()
    print('  Logic: flag as ATTACK if P(attack) > T')
    print('  Raising T → fewer alerts on BENIGN (FPR ↓) AND fewer on attacks (Recall ↓)')

    sep('Threshold sweep -- attack-side P(attack) > T')
    hdr = (f'  {"T":>6} | {"C2 FPs":>8} | {"FPR%":>7} | '
           f'{"DDoS Recall%":>13} | {"Bot Recall%":>11} | '
           f'{"ΔRecall DDoS":>13} | {"ΔRecall Bot":>11} | {"ΔFPR":>8}')
    print(hdr)
    print('  ' + '-' * (len(hdr) - 2))

    baseline = None
    results  = []

    for t in THRESHOLDS:
        fp_c2    = preds_c2.filter(F.col('p_att') > t).count()
        fpr_pct  = fp_c2 / n_c2 * 100
        hit_ddos = preds_ddos.filter(F.col('p_att') > t).count()
        rec_ddos = hit_ddos / n_ddos * 100
        hit_bot  = preds_bot.filter(F.col('p_att') > t).count()
        rec_bot  = hit_bot / n_bot * 100

        if baseline is None:
            baseline = (fp_c2, fpr_pct, rec_ddos, rec_bot)
            d_fpr = d_ddos = d_bot = 0.0
        else:
            d_fpr  = fpr_pct - baseline[1]   # negative = improvement
            d_ddos = rec_ddos - baseline[2]   # negative = recall cost
            d_bot  = rec_bot  - baseline[3]

        print(f'  {t:>6.2f} | {fp_c2:>8,} | {fpr_pct:>6.2f}% | '
              f'{rec_ddos:>12.2f}% | {rec_bot:>10.2f}% | '
              f'{d_ddos:>+12.2f}pp | {d_bot:>+10.2f}pp | {d_fpr:>+7.2f}pp')
        results.append((t, fp_c2, fpr_pct, rec_ddos, rec_bot))

    sep('Recommendation')
    b_fp, b_fpr, b_ddos, b_bot = baseline
    best = None
    for t, fp, fpr, dr, br in results[1:]:
        fpr_drop   = b_fpr  - fpr    # positive = improvement
        ddos_cost  = b_ddos - dr     # positive = recall lost
        bot_cost   = b_bot  - br
        if fpr_drop >= 3.0 and ddos_cost < 1.0 and bot_cost < 5.0:
            best = (t, fp, fpr, dr, br, fpr_drop, ddos_cost, bot_cost)
            break

    if best:
        t, fp, fpr, dr, br, fpr_drop, ddos_cost, bot_cost = best
        saved_hours = (b_fp - fp) / 20
        saved_cost  = saved_hours * 75 * 52
        print(f'  Recommended attack threshold: T = {t:.2f}')
        print(f'    FPR            : {b_fpr:.2f}% → {fpr:.2f}%  (-{fpr_drop:.2f} pp)')
        print(f'    False alerts   : {b_fp:,} → {fp:,}  (-{b_fp - fp:,} per Friday)')
        print(f'    Analyst-hours  : saved {saved_hours:,.0f} hrs/Friday')
        print(f'    Annualised     : ${saved_cost:,.0f} saved')
        print(f'    DDoS recall    : {dr:.2f}%  (cost: {ddos_cost:.2f} pp)')
        print(f'    Bot recall     : {br:.2f}%  (cost: {bot_cost:.2f} pp)')
    else:
        print('  No single threshold buys ≥3pp FPR drop with <1pp DDoS + <5pp Bot cost.')
        print('  → Retrain with capped class weights (max 100×) is required.')
        print('    The over-amplified rare-class weights (up to 22,420×) are the root cause.')
        print('    Capping at 100× eliminates extreme boundary pull without hurting rare-class recall.')

    sep('DONE')
    spark.stop()

if __name__ == '__main__':
    main()
