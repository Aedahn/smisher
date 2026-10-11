#!/usr/bin/env python3
"""
evaluate_model.py  –  Evaluate all fusion methods and produce ONE report file.

Usage:
    python evaluate_model.py gemma2_9b

Output:
    results/<model>/metrics.txt   (all results in one organised file)
"""

import os, sys, glob, warnings
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    confusion_matrix
)
from scipy.stats import chi2, binomtest

warnings.filterwarnings('ignore')

# ──────────────────────────────────────────────
#  HELPER FUNCTIONS (unchanged)
# ──────────────────────────────────────────────

def compute_metrics(y_true, y_pred, system_name):
    valid = [(t, p) for t, p in zip(y_true, y_pred) if p != -1]
    n_errors = sum(1 for p in y_pred if p == -1)
    if not valid:
        return None
    yt, yp = zip(*valid)
    try:
        tn, fp, fn, tp = confusion_matrix(yt, yp).ravel()
    except ValueError:
        return None

    acc  = accuracy_score(yt, yp)
    prec = precision_score(yt, yp, zero_division=0)
    rec  = recall_score(yt, yp, zero_division=0)
    f1   = f1_score(yt, yp, zero_division=0)
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr  = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    tnr  = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    mcc_denom = np.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc  = ((tp*tn) - (fp*fn)) / mcc_denom if mcc_denom > 0 else 0.0

    return {
        'System'    : system_name,
        'N_emails'  : len(y_pred),
        'Valid'     : len(yp),
        'Errors'    : n_errors,
        'TP' : int(tp), 'TN' : int(tn), 'FP' : int(fp), 'FN' : int(fn),
        'Accuracy'  : round(acc * 100, 2),
        'Precision' : round(prec * 100, 2),
        'Recall'    : round(rec * 100, 2),
        'F1'        : round(f1 * 100, 2),
        'FPR'       : round(fpr * 100, 2),
        'FNR'       : round(fnr * 100, 2),
        'TNR'       : round(tnr * 100, 2),
        'MCC'       : round(mcc, 4),
    }


def mcnemar_test(df_a, df_b, name_a, name_b):
    da = df_a[['email_index','true_label','predicted']].rename(columns={'predicted':'pred_a'})
    db = df_b[['email_index','true_label','predicted']].rename(columns={'predicted':'pred_b','true_label':'true_label_b'})
    merged = da.merge(db, on='email_index', how='outer')
    merged['true_label'] = merged['true_label'].fillna(merged['true_label_b'])
    merged['pred_a'] = merged['pred_a'].fillna(-1).astype(int)
    merged['pred_b'] = merged['pred_b'].fillna(-1).astype(int)
    merged['true_label'] = merged['true_label'].fillna(-1).astype(int)
    merged = merged[merged['true_label'] != -1]
    if len(merged) == 0:
        return None

    n10 = sum(1 for _, r in merged.iterrows() if r['pred_a']==r['true_label'] and r['pred_a']!=-1 and (r['pred_b']!=r['true_label'] or r['pred_b']==-1))
    n01 = sum(1 for _, r in merged.iterrows() if r['pred_b']==r['true_label'] and r['pred_b']!=-1 and (r['pred_a']!=r['true_label'] or r['pred_a']==-1))

    total = n10 + n01
    if total == 0:
        p = 1.0; sig = False
    elif total < 25:
        p = binomtest(min(n10, n01), total, 0.5).pvalue
    else:
        stat = (abs(n10 - n01) - 1)**2 / total
        p = 1 - chi2.cdf(stat, df=1)
    sig = p < 0.05
    winner = name_a if n10 > n01 else name_b
    return {
        'A' : name_a, 'B' : name_b,
        'n10' : n10, 'n01' : n01,
        'p'   : round(p, 4),
        'significant' : sig,
        'winner'      : winner if sig else 'tie',
        'interpretation' : f"SIGNIFICANT (p={p:.4f}), {winner} wins." if sig else f"Not significant (p={p:.4f})."
    }


# ──────────────────────────────────────────────
#  ABLATION FUNCTIONS (DS fusion & averaging)
# ──────────────────────────────────────────────

def build_mass(verdict, confidence, is_url_agent=False):
    """DS mass function from verdict + confidence (same as other_methods.py)."""
    if is_url_agent and verdict == "Legitimate" and confidence == 0.50:
        return (0.0, 0.0, 1.0)          # no URLs → total ignorance
    if verdict not in ("Phishing", "Legitimate"):
        return (0.0, 0.0, 1.0)          # error → ignorance
    if verdict == "Phishing":
        return (confidence, 0.0, 1.0 - confidence)
    else:  # Legitimate
        return (0.0, confidence, 1.0 - confidence)


def combine_two(m1, m2):
    """Dempster's rule for two mass functions."""
    m1_P, m1_L, m1_F = m1
    m2_P, m2_L, m2_F = m2
    K = m1_P * m2_L + m1_L * m2_P
    if K == 1.0:
        return (1/3, 1/3, 1/3)          # total conflict → ignorance
    denom = 1.0 - K
    combined_P = (m1_P * m2_P + m1_P * m2_F + m1_F * m2_P) / denom
    combined_L = (m1_L * m2_L + m1_L * m2_F + m1_F * m2_L) / denom
    combined_F = (m1_F * m2_F) / denom
    return (combined_P, combined_L, combined_F)


def run_ablation_ds(df, threshold=0.6):
    """
    Ablation for the DS fusion ensemble.
    Computes the pignistic probability after DS combination of the remaining agents,
    then applies the given threshold to obtain a binary prediction.
    """
    y_true = df['true_label'].tolist()
    rows = []

    # Full system – use the already computed predictions (from ds_fusion CSV)
    rows.append(compute_metrics(y_true, df['predicted'].tolist(), "Full system (DS)"))

    # Ablated systems
    for ablated_name, agents_to_use in [
        ("No URL agent",     ['text', 'meta']),
        ("No Metadata agent",['text', 'url']),
        ("Text agent only",  ['text']),
    ]:
        preds = []
        for _, r in df.iterrows():
            masses = []
            if 'text' in agents_to_use:
                masses.append(build_mass(r['text_verdict'], r['text_confidence']))
            if 'url' in agents_to_use:
                masses.append(build_mass(r['url_verdict'], r['url_confidence'], is_url_agent=True))
            if 'meta' in agents_to_use:
                masses.append(build_mass(r['meta_verdict'], r['meta_confidence']))

            # Combine sequentially
            if len(masses) == 1:
                combined = masses[0]
            else:
                combined = masses[0]
                for m in masses[1:]:
                    combined = combine_two(combined, m)

            # Pignistic probability
            betP_Phish = combined[0] + 0.5 * combined[2]
            preds.append(1 if betP_Phish > threshold else 0)

        rows.append(compute_metrics(y_true, preds, ablated_name))

    valid = [r for r in rows if r is not None]
    return pd.DataFrame(valid)


def run_ablation_averaging(df, threshold=0.5):
    """
    Original averaging-based ablation (used for confidence averaging baseline).
    Retained for non-DS methods.
    """
    y_true = df['true_label'].tolist()
    def to_ps(v, c):
        if v == 'Phishing': return c
        if v == 'Legitimate': return 1.0 - c
        return 0.5

    rows = []
    rows.append(compute_metrics(y_true, df['predicted'].tolist(), "Full system"))
    no_url = [1 if (to_ps(r['text_verdict'], r['text_confidence']) +
                    to_ps(r['meta_verdict'], r['meta_confidence']))/2 > threshold else 0
              for _, r in df.iterrows()]
    rows.append(compute_metrics(y_true, no_url, "No URL agent"))
    no_meta = [1 if (to_ps(r['text_verdict'], r['text_confidence']) +
                     to_ps(r['url_verdict'], r['url_confidence']))/2 > threshold else 0
               for _, r in df.iterrows()]
    rows.append(compute_metrics(y_true, no_meta, "No Metadata agent"))
    static = [1 if (to_ps(r['text_verdict'], r['text_confidence']) +
                    to_ps(r['url_verdict'], r['url_confidence']) +
                    to_ps(r['meta_verdict'], r['meta_confidence']))/3 > threshold else 0
              for _, r in df.iterrows()]
    rows.append(compute_metrics(y_true, static, "Static equal weights"))
    text = [1 if r['text_verdict'] == 'Phishing' else
            0 if r['text_verdict'] == 'Legitimate' else -1
            for _, r in df.iterrows()]
    rows.append(compute_metrics(y_true, text, "Text agent only"))
    valid = [r for r in rows if r is not None]
    return pd.DataFrame(valid)

# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        print("Usage: python evaluate_model.py <model_name>")
        print("Example: python evaluate_model.py gemma2_9b")
        sys.exit(1)

    model_name = sys.argv[1]
    model_dir = os.path.join('results', model_name)

    if not os.path.isdir(model_dir):
        print(f"❌ Directory '{model_dir}' not found.")
        sys.exit(1)

    print("="*70)
    print(f"EVALUATING MODEL: {model_name}")
    print("="*70)

    # Discover method subfolders
    method_dirs = [
        d for d in os.listdir(model_dir)
        if os.path.isdir(os.path.join(model_dir, d))
    ]
    if not method_dirs:
        print(f"❌ No method subdirectories found in '{model_dir}'.")
        sys.exit(1)

    # Load CSV for each method
    dataframes = {}
    for method in sorted(method_dirs):
        method_path = os.path.join(model_dir, method)
        csv_files = glob.glob(os.path.join(method_path, '*.csv'))
        if not csv_files:
            print(f"⚠️  No CSV in '{method_path}' – skipping")
            continue
        csv_path = csv_files[0]
        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            print(f"❌ Error reading {csv_path}: {e}")
            continue
        if 'true_label' not in df.columns or 'predicted' not in df.columns:
            print(f"⚠️  {csv_path} missing required columns – skipping")
            continue
        dataframes[method] = df
        print(f"Loaded {method} ({len(df)} emails) from {os.path.basename(csv_path)}")

    if len(dataframes) < 2:
        print("❌ Need at least two methods to compare.")
        sys.exit(1)

    # Build the unified report
    report = []
    report.append("="*70)
    report.append(f"EVALUATION REPORT FOR MODEL: {model_name}")
    report.append("="*70)
    report.append("")

    all_metrics = []

    # 1) Per‑method detailed metrics
    report.append("-"*60)
    report.append("PER‑METHOD METRICS")
    report.append("-"*60)
    for method, df in dataframes.items():
        m = compute_metrics(df['true_label'].tolist(),
                            df['predicted'].tolist(),
                            method)
        if m is None:
            report.append(f"❌ Could not compute metrics for {method}")
            continue
        all_metrics.append(m)

        report.append(f"\nMethod: {method}")
        report.append(f"  Emails: {m['N_emails']} (valid: {m['Valid']}, errors: {m['Errors']})")
        report.append(f"  Confusion Matrix: TP={m['TP']}, FN={m['FN']}, FP={m['FP']}, TN={m['TN']}")
        report.append(f"  Accuracy:   {m['Accuracy']:.2f}%")
        report.append(f"  Precision:  {m['Precision']:.2f}%")
        report.append(f"  Recall:     {m['Recall']:.2f}%")
        report.append(f"  F1 Score:   {m['F1']:.2f}%")
        report.append(f"  FPR:        {m['FPR']:.2f}%")
        report.append(f"  FNR:        {m['FNR']:.2f}%")
        report.append(f"  TNR:        {m['TNR']:.2f}%")
        report.append(f"  MCC:        {m['MCC']:.4f}")

    report.append("")

    # 2) Ablation study
    abl_df = None
    abl_method = None

    # Prefer DS fusion for ablation if available
    if 'ds_fusion' in dataframes:
        abl_df = run_ablation_ds(dataframes['ds_fusion'])
        abl_method = 'ds_fusion'
    else:
        # Fallback: use averaging ablation on any file with specialist columns
        for method, df in dataframes.items():
            if all(col in df.columns for col in ['text_verdict','text_confidence',
                                                'url_verdict','url_confidence',
                                                'meta_verdict','meta_confidence']):
                abl_df = run_ablation_averaging(df)
                abl_method = method
                break

    if abl_df is not None:
        report.append("-"*60)
        report.append("ABLATION STUDY")
        if abl_method == 'ds_fusion':
            report.append("(using Dempster‑Shafer fusion, threshold 0.6)")
        else:
            report.append("(using confidence averaging)")
        report.append("-"*60)
        abl_cols = ['System','F1','Recall','FPR','MCC']
        report.append(abl_df[abl_cols].to_string(index=False, float_format=lambda x: f"{x:.2f}"))
    else:
        report.append("⚠️  No specialist data found – skipping ablation.")


    if abl_df is not None:
        report.append("-"*60)
        report.append("ABLATION STUDY")
        report.append("-"*60)
        abl_cols = ['System','F1','Recall','FPR','MCC']
        report.append(abl_df[abl_cols].to_string(index=False, float_format=lambda x: f"{x:.2f}"))
    else:
        report.append("⚠️  No file contained specialist verdict columns – skipping ablation.")
    report.append("")

    # 3) McNemar's tests – all pairs
    if len(dataframes) >= 2:
        report.append("-"*60)
        report.append("PAIRWISE McNEMAR'S TESTS")
        report.append("-"*60)
        mcn_results = []
        methods = list(dataframes.keys())
        for i in range(len(methods)):
            for j in range(i+1, len(methods)):
                r = mcnemar_test(dataframes[methods[i]], dataframes[methods[j]],
                                 methods[i], methods[j])
                if r:
                    mcn_results.append(r)
        if mcn_results:
            mcn_df = pd.DataFrame(mcn_results)
            report.append(mcn_df[['A','B','n10','n01','p','winner']].to_string(index=False))
        else:
            report.append("No valid pairs for McNemar.")
    report.append("")

    # 4) Final comparison table
    if all_metrics:
        comp_df = pd.DataFrame(all_metrics)
        comp_df_sorted = comp_df.sort_values('F1', ascending=False)
        report.append("-"*60)
        report.append("FINAL COMPARISON (sorted by F1)")
        report.append("-"*60)
        show_cols = ['System','F1','Recall','Precision','FPR','FNR','MCC']
        report.append(comp_df_sorted[show_cols].to_string(index=False))
        report.append("")

        best = comp_df_sorted.iloc[0]
        report.append(f"🏆 Best method: {best['System']} with F1={best['F1']:.2f}%, "
                      f"Recall={best['Recall']:.2f}%, FPR={best['FPR']:.2f}%")

    # Write everything to a single file
    report_text = "\n".join(report)
    metrics_file = os.path.join(model_dir, f'metrics_{model_name}.txt')
    with open(metrics_file, 'w') as f:
        f.write(report_text)
    print(report_text)
    print(f"\n✅ Full report saved to {metrics_file}")

if __name__ == '__main__':
    main()