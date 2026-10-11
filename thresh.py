import pandas as pd
import numpy as np

df = pd.read_csv('results/judge_gemma2_9b.csv')

def to_score(verdict, conf):
    if verdict == "Phishing":
        return conf
    elif verdict == "Legitimate":
        return 1 - conf
    else:
        return 0.5

def ensemble_gated(t_verdict, t_conf, u_verdict, u_conf, m_verdict, m_conf, dominant_weight):
    # simplified: we use the original gating logic (best_conf >= 0.85 -> 50% weight, etc.)
    # We'll approximate by using fixed weights for simulation? Better to replicate the exact ensemble.
    # But for a quick test, use fixed weights (text 0.5, others 0.25) – this is the high-confidence case.
    t_score = to_score(t_verdict, t_conf)
    u_score = to_score(u_verdict, u_conf)
    m_score = to_score(m_verdict, m_conf)
    return t_score*0.5 + u_score*0.25 + m_score*0.25

# Boost URL and metadata confidences when they say "Legitimate" and have "no suspicious patterns"
# Identify those rows (based on reason strings or just all where url_verdict="Legitimate")
df['url_conf_boosted'] = df['url_confidence'].copy()
df['meta_conf_boosted'] = df['meta_confidence'].copy()
mask_url = (df['url_verdict'] == "Legitimate") & (df['url_reason'].str.contains("No suspicious", na=False))
mask_meta = (df['meta_verdict'] == "Legitimate") & (df['meta_reason'].str.contains("No suspicious", na=False))
df.loc[mask_url, 'url_conf_boosted'] = np.minimum(df['url_confidence'] * 1.1, 0.95)
df.loc[mask_meta, 'meta_conf_boosted'] = np.minimum(df['meta_confidence'] * 1.1, 0.95)

# Recompute final scores using the boosted confidences
new_scores = []
for _, row in df.iterrows():
    t_score = to_score(row['text_verdict'], row['text_confidence'])
    u_score = to_score(row['url_verdict'], row['url_conf_boosted'])
    m_score = to_score(row['meta_verdict'], row['meta_conf_boosted'])
    # Use same gating logic as original (best confidence determines weights)
    confs = [row['text_confidence'], row['url_conf_boosted'], row['meta_conf_boosted']]
    best_idx = np.argmax(confs)
    best_conf = confs[best_idx]
    if best_conf >= 0.85:
        weights = [0.5, 0.25, 0.25]
    elif best_conf >= 0.70:
        weights = [0.4, 0.3, 0.3]
    else:
        weights = [1/3, 1/3, 1/3]
    final_score = (t_score*weights[0] + u_score*weights[1] + m_score*weights[2])
    new_scores.append(final_score)

scores = np.array(new_scores)
true = df['true_label'].values

for th in [0.5, 0.55, 0.6, 0.65]:
    pred = (scores > th).astype(int)
    tp = ((pred == 1) & (true == 1)).sum()
    fp = ((pred == 1) & (true == 0)).sum()
    fn = ((pred == 0) & (true == 1)).sum()
    tn = ((pred == 0) & (true == 0)).sum()
    recall = tp/(tp+fn) if (tp+fn)>0 else 0
    fpr = fp/(fp+tn) if (fp+tn)>0 else 0
    f1 = 2*tp/(2*tp+fp+fn) if (2*tp+fp+fn)>0 else 0
    print(f"Boosted conf, th={th:.2f}: F1={f1:.3f}, recall={recall:.3f}, FPR={fpr:.3f}")