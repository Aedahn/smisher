import os
import sys
import shutil
import pandas as pd
import numpy as np

# ──────────── GET MODEL FROM COMMAND LINE ────────────
if len(sys.argv) != 2:
    print("Usage: python other_methods.py <model_name>")
    print("Example: python other_methods.py qwen3_8b")
    sys.exit(1)

model_name = sys.argv[1]
INPUT_CSV = f"results/judge_{model_name}.csv"

if not os.path.exists(INPUT_CSV):
    print(f"❌ Input file not found: {INPUT_CSV}")
    print("   Please run run_pipeline.py first to generate the judge output.")
    sys.exit(1)

OUTPUT_BASE = "results"
MODEL_DIR = os.path.join(OUTPUT_BASE, model_name)

# ──────────── CREATE MODEL FOLDER AND SUBFOLDERS ────────────
os.makedirs(MODEL_DIR, exist_ok=True)

# 1. Judge Agent – copy the input CSV
judge_dir = os.path.join(MODEL_DIR, "judge_agent")
os.makedirs(judge_dir, exist_ok=True)
judge_file = os.path.join(judge_dir, f"judge_{model_name}.csv")
shutil.copy2(INPUT_CSV, judge_file)
print(f"✅ Judge agent copied to {judge_file}")

# ──────────── LOAD DATA ────────────
df = pd.read_csv(INPUT_CSV)

# Required columns check
required = ['email_index','true_label',
            'text_verdict','text_confidence',
            'url_verdict', 'url_confidence',
            'meta_verdict','meta_confidence']
for col in required:
    if col not in df.columns:
        raise KeyError(f"Missing column: {col}")

# ──────────── HELPER FUNCTIONS ────────────

def to_phishing_score(verdict, confidence):
    """Convert a single agent output to a phishing score."""
    if verdict == "Phishing":
        return confidence
    elif verdict == "Legitimate":
        return 1.0 - confidence
    else:   # Error
        return 0.5

# ──────────── METHOD 1: CONFIDENCE AVERAGING ────────────
avg_rows = []
for _, r in df.iterrows():
    scores = [
        to_phishing_score(r['text_verdict'], r['text_confidence']),
        to_phishing_score(r['url_verdict'],  r['url_confidence']),
        to_phishing_score(r['meta_verdict'], r['meta_confidence']),
    ]
    avg_score = np.mean(scores)
    predicted = 1 if avg_score > 0.5 else 0
    avg_rows.append({
        'email_index':    r['email_index'],
        'true_label':     r['true_label'],
        'predicted':      predicted,
        'correct':        int(predicted == r['true_label']),
        'predicted_label': "Phishing" if predicted == 1 else "Legitimate",
        'phishing_score': round(avg_score, 4),
        'dominant_agent': "confidence_average",
        'final_reason':   "Confidence averaging",
        'text_verdict':   r['text_verdict'],
        'text_confidence': r['text_confidence'],
        'text_reason':    r.get('text_reason', ''),
        'url_verdict':    r['url_verdict'],
        'url_confidence': r['url_confidence'],
        'url_reason':     r.get('url_reason', ''),
        'meta_verdict':   r['meta_verdict'],
        'meta_confidence': r['meta_confidence'],
        'meta_reason':    r.get('meta_reason', ''),
        'has_error':      0,
        'model':          r.get('model', model_name),
    })
df_avg = pd.DataFrame(avg_rows)
avg_dir = os.path.join(MODEL_DIR, "confidence_averaging")
os.makedirs(avg_dir, exist_ok=True)
avg_file = os.path.join(avg_dir, f"confidence_averaging_{model_name}.csv")
df_avg.to_csv(avg_file, index=False)
print(f"✅ Confidence averaging done → {avg_file}")

# ──────────── METHOD 2: DEMPSTER‑SHAFER FUSION ────────────
def build_mass(verdict, confidence, is_url_agent=False):
    """
    Convert a specialist's verdict + confidence into a DS mass function.
    Returns tuple: (m_Phishing, m_Legitimate, m_Frame)
    """
    # Total ignorance for URL agent when no URLs were found
    if is_url_agent and verdict == "Legitimate" and confidence == 0.50:
        return (0.0, 0.0, 1.0)

    # Treat Error as total ignorance
    if verdict not in ("Phishing", "Legitimate"):
        return (0.0, 0.0, 1.0)

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
        return (1/3, 1/3, 1/3)

    denom = 1.0 - K
    combined_P = (m1_P * m2_P + m1_P * m2_F + m1_F * m2_P) / denom
    combined_L = (m1_L * m2_L + m1_L * m2_F + m1_F * m2_L) / denom
    combined_F = (m1_F * m2_F) / denom

    return (combined_P, combined_L, combined_F)

ds_rows = []
for _, r in df.iterrows():
    m_text = build_mass(r['text_verdict'], r['text_confidence'])
    m_url  = build_mass(r['url_verdict'],  r['url_confidence'],  is_url_agent=True)
    m_meta = build_mass(r['meta_verdict'], r['meta_confidence'])

    m_comb = combine_two(m_text, m_url)
    m_final = combine_two(m_comb, m_meta)

    betP_Phish = m_final[0] + 0.5 * m_final[2]

    predicted = 1 if betP_Phish > 0.6 else 0

    ds_rows.append({
        'email_index':    r['email_index'],
        'true_label':     r['true_label'],
        'predicted':      predicted,
        'correct':        int(predicted == r['true_label']),
        'predicted_label': "Phishing" if predicted == 1 else "Legitimate",
        'phishing_score': round(betP_Phish, 4),
        'dominant_agent': "ds_fusion",
        'final_reason':   "Dempster‑Shafer fusion (threshold 0.6)",
        'text_verdict':   r['text_verdict'],
        'text_confidence': r['text_confidence'],
        'text_reason':    r.get('text_reason', ''),
        'url_verdict':    r['url_verdict'],
        'url_confidence': r['url_confidence'],
        'url_reason':     r.get('url_reason', ''),
        'meta_verdict':   r['meta_verdict'],
        'meta_confidence': r['meta_confidence'],
        'meta_reason':    r.get('meta_reason', ''),
        'has_error':      0,
        'model':          r.get('model', model_name),
    })
df_ds = pd.DataFrame(ds_rows)
ds_dir = os.path.join(MODEL_DIR, "ds_fusion")
os.makedirs(ds_dir, exist_ok=True)
ds_file = os.path.join(ds_dir, f"ds_fusion_{model_name}.csv")
df_ds.to_csv(ds_file, index=False)
print(f"✅ Dempster‑Shafer fusion done → {ds_file}")

print(f"\n✅ All files saved in {MODEL_DIR}/")
print(f"  - judge_agent/judge_{model_name}.csv")
print(f"  - confidence_averaging/confidence_averaging_{model_name}.csv")
print(f"  - ds_fusion/ds_fusion_{model_name}.csv")