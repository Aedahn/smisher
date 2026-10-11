import os, time, subprocess
import pandas as pd
from datetime import datetime
from agents import process_email, _ollama_model_name, save_execution_time
import time as _time

CHECKPOINT_EVERY = 25
MAX_EMAILS = 3000
DELAY_BETWEEN = 0.2
DATASETS = {
    'test_final': 'data/test_dataset_final.csv',
}

def flush_ollama_cache():
    for m in ["qwen3:8b", "llama3.2:latest", "gemma2:9b"]:
        subprocess.run(["ollama", "stop", m], capture_output=True)
    print("✅ Ollama cache flushed — no ghost models in memory")

def result_filename(dataset_key):
    safe_name = _ollama_model_name.replace(':', '_').replace('.', '_')
    return f"results/judge_{safe_name}.csv"

def load_checkpoint(filepath):
    if os.path.exists(filepath):
        df = pd.read_csv(filepath)
        done = set(df['email_index'].dropna().astype(int).tolist())
        return df, done
    return pd.DataFrame(), set()

def run_dataset(dataset_key):
    input_file = DATASETS[dataset_key]
    output_file = result_filename(dataset_key)

    print(f"\n{'='*55}")
    print(f"Dataset: {dataset_key} | Model: {_ollama_model_name}")
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print(f"{'='*55}")

    if not os.path.exists(input_file):
        print(f"❌ {input_file} not found.")
        print("   Run: python3 prepare_data.py --multiphishguard")
        return

    df = pd.read_csv(input_file)
    df = df.head(MAX_EMAILS)
    saved_df, done = load_checkpoint(output_file)
    remaining = [int(i) for i in df['email_index'].tolist() if int(i) not in done]

    print(f"Total: {len(df)} | Done: {len(done)} | Remaining: {len(remaining)}")

    if not remaining:
        print("✅ Already complete for this model + dataset!")
        return

    est_hours = len(remaining) * 9 / 3600
    print(f"Estimated time: {est_hours:.1f} hours")
    print("Press Ctrl+C at any time — progress is saved every 25 emails")
    print("Starting in 3 seconds...")
    time.sleep(3)

    new_results = []

    for pos, email_idx in enumerate(remaining):
        row = df[df['email_index'] == email_idx].iloc[0]
        total = len(done) + pos + 1
        label = int(row['label'])

        print(f"\n[{total}/{len(df)}] idx={email_idx} "
              f"{'PHISH' if label==1 else 'legit'}", end="  ")

        try:
            r = process_email(
                body=str(row.get('body', '')),
                urls=str(row.get('urls', '')),
                metadata=str(row.get('metadata', '')),
                true_label=label,
                explain=True        # ← runs the judge agent
            )
            r['email_index'] = email_idx
            r['dataset'] = dataset_key
            new_results.append(r)

            mark = "✓" if r['correct'] else "✗"
            print(f"{mark} {r['predicted_label']:12} "
                  f"score={r['phishing_score']:.3f} "
                  f"dom={r['dominant_agent']}")
            # Show the judge's explanation
            print(f"  Reason: {r['final_reason'][:150]}...")

        except KeyboardInterrupt:
            print("\n\nStopped. Saving progress...")
            if new_results:
                saved_df = pd.concat([saved_df, pd.DataFrame(new_results)], ignore_index=True)
                saved_df.to_csv(output_file, index=False)
            print(f"Saved. {len(done)+len(new_results)} emails done. Run again to resume.")
            return

        except Exception as e:
            print(f"ERROR: {str(e)[:100]}")
            new_results.append({
                'email_index': email_idx,
                'true_label': label,
                'predicted': -1,
                'dataset': dataset_key,
                'model': _ollama_model_name,
                'error': str(e)[:100],
            })

        if (pos + 1) % CHECKPOINT_EVERY == 0 or pos == len(remaining) - 1:
            if new_results:
                saved_df = pd.concat([saved_df, pd.DataFrame(new_results)], ignore_index=True)
                saved_df.to_csv(output_file, index=False)
                new_results = []
                print(f"\n  💾 Checkpoint — {total} done")

        time.sleep(DELAY_BETWEEN)

    print(f"\n✅ {dataset_key} complete for {_ollama_model_name}")

def main():
    start_time = _time.time()
    flush_ollama_cache()
    print(f"\n{'='*55}")
    print(f"PIPELINE START — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"Model: {_ollama_model_name}")
    print(f"{'='*55}")
    os.makedirs('results', exist_ok=True)
    for dataset_key in DATASETS.keys():
        run_dataset(dataset_key)
    print(f"\n{'='*55}")
    print("ALL DATASETS COMPLETE FOR THIS MODEL")
    print("To run the other model:")
    print("  1. Open agents.py")
    print("  2. Change MODEL_TO_LOAD = 'A' to 'B' (or vice versa)")
    print("  3. Run: caffeinate -i python3 run_pipeline.py")
    print(f"{'='*55}")
    save_execution_time(_ollama_model_name, start_time)

if __name__ == "__main__":
    main()