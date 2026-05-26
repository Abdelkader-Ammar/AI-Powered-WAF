import os
import torch
import csv
import sys
import time
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score, confusion_matrix

csv.field_size_limit(sys.maxsize)

MODEL_PATH = os.environ.get("WAF_MODEL_PATH", "waf_roberta_model/checkpoint-5626")
DATA_PATH = os.environ.get("WAF_DATASET", "dataset.csv")

MAX_BENIGN = 500_000
MAX_ATTACK = 500_000
BATCH_SIZE = 256
SKIP_ROWS = 1_000_000 # Skip the first 1M rows to guarantee completely unseen data

def main():
    print("Loading tokenizer and model...")
    tokenizer = AutoTokenizer.from_pretrained("roberta-base")
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    
    # FP16 inference for speed
    if torch.cuda.is_available():
        model.half()

    print(f"Streaming dataset (skipping first {SKIP_ROWS:,} rows to guarantee unseen data)...")
    
    all_labels = []
    all_probs = []
    
    benign_count = 0
    attack_count = 0
    
    batch_texts = []
    batch_labels = []
    
    start_time = time.time()
    
    def process_batch(texts, labels):
        inputs = tokenizer(texts, padding=True, truncation=True, max_length=256, return_tensors="pt").to(device)
        with torch.no_grad():
            outputs = model(**inputs)
            # Softmax to get probabilities (0.0 to 1.0)
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            # Extract probability for class 1 (Attack)
            attack_probs = probs[:, 1].cpu().numpy()
            
        all_labels.extend(labels)
        all_probs.extend(attack_probs)

    with open(DATA_PATH, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        print(f"Skipping {SKIP_ROWS:,} rows... This takes a few seconds.")
        for _ in range(SKIP_ROWS):
            try:
                next(reader)
            except StopIteration:
                break
                
        print(f"Starting 1 Million Row extraction and inference ({MAX_BENIGN:,} Benign, {MAX_ATTACK:,} Attack)...")
        for row in reader:
            if benign_count >= MAX_BENIGN and attack_count >= MAX_ATTACK:
                break
                
            try:
                label = int(row['label'])
                text = row['text']
            except (ValueError, KeyError):
                continue
                
            if label == 0 and benign_count < MAX_BENIGN:
                benign_count += 1
                batch_texts.append(text)
                batch_labels.append(label)
            elif label == 1 and attack_count < MAX_ATTACK:
                attack_count += 1
                batch_texts.append(text)
                batch_labels.append(label)
                
            if len(batch_texts) >= BATCH_SIZE:
                process_batch(batch_texts, batch_labels)
                batch_texts = []
                batch_labels = []
                
                total_processed = benign_count + attack_count
                if total_processed % 10000 == 0:
                    elapsed = time.time() - start_time
                    speed = total_processed / elapsed
                    print(f"Processed: {total_processed:,}/1,000,000 | Speed: {speed:.0f} req/s | Time elapsed: {elapsed/60:.2f}m")
                    
        # Process remainder
        if len(batch_texts) > 0:
            process_batch(batch_texts, batch_labels)
            
    print("\nInference complete! Calculating metrics across thresholds...")
    
    y_true = np.array(all_labels)
    y_probs = np.array(all_probs)
    
    auc = roc_auc_score(y_true, y_probs)
    print(f"\n========================================")
    print(f"     FINAL 1 MILLION ROW METRICS        ")
    print(f"========================================")
    print(f"Total Evaluated: {len(y_true):,}")
    print(f"AUC-ROC Score:   {auc:.5f}")
    print(f"========================================\n")
    
    thresholds = [0.50, 0.80, 0.90, 0.95, 0.99]
    
    for t in thresholds:
        y_pred = (y_probs >= t).astype(int)
        
        acc = accuracy_score(y_true, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        
        print(f"--- THRESHOLD: {t:.2f} ---")
        print(f"Accuracy:  {acc:.5f}")
        print(f"Precision: {precision:.5f}  <-- Focus here (False Positives)")
        print(f"Recall:    {recall:.5f}  <-- Caught attacks")
        print(f"F1 Score:  {f1:.5f}")
        print(f"True Negatives (TN):  {tn:,} (Allowed innocent)")
        print(f"False Positives (FP): {fp:,} (WRONGLY BLOCKED)")
        print(f"True Positives (TP):  {tp:,} (Blocked attack)")
        print(f"False Negatives (FN): {fn:,} (Slipped past)")
        print("-" * 40)

if __name__ == "__main__":
    main()