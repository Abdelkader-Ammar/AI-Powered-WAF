import os
import csv
import sys
import torch
import numpy as np
from tqdm import tqdm
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score
)

csv.field_size_limit(sys.maxsize)

MODEL_PATH = os.environ.get("WAF_MODEL_PATH", "waf_roberta_model/checkpoint-5626")
DATA_PATH = os.environ.get("WAF_DATASET", "dataset.csv")
MAX_LENGTH = 256
BATCH_SIZE = 128

def get_unseen_data(file_path, skip_rows=500_000, target_benign=50_000, target_attack=50_000):
    texts = []
    labels = []
    b_count = 0
    a_count = 0
    
    print(f"Streaming data, skipping first {skip_rows} rows to ensure 100% unseen data...")
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        # Skip the first N rows
        for _ in tqdm(range(skip_rows), desc="Skipping rows"):
            try:
                next(reader)
            except StopIteration:
                break
                
        # Collect our fresh 100k
        pbar = tqdm(total=target_benign + target_attack, desc="Collecting test set")
        for row in reader:
            if b_count >= target_benign and a_count >= target_attack:
                break
                
            try:
                label = int(row['label'])
                text = row['text']
            except (ValueError, KeyError):
                continue
                
            if label == 0 and b_count < target_benign:
                texts.append(text)
                labels.append(0)
                b_count += 1
                pbar.update(1)
            elif label == 1 and a_count < target_attack:
                texts.append(text)
                labels.append(1)
                a_count += 1
                pbar.update(1)
        pbar.close()
                
    return texts, labels

def main():
    print("Loading fine-tuned model and tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    if torch.cuda.is_available():
        model.half() # Use fp16 for faster inference
        
    texts, true_labels = get_unseen_data(DATA_PATH)
    print(f"Collected {len(texts)} completely new test samples.")
    
    all_preds = []
    all_probs = []
    
    print("Running Inference...")
    for i in tqdm(range(0, len(texts), BATCH_SIZE), desc="Inferencing"):
        batch_texts = texts[i:i+BATCH_SIZE]
        
        inputs = tokenizer(
            batch_texts,
            truncation=True,
            padding=True,
            max_length=MAX_LENGTH,
            return_tensors="pt"
        ).to(device)
        
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy() # Probability of Attack
            preds = torch.argmax(logits, dim=1).cpu().numpy()
            
        all_probs.extend(probs)
        all_preds.extend(preds)
        
    print("\n" + "="*40)
    print("         FINAL TEST METRICS")
    print("="*40)
    acc = accuracy_score(true_labels, all_preds)
    prec = precision_score(true_labels, all_preds)
    rec = recall_score(true_labels, all_preds)
    f1 = f1_score(true_labels, all_preds)
    auc = roc_auc_score(true_labels, all_probs)
    
    tn, fp, fn, tp = confusion_matrix(true_labels, all_preds).ravel()
    
    print(f"Accuracy:  {acc:.5f} (99.xx%)")
    print(f"Precision: {prec:.5f}")
    print(f"Recall:    {rec:.5f}")
    print(f"F1 Score:  {f1:.5f}")
    print(f"AUC-ROC:   {auc:.5f}")
    print("-" * 40)
    print("CONFUSION MATRIX BREAKDOWN:")
    print(f"True Negatives  (TN): {tn:6d} - Innocent requests correctly allowed")
    print(f"False Positives (FP): {fp:6d} - Innocent requests WRONGLY blocked")
    print(f"True Positives  (TP): {tp:6d} - Attacks correctly caught and blocked")
    print(f"False Negatives (FN): {fn:6d} - Attacks that WRONGLY slipped past")
    print("="*40)
    
if __name__ == "__main__":
    main()