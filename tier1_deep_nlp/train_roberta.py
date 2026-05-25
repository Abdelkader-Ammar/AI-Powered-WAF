import os
import torch
import numpy as np
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import pandas as pd
import csv
import sys

# Crucial for reading large payloads
csv.field_size_limit(sys.maxsize)

# === CONFIGURATION ===
MODEL_NAME = "roberta-base"
DATA_PATH = os.environ.get("WAF_DATASET", "dataset.csv")
OUTPUT_DIR = os.environ.get("WAF_MODEL_DIR", "waf_roberta_model")
CACHE_DIR = os.environ.get("WAF_CACHE_DIR", "roberta_cache")

# Perfectly balanced dataset
MAX_BENIGN = 50_000
MAX_ATTACKS = 50_000
MAX_LENGTH = 256
BATCH_SIZE = 16
GRAD_ACCUM = 2
EPOCHS = 2
LEARNING_RATE = 2e-5

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary', zero_division=0)
    acc = accuracy_score(labels, preds)
    return {
        'accuracy': acc,
        'f1': f1,
        'precision': precision,
        'recall': recall
    }

def main():
    print(f"Loading {MODEL_NAME} tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    
    print("Reading and perfectly balancing the dataset via streaming (50k Benign, 50k Attack)...")
    import random
    
    benign_rows = []
    attack_rows = []
    
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Safely handle missing/malformed rows
            if "label" not in row or row["label"] is None:
                continue
            
            try:
                label_val = int(row["label"])
            except ValueError:
                continue
            
            if label_val == 0 and len(benign_rows) < MAX_BENIGN:
                benign_rows.append(row)
            elif label_val == 1 and len(attack_rows) < MAX_ATTACKS:
                attack_rows.append(row)
                
            if len(benign_rows) >= MAX_BENIGN and len(attack_rows) >= MAX_ATTACKS:
                break

    print(f"Extraction complete! Found {len(benign_rows)} Benign and {len(attack_rows)} Attack rows.")
    
    # Combine and shuffle
    all_rows = benign_rows + attack_rows
    random.shuffle(all_rows)
    
    df_balanced = pd.DataFrame(all_rows)
    # Ensure label is int
    df_balanced["label"] = df_balanced["label"].astype(int)
    
    print(f"Dataset ready: {len(df_balanced)} total rows.")
    print("Class distribution:")
    print(df_balanced['label'].value_counts())

    dataset = Dataset.from_pandas(df_balanced)
    
    print("Tokenizing dataset (Dynamic Padding)...")
    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            max_length=MAX_LENGTH
        )

    # Remove all columns except 'label' so Trainer doesn't get confused
    cols_to_remove = [col for col in dataset.column_names if col != "label"]
    
    tokenized_dataset = dataset.map(
        tokenize_fn,
        batched=True,
        num_proc=4,
        remove_columns=cols_to_remove,
        cache_file_name=os.path.join(CACHE_DIR, "tokenized.arrow")
    )

    # 90% train, 10% validation
    split_dataset = tokenized_dataset.train_test_split(test_size=0.1, seed=42)
    
    print("Loading model...")
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)
    
    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        eval_strategy="epoch",
        save_strategy="epoch",
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUM,
        num_train_epochs=EPOCHS,
        weight_decay=0.01,
        fp16=True, # Safely supported by RoBERTa
        dataloader_num_workers=0, # Prevent memory leak crash
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        seed=42
    )

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=split_dataset["train"],
        eval_dataset=split_dataset["test"],
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
        data_collator=data_collator
    )

    print("Starting training...")
    trainer.train()
    
    print("Training complete! Evaluating best model...")
    metrics = trainer.evaluate()
    print(metrics)

if __name__ == "__main__":
    os.makedirs(CACHE_DIR, exist_ok=True)
    main()
