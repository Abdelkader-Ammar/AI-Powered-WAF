# Tier-1 Deep NLP Model (RoBERTa)

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C.svg)
![Transformers](https://img.shields.io/badge/Transformers-FFD21E.svg)
![Status](https://img.shields.io/badge/Status-Active_Development-brightgreen.svg)

---

## Project Overview

Tier‑1 is the **asynchronous deep‑semantic analyser** of the AI‑Powered WAF.  It processes the “gray‑area” traffic that Tier‑0 cannot decide with sub‑millisecond latency. A fine‑tuned **RoBERTa‑base** model (≈ 125 M parameters) is used to recognise sophisticated attacks that evade classical signatures.

Key goals:

| Goal | Description |
|------|-------------|
| **High Accuracy** | > 99 % AUC‑ROC on a 1 M‑row unseen test set. |
| **Low Latency (async)** | Runs on GPU (or CPU‑FP16) and streams predictions back to the Orchestrator. |
| **Extensibility** | Model checkpoint is stored on Hugging Face for reproducibility and future fine‑tuning. |

---

## Architecture & Data Flow

```
[Client Request] → Tier‑0 Inline Filter → (uncertain?) → Tier‑1 Deep NLP (async) → Trust Engine → Decision
```

1. **Request reaches Tier‑0** – quick LightGBM scoring.  
2. **Uncertain prediction** → request is **copied** to Tier‑1.  
3. **Tier‑1** loads the RoBERTa checkpoint, computes a probability of “malicious”.  
4. If the probability exceeds the configured threshold, Tier‑1 **notifies the Trust Engine** to lower the attacker’s score and logs the payload for later fine‑tuning.

---

## Model Training

* **Base model** – `roberta-base` from Hugging Face Transformers.  
* **Dataset** – 100 k balanced samples (50 k benign, 50 k attacks) drawn from the university‑wide WAF log CSV  
* **Tokenizer** – `AutoTokenizer.from_pretrained("roberta-base")`.  
* **Training arguments** – 2 epochs, batch size 16 (gradient accumulation 2), learning rate 2e‑5, max length 256, FP16 mixed precision.  
* **Training script** – `train_roberta.py`.  
* **Checkpoint** – saved under `waf_roberta_model/` and later pushed to Hugging Face.

```bash
python train_roberta.py  # runs the Trainer with the above config
```

---

## Evaluation & Metrics

The model was evaluated on **1 000 000 completely unseen rows** (skipping the first million entries of the CSV). Results are reported for several decision thresholds.

### Overall AUC‑ROC

```
AUC‑ROC Score: 0.99942
```

### Detailed Threshold Table  

| Threshold | Accuracy | Precision | Recall | F1‑Score |  TN |  FP |  TP |  FN |
|----------|----------|-----------|--------|----------|----|-----|-----|-----|
| **0.50** | 0.99265 | 0.99348 | 0.99181 | 0.99264 | 496 744 | 3 256 | 495 903 | 4 097 |
| **0.80** | 0.99277 | 0.99485 | 0.99067 | 0.99276 | 497 435 | 2 565 | 495 337 | 4 663 |
| **0.90** | 0.99254 | 0.99540 | 0.98966 | 0.99252 | 497 711 | 2 289 | 494 831 | 5 169 |
| **0.95** | 0.99232 | 0.99608 | 0.98854 | 0.99229 | 498 053 | 1 947 | 494 270 | 5 730 |
| **0.99** | 0.99140 | 0.99826 | 0.98452 | 0.99134 | 499 142 |   858 | 492 261 | 7 739 |

* **Precision** is highlighted because false‑positives directly impact legitimate traffic.  
* **Recall** shows the proportion of attacks successfully caught.

The evaluation script (`evaluate_1M.py`) prints the same table and can be re‑run on any new checkpoint.

---



## Testing

The folder already includes two evaluation scripts (`evaluate_model.py` and `evaluate_1M.py`). Run the full test suite:

```bash
cd tier1_deep_nlp
python -m pytest   # (if additional unit tests are added)
python evaluate_1M.py   # reproduces the metrics shown above
```

All tests should pass on a machine with **Python 3.10+**, **PyTorch 2.0+**, and a GPU (optional but recommended).

