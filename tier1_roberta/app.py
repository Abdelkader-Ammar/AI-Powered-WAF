import os
import sys
import time
from typing import Dict, Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ─── Configuration ──────────────────────────────────────────────────────────
# Model path comes from the environment; default to a repo-relative ./model so
# the service is portable (no machine-specific path baked in).
MODEL_PATH = os.environ.get("ROBERTA_MODEL_PATH", "")
if not MODEL_PATH:
    MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model")
    print(f"[WARN] ROBERTA_MODEL_PATH not set; defaulting to {MODEL_PATH}")
if not os.path.isdir(MODEL_PATH):
    print(f"[WARN] model dir {MODEL_PATH!r} does not exist; "
          f"set ROBERTA_MODEL_PATH to a trained checkpoint.")
API_KEY = os.environ.get("ROBERTA_API_KEY", "")
MAX_LENGTH = 256
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


# ─── Pydantic Models ────────────────────────────────────────────────────────
class PredictRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str]
    body_snippet: str = ""
    tier0_decision: str
    lgbm_prob: float


class PredictResponse(BaseModel):
    label: str
    confidence: float
    benign_prob: float
    malicious_prob: float
    inference_time_ms: float


# ─── Model Loading ───────────────────────────────────────────────────────────
print(f"Loading RoBERTa from {MODEL_PATH}...")
print(f"Device: {DEVICE}")

try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    model.to(DEVICE)
    model.eval()

    if DEVICE.type == "cuda":
        model.half()
        print("Using FP16 half precision")

    print("Model loaded successfully.")
except Exception as e:
    print(f"FATAL: Failed to load model: {e}")
    sys.exit(1)


# ─── FastAPI App ────────────────────────────────────────────────────────────
app = FastAPI(title="WAF Tier 1 RoBERTa Service")


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> None:
    if API_KEY and API_KEY != "":
        if not x_api_key:
            raise HTTPException(status_code=401, detail="Missing X-API-Key header")
        if x_api_key != API_KEY:
            raise HTTPException(status_code=403, detail="Invalid API key")


def serialize_request(req: PredictRequest) -> str:
    text = f"{req.method} {req.url}"

    important_headers = [
        "user-agent", "content-type", "authorization",
        "x-forwarded-for", "accept", "referer"
    ]
    for key in important_headers:
        if key in req.headers:
            text += f" {key}: {req.headers[key]}"

    other_headers = [k for k in req.headers.keys() if k not in important_headers]
    for key in other_headers[:5]:
        text += f" {key}: {req.headers[key]}"

    if req.body_snippet:
        snippet = req.body_snippet[:1024].replace("\n", " ")
        text += f" body: {snippet}"

    return text


@app.post("/predict", response_model=PredictResponse, dependencies=[Depends(verify_api_key)])
async def predict(req: PredictRequest):
    start_time = time.time()

    text = serialize_request(req)

    inputs = tokenizer(
        text,
        truncation=True,
        padding=True,
        max_length=MAX_LENGTH,
        return_tensors="pt"
    ).to(DEVICE)

    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = torch.softmax(logits, dim=1)

        benign_prob = probs[0][0].item()
        malicious_prob = probs[0][1].item()

        label = "malicious" if malicious_prob > benign_prob else "benign"
        confidence = max(benign_prob, malicious_prob)

    inference_time = (time.time() - start_time) * 1000

    return PredictResponse(
        label=label,
        confidence=confidence,
        benign_prob=benign_prob,
        malicious_prob=malicious_prob,
        inference_time_ms=inference_time
    )


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "model_loaded": True,
        "device": str(DEVICE),
        "timestamp": time.time()
    }


@app.get("/stats")
async def stats():
    return {
        "device": str(DEVICE),
        "model_path": MODEL_PATH,
        "max_length": MAX_LENGTH,
        "auth_enabled": API_KEY != ""
    }


if __name__ == "__main__":
    import uvicorn
    host = os.environ.get("ROBERTA_HOST", "127.0.0.1")
    port = int(os.environ.get("ROBERTA_PORT", "5001"))
    uvicorn.run(app, host=host, port=port, workers=1)
