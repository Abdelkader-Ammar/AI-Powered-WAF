# Tier 1 RoBERTa inference service. Requires a trained checkpoint mounted at
# ROBERTA_MODEL_PATH (see README). Heavy (torch); optional for the demo — the
# orchestrator logs a warning and continues if this service is absent.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV ROBERTA_HOST=0.0.0.0
ENV ROBERTA_PORT=5001
EXPOSE 5001
CMD ["python", "app.py"]
