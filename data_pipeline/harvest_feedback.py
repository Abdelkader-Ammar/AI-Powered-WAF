"""Active-learning bridge: turn Tier 1 audit corrections into labelled training
rows. Closes the loop that was previously open (corrections were logged to the
SQLite audit DB but never fed back to training).

A 'tier1_false_negative' (Tier 0 allowed, RoBERTa said malicious) becomes a
malicious example; a 'tier1_false_positive' (Tier 0 blocked, RoBERTa said benign)
becomes a benign one. These are exactly the samples the current model got wrong.

Reads the audit DB written by trustscore/tier1_audit.go (table tier1_audit,
columns event_json TEXT, feedback_reason TEXT, ...). Reconstructs the request
text from event_json the same way the serving service serialises it.

Usage:
    TIER1_AUDIT_DB=./tier1_audit.db FEEDBACK_OUT_CSV=./feedback.csv \
        python harvest_feedback.py
"""
import csv
import json
import os
import sqlite3

AUDIT_DB = os.environ.get("TIER1_AUDIT_DB", "./tier1_audit.db")
OUT_CSV = os.environ.get("FEEDBACK_OUT_CSV", "./feedback.csv")

LABEL_FOR = {"tier1_false_negative": 1, "tier1_false_positive": 0}


def request_text(event_json: str) -> str:
    """Reconstruct 'METHOD path?query' from the stored RequestEvent JSON."""
    try:
        ev = json.loads(event_json)
    except (ValueError, TypeError):
        return ""
    method = ev.get("method", "")
    path = ev.get("path", "")
    query = ev.get("query_string", "")
    text = f"{method} {path}"
    if query:
        text += f"?{query}"
    return text.strip()


def harvest() -> int:
    if not os.path.exists(AUDIT_DB):
        print(f"[harvest] audit DB not found: {AUDIT_DB}")
        return 0

    con = sqlite3.connect(AUDIT_DB)
    rows = con.execute(
        "SELECT event_json, feedback_reason FROM tier1_audit "
        "WHERE feedback_reason IS NOT NULL AND feedback_reason != ''"
    ).fetchall()
    con.close()

    written = 0
    seen = set()
    with open(OUT_CSV, "a", newline="") as f:
        w = csv.writer(f)
        for event_json, reason in rows:
            if reason not in LABEL_FOR:
                continue
            text = request_text(event_json)
            if not text or text in seen:
                continue          # dedupe within this harvest run
            seen.add(text)
            w.writerow([text, LABEL_FOR[reason]])
            written += 1
    return written


if __name__ == "__main__":
    n = harvest()
    print(f"[harvest] wrote {n} feedback samples -> {OUT_CSV}")
