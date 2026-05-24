import csv
import json
import sys
from pathlib import Path

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
JSONL_PATH  = "compressed_dataset.jsonl"
OUTPUT_PATH = "dataset.csv"
CHUNK_SIZE  = 100_000   # flush to disk every N rows (keeps RAM low)

# Columns to write, in order
COLUMNS = [
    "text",
    "label",
    "attack_type",
    "source",
    "encoding_applied",
    "injection_point",
    "injection_key",
    "payload_used",
    "source_request_id",
]

# ──────────────────────────────────────────────
# LABEL NORMALIZER
# ──────────────────────────────────────────────
def normalize_label(raw) -> int | None:
    """
    0            -> 0  (benign)
    1            -> 1  (attack)
    "malicious"  -> 1  (attack, string variant used by one source subset)
    anything else -> None  (row dropped with a warning)
    """
    if raw == 0:
        return 0
    if raw == 1 or raw == "malicious":
        return 1
    return None


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    jsonl_path = Path(JSONL_PATH)
    out_path   = Path(OUTPUT_PATH)

    if not jsonl_path.exists():
        print(f"ERROR: {JSONL_PATH} not found.", file=sys.stderr)
        sys.exit(1)

    jsonl_size_gb = jsonl_path.stat().st_size / 1024**3
    print("=" * 60)
    print("  JSONL -> CSV Converter  (full dataset, all columns)")
    print("=" * 60)
    print(f"  Input  : {JSONL_PATH}  ({jsonl_size_gb:.1f} GB)")
    print(f"  Output : {OUTPUT_PATH}")
    print(f"  Columns: {', '.join(COLUMNS)}")
    print("=" * 60)
    print()

    total     = 0
    benign    = 0
    attack    = 0
    skipped   = 0
    chunk     = []

    attack_type_counts = {}
    source_counts      = {}
    encoding_counts    = {}

    with (
        open(jsonl_path, "r", encoding="utf-8", errors="replace") as fin,
        open(out_path,   "w", encoding="utf-8", newline="")       as fout,
    ):
        writer = csv.writer(fout, quoting=csv.QUOTE_ALL)
        writer.writerow(COLUMNS)   # header

        for raw_line in fin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                d = json.loads(raw_line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            # ── Normalize label ─────────────────────────────────────────
            label = normalize_label(d.get("label"))
            text  = d.get("request", "")

            if label is None or not text:
                skipped += 1
                continue

            # ── Build row ───────────────────────────────────────────────
            attack_type      = d.get("attack_type", "") or ""
            source           = d.get("source", "")      or ""
            encoding_applied = d.get("encoding_applied", "") or ""
            injection_point  = d.get("injection_point", "") or ""
            injection_key    = d.get("injection_key", "")   or ""
            payload_used     = d.get("payload_used", "")    or ""
            source_request_id = d.get("source_request_id", "") or ""

            chunk.append([
                text,
                label,
                attack_type,
                source,
                encoding_applied,
                injection_point,
                injection_key,
                payload_used,
                source_request_id,
            ])

            # ── Counters ────────────────────────────────────────────────
            total += 1
            if label == 0:
                benign += 1
            else:
                attack += 1

            attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1
            source_counts[source]           = source_counts.get(source, 0) + 1
            encoding_counts[encoding_applied] = encoding_counts.get(encoding_applied, 0) + 1

            # ── Flush chunk ─────────────────────────────────────────────
            if len(chunk) >= CHUNK_SIZE:
                writer.writerows(chunk)
                chunk.clear()

            # ── Progress ─────────────────────────────────────────────────
            if total % 500_000 == 0:
                pct = total / 9_965_872 * 100   # approximate total
                print(f"  {total:>9,} rows  ({pct:.1f}%)  "
                      f"| benign: {benign:,}  attack: {attack:,}")

        # Flush remaining
        if chunk:
            writer.writerows(chunk)

    # ── Summary ──────────────────────────────────────────────────────────
    out_size_gb = out_path.stat().st_size / 1024**3
    print()
    print("=" * 60)
    print("  DONE")
    print("=" * 60)
    print(f"  Output file    : {OUTPUT_PATH}  ({out_size_gb:.2f} GB)")
    print(f"  Total rows     : {total:,}")
    print(f"  Benign   (0)   : {benign:,}  ({100*benign/total:.1f}%)")
    print(f"  Attack   (1)   : {attack:,}  ({100*attack/total:.1f}%)")
    print(f"  Skipped        : {skipped:,}")

    print()
    print("  Attack types (top 25):")
    for k, v in sorted(attack_type_counts.items(), key=lambda x: -x[1])[:25]:
        label_tag = "(benign)" if k in ("benign", "", "normal") else "(attack)"
        print(f"    {k or '(empty)':35s}  {v:>9,}  {label_tag}")

    print()
    print("  Sources:")
    for k, v in sorted(source_counts.items(), key=lambda x: -x[1]):
        print(f"    {k or '(empty)':30s}  {v:>9,}")

    print()
    print("  Encodings:")
    for k, v in sorted(encoding_counts.items(), key=lambda x: -x[1]):
        print(f"    {k or '(empty)':30s}  {v:>9,}")

    print()
    print("  Next step:")
    print("    python train_new.py")


if __name__ == "__main__":
    main()
