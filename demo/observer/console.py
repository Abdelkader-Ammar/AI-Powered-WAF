"""Read-only live correlation console. Joins the WAF's OWN outputs into one view
keyed on the request. It writes nothing back to the WAF.

It reads access-log + RASP lines from stdin, so the simplest invocation is:

    docker compose logs -f orchestrator | python observer/console.py

The orchestrator emits `[ACCESS_LOG] {json}` per request (with method, path, ip,
trust_score, lgbm_prob, coraza_verdict, decision, and request_id) and the trust
engine emits `[RASP] <id> severity=... category=...` per ground-truth effect.
This joins them by request_id (falling back to ip+path) and renders the journey:
attack sent -> decision -> RASP -> trust score.
"""
import json
import re
import sys

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    _RICH = True
except Exception:
    _RICH = False

RASP_RE = re.compile(
    r"\[RASP\]\s+(?P<id>\S+)\s+severity=(?P<sev>\S+)\s+category=(?P<cat>\S+)")


def _key(ev):
    return ev.get("request_id") or f"{ev.get('ip','')}{ev.get('path','')}"


def consume(line, rows):
    if "[ACCESS_LOG]" in line:
        try:
            ev = json.loads(line.split("[ACCESS_LOG]", 1)[1].strip())
        except Exception:
            return
        rows[_key(ev)] = {
            "path": ev.get("path", "-"),
            "ip": ev.get("ip", "-"),
            "score": ev.get("trust_score", "-"),
            "lgbm": ev.get("lgbm_prob", "-"),
            "coraza": ev.get("coraza_verdict", "-") or "-",
            "decision": ev.get("decision", "-"),
            "rasp": rows.get(_key(ev), {}).get("rasp", "-"),
        }
    else:
        m = RASP_RE.search(line)
        if m:
            rid = m.group("id")
            row = rows.setdefault(rid, {"path": "?", "decision": "?"})
            row["rasp"] = f"{m.group('cat')}/{m.group('sev')}"


def render(rows):
    if not _RICH:
        return
    t = Table(title="WAF / RASP — request journey (read-only)")
    for c in ("path", "ip", "lgbm", "coraza", "rasp", "decision", "score"):
        t.add_column(c)
    for row in list(rows.values())[-25:]:
        rasp = row.get("rasp", "-")
        rasp_cell = f"[bold red]{rasp}[/]" if rasp and rasp != "-" else "-"
        t.add_row(str(row.get("path", "-")), str(row.get("ip", "-")),
                  str(row.get("lgbm", "-")), str(row.get("coraza", "-")),
                  rasp_cell, str(row.get("decision", "-")),
                  str(row.get("score", "-")))
    return t


def main():
    rows = {}
    if _RICH:
        console = Console()
        with Live(render(rows), console=console, refresh_per_second=4) as live:
            for line in sys.stdin:
                consume(line, rows)
                live.update(render(rows))
    else:
        for line in sys.stdin:
            consume(line, rows)
            last = list(rows.values())[-1:] or [{}]
            r = last[0]
            print(f"{r.get('path','-'):<28} dec={r.get('decision','-'):<14} "
                  f"rasp={r.get('rasp','-'):<14} score={r.get('score','-')}")


if __name__ == "__main__":
    main()
