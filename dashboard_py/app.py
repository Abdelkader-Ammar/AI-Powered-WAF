"""AI-WAF Admin Dashboard — Python (FastAPI + Jinja2 + HTMX + server-rendered SVG).

A modern, dark cybersecurity-monitoring dashboard. It is a thin presentation
layer over the Go admin API (tier-0/admin.go, :8081) and the live Redis feeds the
orchestrator publishes (waf:events, waf:rasp:events, id->score). No JavaScript or
TypeScript is authored: HTMX polls partials, and all charts are SVG generated in
Python (charts.py).

Run:  WAF_ADMIN_API=http://localhost:8081 PORT=8082 python app.py
"""
import json
import os
import re
from collections import Counter

import httpx
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import charts

ADMIN_API = os.environ.get("WAF_ADMIN_API", "http://localhost:8081")
HERE = os.path.dirname(os.path.abspath(__file__))

app = FastAPI(title="AI-WAF Control Center")
app.mount("/static", StaticFiles(directory=os.path.join(HERE, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(HERE, "templates"))


# ── Go admin API plumbing ────────────────────────────────────────────────────
def _client(request: Request) -> httpx.Client:
    cookie = request.cookies.get("admin_session", "")
    cookies = {"admin_session": cookie} if cookie else {}
    return httpx.Client(base_url=ADMIN_API, cookies=cookies, timeout=5.0)


def _coerce(value: str):
    low = value.strip().lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        if "." in value or "e" in low:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _set_path(cfg: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    node = cfg
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = value


# ── Redis feeds ──────────────────────────────────────────────────────────────
def _redis():
    try:
        import redis
        return redis.Redis(host=os.environ.get("REDIS_HOST", "localhost"),
                           port=int(os.environ.get("REDIS_PORT", "6379")),
                           decode_responses=True)
    except Exception:
        return None


def _redis_list(key, n):
    r = _redis()
    if r is None:
        return []
    try:
        out = []
        for raw in r.lrange(key, 0, n - 1):
            try:
                out.append(json.loads(raw))
            except (ValueError, TypeError):
                pass
        return out
    except Exception:
        return []


def _isnum(s):
    try:
        float(s)
        return True
    except (ValueError, TypeError):
        return False


def _score_rows():
    rows = []
    r = _redis()
    if r is not None:
        try:
            for key in list(r.scan_iter(count=200))[:200]:
                if key.startswith("waf:") or key.startswith("tier1:") or key.startswith("ratelimit:"):
                    continue
                if r.type(key) != "string":
                    continue
                val = r.get(key)
                if val is not None and _isnum(val):
                    rows.append((key, float(val)))
        except Exception:
            pass
    rows.sort(key=lambda kv: kv[1])
    return rows


# ── overview aggregation ─────────────────────────────────────────────────────
def _bucket(decision: str) -> str:
    d = decision or ""
    if d == "ban":
        return "ban"
    if d == "challenge":
        return "challenge"
    if "block" in d or "rate_limit" in d:
        return "block"
    return "allow"


def _series(events, pred, n=24):
    ev = list(reversed(events))   # oldest -> newest
    out = [0] * n
    if not ev:
        return out
    for i, e in enumerate(ev):
        out[min(n - 1, i * n // len(ev))] += 1 if pred(e) else 0
    return out


CAT_COLOR = {"rce": charts.RED, "lfi": charts.ORANGE, "webshell": charts.RED,
             "ssrf": charts.MAGENTA, "sqli": charts.PURPLE, "db_unauth": charts.PURPLE,
             "coraza": charts.TEAL, "lgbm/xss": charts.ORANGE}


def _overview():
    events = _redis_list("waf:events", 200)
    rasp = _redis_list("waf:rasp:events", 50)
    scores = _score_rows()

    total = len(events)
    by = Counter(_bucket(e.get("decision", "")) for e in events)
    blocked = by["block"] + by["ban"]
    threat = round((blocked + by["challenge"]) / total * 100) if total else 0

    cats = Counter()
    for r in rasp:
        cats[r.get("category", "?")] += 1
    for e in events:
        d = e.get("decision", "")
        if d == "block_coraza":
            cats["coraza"] += 1
        elif d == "block_lgbm":
            cats["lgbm/xss"] += 1
    cat_bars = [(k, v, CAT_COLOR.get(k, charts.PURPLE)) for k, v in cats.most_common(6)]

    # Per-IP trust-score trajectories from the score logged on each request.
    traj = {}
    for e in reversed(events):                       # oldest -> newest
        ip, ts = e.get("ip"), e.get("trust_score")
        if ip and ts is not None:
            traj.setdefault(ip, []).append(float(ts))
    ranked = sorted(traj.items(), key=lambda kv: min(kv[1]))[:6]  # lowest-driven first
    score_lines = [(ip, vals, charts.PALETTE[i % len(charts.PALETTE)])
                   for i, (ip, vals) in enumerate(ranked)]
    score_legend = [(ip, vals[-1], charts.PALETTE[i % len(charts.PALETTE)])
                    for i, (ip, vals) in enumerate(ranked)]

    # Stable per-row ids so the :target CSS expansion survives a feed refresh.
    def _rowid(prefix, d):
        raw = d.get("request_id") or (f"{d.get('ip','')}{d.get('timestamp','')}"
                                      f"{d.get('path','')}{d.get('evidence','')}")
        return prefix + re.sub(r"[^a-zA-Z0-9]", "", raw)[:44]
    ev = events[:120]
    for e in ev:
        e["_rowid"] = _rowid("e", e)
    rv = rasp[:60]
    for r in rv:
        r["_rowid"] = _rowid("r", r)

    # Join the RASP catches into the decision feed by request id, so a confirmed
    # exploitation is visible IN Recent Decisions (the orchestrator logged that
    # request as "allow" because the RASP blocked it at the backend, not at a tier).
    rasp_by_rid = {r.get("request_id"): r for r in rv if r.get("request_id")}
    for e in ev:
        rid = e.get("request_id")
        e["_rasp"] = rasp_by_rid.get(rid) if rid else None

    return {
        "kpi": {"total": total, "blocked": blocked, "banned": by["ban"],
                "challenged": by["challenge"], "rasp": len(rasp),
                "entities": len(scores)},
        "gauge": charts.gauge(threat, f"{threat}%", "threat level"),
        "req_spark": charts.sparkline(_series(events, lambda e: True), charts.PURPLE),
        "block_spark": charts.sparkbars(_series(events, lambda e: _bucket(e.get("decision", "")) in ("block", "ban"))),
        "ban_spark": charts.sparkbars(_series(events, lambda e: e.get("decision") == "ban"), charts.MAGENTA),
        "rasp_spark": charts.sparkbars(_series(rasp, lambda e: True), charts.ORANGE),
        "donut": charts.donut([("allow", by["allow"], charts.TEAL),
                               ("block", by["block"], charts.PURPLE),
                               ("challenge", by["challenge"], charts.ORANGE),
                               ("ban", by["ban"], charts.RED)]),
        "cat_bars": cat_bars,
        "cat_max": max([v for _, v, _ in cat_bars] + [1]),
        "score_chart": charts.multiline(score_lines),
        "score_legend": score_legend,
        "events": ev,
        "rasp_events": rv,
        "scores": scores[:12],
        "segbar": charts.segbar,
    }


# ── pages ────────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def overview_page(request: Request):
    with _client(request) as api:
        try:
            status = api.get("/api/admin/status").json()
        except Exception:
            return templates.TemplateResponse(request, "error.html", {"api": ADMIN_API})
        if status.get("setup_required"):
            return RedirectResponse("/setup", status_code=303)
        if api.get("/api/admin/config").status_code == 401:
            return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "overview.html",
                                      {"nav": "overview", **_overview()})


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    with _client(request) as api:
        cfg = api.get("/api/admin/config")
        if cfg.status_code == 401:
            return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "settings.html",
                                      {"nav": "settings", "config": cfg.json()})


@app.get("/api/metrics", response_class=HTMLResponse)
def metrics_partial(request: Request):
    return templates.TemplateResponse(request, "_metrics.html", _overview())


@app.get("/api/feeds", response_class=HTMLResponse)
def feeds_partial(request: Request):
    return templates.TemplateResponse(request, "_feeds.html", _overview())


# ── auth ─────────────────────────────────────────────────────────────────────
def _setup_required(request: Request) -> bool:
    with _client(request) as api:
        try:
            return bool(api.get("/api/admin/status").json().get("setup_required"))
        except Exception:
            return False


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    # No admin account yet -> send to sign-up instead of a dead-end login.
    if _setup_required(request):
        return RedirectResponse("/setup", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"mode": "login"})


@app.get("/setup", response_class=HTMLResponse)
def setup_form(request: Request):
    # Already set up -> sign-up is closed, send to login.
    if not _setup_required(request):
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "login.html", {"mode": "setup"})


@app.post("/login")
def do_login(request: Request, username: str = Form(...), password: str = Form(...)):
    return _auth(request, "/api/admin/login", username, password)


@app.post("/setup")
def do_setup(request: Request, username: str = Form(...), password: str = Form(...)):
    return _auth(request, "/api/admin/setup", username, password)


def _auth(request: Request, path: str, username: str, password: str) -> Response:
    with _client(request) as api:
        r = api.post(path, json={"Username": username, "Password": password})
    if r.status_code != 200:
        return templates.TemplateResponse(
            request, "login.html", {"mode": "login", "error": "Authentication failed"},
            status_code=401)
    resp = RedirectResponse("/", status_code=303)
    if "admin_session" in r.cookies:
        resp.set_cookie("admin_session", r.cookies["admin_session"],
                        httponly=True, samesite="strict")
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("admin_session")
    return resp


# ── config save / reset ──────────────────────────────────────────────────────
@app.post("/api/config", response_class=HTMLResponse)
async def save_config(request: Request):
    form = await request.form()
    with _client(request) as api:
        current = api.get("/api/admin/config")
        if current.status_code == 401:
            return HTMLResponse('<span class="toast err">Session expired</span>')
        cfg = current.json()
        for key, raw in form.items():
            _set_path(cfg, key, _coerce(raw))
        resp = api.post("/api/admin/config", json=cfg)
    return templates.TemplateResponse(request, "_toast.html",
                                      {"ok": resp.status_code == 200})


@app.post("/api/config/reset")
def reset_config(request: Request):
    with _client(request) as api:
        resp = api.post("/api/admin/config/reset")
    # HX-Refresh tells HTMX to do a full page reload so every control shows the
    # restored default value -- no JavaScript authored.
    if resp.status_code == 200:
        return Response(status_code=200, headers={"HX-Refresh": "true"})
    return HTMLResponse('<div class="toast err">Reset failed</div>')


@app.post("/api/data/reset")
def reset_data(request: Request):
    """Clear all runtime data (decisions, RASP feed, scores, profiles) but keep
    the admin account and config."""
    with _client(request) as api:
        resp = api.post("/api/admin/reset-data")
    if resp.status_code == 200:
        return Response(status_code=200, headers={"HX-Refresh": "true"})
    return HTMLResponse('<div class="toast err">Clear failed</div>')


# ── live partials ────────────────────────────────────────────────────────────
@app.get("/api/events", response_class=HTMLResponse)
def live_events(request: Request):
    return templates.TemplateResponse(request, "_events.html",
                                      {"events": _redis_list("waf:events", 40)})


@app.get("/api/rasp", response_class=HTMLResponse)
def live_rasp(request: Request):
    return templates.TemplateResponse(request, "_rasp.html",
                                      {"events": _redis_list("waf:rasp:events", 30)})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8082")))
