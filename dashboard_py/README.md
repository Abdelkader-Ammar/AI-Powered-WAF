# AI-WAF Admin Dashboard — Python

Server-rendered admin dashboard built with **FastAPI + Jinja2 + HTMX**. It
replaces the former React/TypeScript SPA (`dashboard/`). No JavaScript or
TypeScript is authored — HTMX is a single `<script>` tag.

It is a thin presentation layer over the existing **Go admin API**
(`tier-0/admin.go`, port `8081`): it renders the config forms, forwards
credentials and config changes to the Go API, and carries the `admin_session`
cookie end-to-end. The Go orchestrator remains the single source of truth for
configuration (`SaveWafConfig` still applies everything live).

## Run

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
WAF_ADMIN_API=http://localhost:8081 PORT=8082 python app.py
# or: uvicorn app:app --port 8082
```

Open <http://localhost:8082>.

## Environment

| Variable        | Default                  | Purpose                                  |
|-----------------|--------------------------|------------------------------------------|
| `WAF_ADMIN_API` | `http://localhost:8081`  | Go orchestrator admin API base URL.      |
| `PORT`          | `8082`                   | Dashboard listen port.                   |
| `REDIS_HOST`    | `localhost`              | Live-scores panel (optional).            |
| `REDIS_PORT`    | `6379`                   | Live-scores panel (optional).            |

## Features

- **Overview** (`/`) — a dark, cybersecurity-monitoring dashboard:
  - **KPI cards** (Total Requests, Blocked, Banned, RASP Detections, Entities)
    each with a mini SVG spark-line / bar chart.
  - A **threat-level gauge**, a **decision-breakdown donut**, and an
    **attacks-by-type** bar chart — all **server-rendered SVG** (`charts.py`),
    so there is still **no JavaScript authored** (HTMX refreshes the whole
    panel every 3 s).
  - **Recent Decisions** (what was decided and *why*), the **Confirmed
    Exploitation** RASP feed, and **Live Trust Scores** with segmented bars.
- **Settings** (`/settings`) — every `WafConfig` control, applied live: Core,
  Identity, **Rate Limits**, **Tier 1**, **Coraza / RASP / XFF** toggles, and all
  Trust-Engine thresholds — plus a **↺ Reset to Defaults** button (restores every
  value via the Go `/api/admin/config/reset` endpoint, preserving admin accounts
  and the JWT secret).
- **Setup / Login / Logout** against the Go admin API.

All charts are generated in Python as SVG and all interactivity is HTMX — no
JavaScript or TypeScript source.

## Retiring the React app

This dashboard runs as its own service on `:8082` in front of the `:8081` admin
API. It replaced the former React SPA, and the admin server no longer serves any
static UI.

> Templates are validated by rendering them with sample config.
