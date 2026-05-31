# AI-WAF Demo & Testing Harness (standalone)

A disposable, **black-box** harness that stands up the whole WAF in front of a
deliberately-vulnerable target, fires a labelled catalogue of attacks, and shows
— read-only — how each tier (Gatekeeper → Coraza → Tier 0 → Tier 1 → RASP)
reacts and how the trust score moves. It changes **no** product code; deleting
`demo/` removes it entirely.

## Layout

```
demo/
  docker-compose.yml     the WAF (built from ../tier-0, ../rasp, ...) + target + deps
  orchestrator.Dockerfile
  target/                deliberately-vulnerable Flask + Postgres backend (DEMO ONLY)
  attacks/               sim.py (labelled black-box attacker) + scenarios.yaml
  observer/              console.py (read-only request-journey view)
  tests/                 pytest assertions over the same scenarios
  Makefile               make up / attack / watch / storyline / test / down
```

## Prerequisites

- **Docker** and **Docker Compose** (the whole stack runs in containers).
- **Python 3.10+** on the host to run the attacker and the console:
  `pip install -r requirements.txt` (installs `httpx` and `pyyaml`).
- First `make up` downloads base images and, if a RoBERTa checkpoint is provided,
  the model weights. Everything binds on a private Docker network; only the proxy,
  admin API, and dashboard are exposed to localhost.

## Quick start

```sh
cd demo
cp .env.example .env
make up                      # build + start everything (private network)
pip install -r requirements.txt

# In one terminal — the live correlation console:
make watch

# In another — drive attacks:
make storyline               # the scripted narrative (see below)
make attack S=rce_exec       # a single scenario
make test                    # black-box regression suite
make down                    # tear everything down
```

Ports: proxy `:8080`, admin API `:8081`, **dashboard** `:8082`.
Internal-only: Redis `:6379`, Postgres `:5432`, Tier 1 service `:5001`.

Open `http://localhost:8082` for the dashboard. The first time, create an admin
account on the sign-up screen, then watch the two live feeds while the storyline
runs.

### Fast rebuilds

The orchestrator's Go binary is compiled by `make proxy` inside a `golang`
container with a persistent Go build cache (named volumes `ai-waf-gobuild` /
`ai-waf-gomod`), then the image just copies it in. After the first build, a code
change rebuilds in seconds instead of minutes:

```sh
make proxy   # recompile demo/bin/waf-proxy (incremental, cached)
make orch    # recompile + rebuild & restart just the orchestrator
```

(This avoids an in-image `go build`; the cache mounts that would normally speed
that up need BuildKit/buildx, which isn't always present. The build cache volumes
survive `make down`, so they only cold-build once.)

## Decision bands and the trust score

The trust engine assigns each entity a score in `0–10` and maps it to a decision:

| Score | Decision | Meaning |
| :--- | :--- | :--- |
| `>= 8` | **allow** | trusted |
| `5 – 7.9` | allow + stricter | allowed, under tighter rate limits |
| `3 – 4.9` | **challenge** | suspicious but unproven — served a proof-of-work |
| `1 – 2.9` | **block** | this request is denied |
| `< 1` | **ban** | the entity is denied on every future request |

A confirmed RASP exploit is treated as ground truth and overrides the score to
`0` (ban) regardless of prior reputation.

## What `make storyline` demonstrates

A paced, narrated sequence that exercises **every decision band** and the RASP,
shows **per-actor isolation**, and proves the **ban persists**. It is timed
(roughly a quarter-second between requests, a short pause between phases) so an
operator watching the dashboard can see each phase land in turn.

1. A **clean user** browses → trust climbs, all `allow`.
2. The Gatekeeper / trust engine, each attack from its **own fresh IP**:
   - recon sweep (sensitive-path probing) → **block**
   - ID enumeration → behavioral signal
   - brute force (repeated failed logins) → **block**
   - a **DDoS** flood → hard-override **ban**
   - a single sensitive-endpoint probe → **challenge** (the IP, and even its
     following benign requests, are served a proof-of-work until it proves itself)
3. Payload tiers: a classic SQLi and a reflected XSS. **By default this demo ships
   with the signature/ML front tiers permissive** (Coraza off, ML threshold `0.99`)
   to spotlight the RASP, so most payloads reach the backend instead of being
   blocked at the edge. Enable Coraza or lower the threshold in **Settings** to see
   the front wall catch them.
4. **RASP (Tier 2)** — the real exploitation, each from a fresh IP. The backend
   runs under the RASP shim, so the dangerous operation is caught **inline at the
   backend** and the entity's score craters to `0` (ban):
   - RCE (`/ping?host=...;id`) → refused process exec
   - web-shell upload (a `.php` filename with plain text, **no** `<?php` — invisible
     to signature/ML tiers) → refused executable write
   - LFI (`/download?file=/etc/passwd`) → refused sensitive read
   - SSRF (`http://169.254.169.254/...`) → refused metadata connection
5. The **banned RCE attacker retries a perfectly innocent request → still refused**
   at the edge (the ban sticks).
6. The **clean user from step 1 is unaffected** — proving per-actor isolation.

Every row in the dashboard's **Recent Decisions** and **Confirmed Exploitation**
feeds is click-to-expand: open one to see the full payload (path + query + body),
the exact reason, the LightGBM probability, the Coraza verdict, the trust score,
the request id, and for RASP rows the precise syscall/query attempted.

Distinct actors are presented via `X-Forwarded-For` (the orchestrator runs with
`TRUST_XFORWARDED=true` in the demo), so attacker, victim, and clean user are
scored independently — and a ban on one does not affect the others.

### Watch it live

`make watch` (terminal) shows the request journey. The dashboard (`:8082`) has two
live feeds that answer *why* and *how* each request was decided:

- **Recent Decisions** — per request: the decision (`block_coraza`, `block_lgbm`,
  `ban`, `challenge`, …), the LightGBM probability, the trust score, and a
  one-line reason. A request the front tiers allowed but the RASP blocked at the
  backend is shown as exactly that.
- **Confirmed Exploitation** — the ground-truth feed: category
  (`rce`/`webshell`/`lfi`/`ssrf`), severity, action (`blocked`/`observed`), and the
  evidence (the exact syscall / query the backend attempted).

### RASP channel reliability (honest notes)

- **Channel A (syscalls)** is reliable: the target runs under the `LD_PRELOAD`
  shim, which interposes `execve`/`execv`/`posix_spawn` (CPython's subprocess
  path), `open(at)`/`open64`, and `connect`. The shim is fork-safe (the backend
  uses `fork()` rather than `vfork()` so a refused exec is reported without
  corrupting the parent).
- **Channel B (DB query interposition)** is opt-in: it needs the backend to
  *dynamically* link a reachable `libpq`. The demo target uses the `psycopg2`
  binary wheel, which statically bundles libpq, so this channel is built out by
  default (`make RASP_DB_HOOK=1` enables it on a source-libpq deployment).

## Safety

The target is deliberately insecure, so it binds only on the private demo network,
never to a host port. `/etc/passwd` in the target container is a planted fake; the
SSRF "metadata" target is an in-network stub. The observer holds no write handle
to Redis, the audit DB, or the WAF. `make down` removes everything.

## Notes

- **Tier 1 is optional**: it needs a trained RoBERTa checkpoint
  (`ROBERTA_MODEL_PATH`); without it the orchestrator logs a warning and runs the
  other tiers normally, so the gray-zone scenario simply won't get a deep verdict.
- The Docker images are not built in CI here; the Go binary, the RASP `.so`, the
  dashboard templates, and the Python tools are individually validated.
