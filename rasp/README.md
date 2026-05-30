# RASP — Tier 2 (Runtime Application Self-Protection)

Ground-truth enforcement layer. It judges requests by what the backend
*actually does* (system calls and database queries), not by payload appearance,
and feeds the highest-weighted, override-capable signal into the Go trust engine
(`trustscore`).

## What builds here

This directory builds the **portable `LD_PRELOAD` channel** — the part that runs
in the demo and on any dynamically-linked backend, with a plain C toolchain:

```
make            # -> librasp_preload.so
```

- **Channel A** (`preload_a.c`) — interposes `execve`, `system`, `open`,
  `openat`, `connect` → detects RCE, LFI, web-shell writes, SSRF.
- **Channel B** (`pg_hook.c`) — interposes libpq `PQexec` / `PQexecParams`
  (via `dlsym`, so **no libpq link needed**) → detects structural SQL injection
  and unauthorized / sensitive-object database access.
- **context.c** — per-thread request attribution. The backend calls
  `rasp_ctx_set(request_id, ip, user, route)` at request entry and
  `rasp_ctx_clear()` at exit (e.g. from Flask `before_request`/`teardown` via
  `ctypes`), so each effect is attributed to the originating IP / user.
- **emitter.c** — sends one JSON verdict per effect over a unix socket
  (`$RASP_SOCKET`, default `/run/waf-rasp.sock`) in the exact shape
  `trustscore.StartRASPIngest` decodes. Falls back to stderr if the socket is
  absent.

> The `seccomp-unotify` and `BPF-LSM` enforcement cores from the design document
> are kernel-version and privilege dependent and are **not** built here; this
> portable channel is what the demo runs the target under.

## Usage

```sh
# Observe only (default): emit verdicts, never refuse.
LD_PRELOAD=$PWD/librasp_preload.so  your-backend

# Enforce channel A inline (refuse dangerous syscalls):
RASP_ENFORCE=1     LD_PRELOAD=$PWD/librasp_preload.so  your-backend

# Also refuse malicious DB queries (channel B):
RASP_DB_ENFORCE=1  LD_PRELOAD=$PWD/librasp_preload.so  your-backend

# Point at the trust engine's ingest socket:
RASP_SOCKET=/run/waf-rasp.sock  LD_PRELOAD=...  your-backend
```

Enable ingest on the WAF side by setting `enable_rasp: true` and
`rasp_socket_path` in `waf_config.json` (the orchestrator then runs
`trustscore.StartRASPIngest`).

## Environment variables

| Variable          | Default                | Effect                                  |
|-------------------|------------------------|-----------------------------------------|
| `RASP_SOCKET`     | `/run/waf-rasp.sock`   | Unix socket to emit verdicts to.        |
| `RASP_ENFORCE`    | unset (observe)        | `1` → refuse HIGH/CRITICAL syscalls.    |
| `RASP_DB_ENFORCE` | unset (observe)        | `1` → refuse HIGH/CRITICAL DB queries.  |

## Event schema (C `rasp_event_t` → Go `RASPEvent`)

```json
{"request_id":"...","ip":"...","user_id":"...","timestamp":1700000000,
 "category":"rce|lfi|webshell|ssrf|sqli|db_unauth|anomaly",
 "severity":"critical|high|medium|low","action":"blocked|killed|observed",
 "evidence":"argv[0] / path / table.column"}
```
