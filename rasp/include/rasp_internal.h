/*
 * rasp_internal.h -- declarations shared between the RASP agent's own
 *                    translation units (context, emitter, engine, channels).
 *                    Not part of the public surface.
 */
#ifndef RASP_INTERNAL_H
#define RASP_INTERNAL_H

#include "rasp.h"

/* ── Request attribution (context/) ──────────────────────────────────────── */

/*
 * A per-thread request context. The backend (the demo Flask target) calls
 * rasp_ctx_set() at request entry and rasp_ctx_clear() at request exit, via
 * ctypes, so each interposed syscall / query can be attributed to the HTTP
 * request -- and therefore the IP / user -- that caused it. This is the
 * "context shim" from the design document, made explicit for an instrumentable
 * backend.
 */
typedef struct rasp_reqctx_t {
    char request_id[RASP_MAX_REQID];
    char ip[RASP_MAX_IP];
    char user[RASP_MAX_USER];
    char route[RASP_MAX_ROUTE];
    int  valid;
} rasp_reqctx_t;

/* Exported (visible to ctypes) -- called by the instrumented backend. */
void rasp_ctx_set(const char *request_id, const char *ip,
                  const char *user, const char *route);
void rasp_ctx_clear(void);

/* Internal -- returns the calling thread's context, or NULL if none set. */
const rasp_reqctx_t *rasp_ctx_get(void);

/* ── Reporting (report/) ─────────────────────────────────────────────────── */

/*
 * rasp_emit -- send one verdict to the trust engine as a JSON line over the
 *              configured unix socket ($RASP_SOCKET, default /run/waf-rasp.sock).
 *              Falls back to stderr when the socket is unavailable so the demo
 *              is still legible. Never blocks the caller for long.
 */
void rasp_emit(rasp_category_t cat, rasp_severity_t sev,
               rasp_action_t act, const char *evidence);

/* ── Policy / classification (engine/) ───────────────────────────────────── */

int rasp_enforce_enabled(void);     /* RASP_ENFORCE=1 -> block, else observe   */
int rasp_db_enforce_enabled(void);  /* RASP_DB_ENFORCE=1 -> refuse bad queries */

/* Channel A classifiers: return a severity (RASP_SEV_NONE = allow). */
rasp_severity_t rasp_classify_exec(const char *path);
rasp_severity_t rasp_classify_open(const char *path);
rasp_severity_t rasp_classify_connect_v4(unsigned int be_addr); /* network order */

/* Channel B classifier: structural / authorization analysis of a SQL string. */
rasp_severity_t rasp_classify_sql(const char *sql, rasp_category_t *cat_out,
                                  char *evidence, size_t evidence_len);

#endif /* RASP_INTERNAL_H */
