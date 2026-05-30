/*
 * pg_hook.c -- Channel B: interpose libpq's query entry points to catch
 *              unauthorized database access -- structural SQL injection and
 *              sensitive-object / DDL access -- on the fully-assembled query the
 *              driver is about to send.
 *
 * The real symbols are resolved with dlsym(RTLD_NEXT, ...), so this library does
 * NOT link libpq: the interposers only become active inside a process that has
 * itself loaded libpq (e.g. a psycopg2 / libpq backend). PGconn / PGresult are
 * treated as opaque void* so no libpq headers are required to build.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include "rasp_internal.h"

typedef void *(*pqexec_fn)(void *conn, const char *query);
typedef void *(*pqexecparams_fn)(void *conn, const char *command, int n,
                                 const unsigned int *types,
                                 const char *const *values,
                                 const int *lengths, const int *formats,
                                 int result_fmt);

/* Inspect a query; return 1 if it should be refused (and a verdict emitted). */
static int
inspect_query(const char *sql)
{
    if (sql == NULL) {
        return 0;
    }
    rasp_category_t cat = RASP_CAT_NONE;
    char ev[RASP_MAX_EVIDENCE];
    rasp_severity_t sev = rasp_classify_sql(sql, &cat, ev, sizeof(ev));
    if (sev == RASP_SEV_NONE) {
        return 0;
    }
    int refuse = (sev >= RASP_SEV_HIGH) && rasp_db_enforce_enabled();
    rasp_emit(cat, sev, refuse ? RASP_ACT_BLOCK : RASP_ACT_OBSERVE, ev);
    return refuse;
}

void *
PQexec(void *conn, const char *query)
{
    static pqexec_fn real;
    if (real == NULL) {
        real = (pqexec_fn) dlsym(RTLD_NEXT, "PQexec");
    }
    /* If the real libpq is unreachable (e.g. statically bundled inside a binary
     * wheel so RTLD_NEXT yields NULL), we MUST NOT call through a NULL pointer.
     * Forwarding is impossible, so fail the query cleanly instead of crashing. */
    if (real == NULL) {
        return NULL;
    }
    if (inspect_query(query)) {
        return NULL; /* refuse: the driver caller sees a failed query */
    }
    return real(conn, query);
}

void *
PQexecParams(void *conn, const char *command, int n,
             const unsigned int *types, const char *const *values,
             const int *lengths, const int *formats, int result_fmt)
{
    static pqexecparams_fn real;
    if (real == NULL) {
        real = (pqexecparams_fn) dlsym(RTLD_NEXT, "PQexecParams");
    }
    if (real == NULL) {
        return NULL;
    }
    if (inspect_query(command)) {
        return NULL;
    }
    return real(conn, command, n, types, values, lengths, formats, result_fmt);
}
