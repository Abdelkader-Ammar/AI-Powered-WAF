/*
 * engine.c -- classification and policy. Turns an observed effect into a
 *             severity. Deliberately conservative defaults suited to a web
 *             backend that should never exec, never read system secrets, and
 *             only connect to allowlisted hosts.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdio.h>

#include "rasp_internal.h"

int
rasp_enforce_enabled(void)
{
    const char *e = getenv("RASP_ENFORCE");
    return e != NULL && e[0] == '1';
}

int
rasp_db_enforce_enabled(void)
{
    const char *e = getenv("RASP_DB_ENFORCE");
    return e != NULL && e[0] == '1';
}

/* A web backend essentially never exec()s during request handling. */
rasp_severity_t
rasp_classify_exec(const char *path)
{
    (void) path;
    return RASP_SEV_CRITICAL;
}

/* Sensitive reads and path traversal are the file-channel signals. */
rasp_severity_t
rasp_classify_open(const char *path)
{
    if (path == NULL) {
        return RASP_SEV_NONE;
    }
    if (strstr(path, "..") != NULL) {
        return RASP_SEV_HIGH;            /* path traversal attempt */
    }
    if (strcmp(path, "/etc/passwd") == 0 ||
        strcmp(path, "/etc/shadow") == 0 ||
        strncmp(path, "/etc/ssh", 8) == 0 ||
        strstr(path, "id_rsa") != NULL) {
        return RASP_SEV_CRITICAL;        /* system secret read */
    }
    return RASP_SEV_NONE;
}

/* SSRF: outbound connect to a link-local / cloud-metadata address. be_addr is
 * the IPv4 address in network byte order (as in struct sockaddr_in.sin_addr). */
rasp_severity_t
rasp_classify_connect_v4(unsigned int be_addr)
{
    unsigned char a = (unsigned char) (be_addr & 0xff);          /* first octet */
    unsigned char b = (unsigned char) ((be_addr >> 8) & 0xff);   /* second      */

    if (a == 169 && b == 254) {
        return RASP_SEV_HIGH;            /* 169.254.0.0/16 -> cloud metadata */
    }
    return RASP_SEV_NONE;
}

/* Case-insensitive substring search. */
static int
icontains(const char *hay, const char *needle)
{
    return strcasestr(hay, needle) != NULL;
}

/* Count top-level statement separators that are followed by more SQL. A simple
 * heuristic: a ';' that is not the final non-space character implies a stacked
 * statement. Good enough for the demo's clearly-malicious payloads. */
static int
has_stacked_statement(const char *sql)
{
    const char *semi = strchr(sql, ';');
    while (semi != NULL) {
        const char *p = semi + 1;
        while (*p != '\0' && isspace((unsigned char) *p)) {
            p++;
        }
        if (*p != '\0') {
            return 1;
        }
        semi = strchr(p, ';');
    }
    return 0;
}

rasp_severity_t
rasp_classify_sql(const char *sql, rasp_category_t *cat_out,
                  char *evidence, size_t evidence_len)
{
    if (sql == NULL) {
        return RASP_SEV_NONE;
    }
    *cat_out = RASP_CAT_NONE;

    /* (1) Always-on sensitive-object denylist for an application route. */
    if (icontains(sql, "information_schema") || icontains(sql, "pg_catalog") ||
        icontains(sql, "pg_shadow") || icontains(sql, "pg_authid")) {
        *cat_out = RASP_CAT_DB_UNAUTH;
        snprintf(evidence, evidence_len, "schema/catalog access: %.120s", sql);
        return RASP_SEV_CRITICAL;
    }
    if (icontains(sql, "drop table") || icontains(sql, "drop database") ||
        icontains(sql, "grant ") || icontains(sql, " into outfile") ||
        icontains(sql, "copy ") || icontains(sql, "load_file")) {
        *cat_out = RASP_CAT_DB_UNAUTH;
        snprintf(evidence, evidence_len, "DDL/DCL/file op: %.120s", sql);
        return RASP_SEV_CRITICAL;
    }

    /* (2) Structural injection in the assembled query. */
    if (has_stacked_statement(sql)) {
        *cat_out = RASP_CAT_SQLI;
        snprintf(evidence, evidence_len, "stacked statement: %.120s", sql);
        return RASP_SEV_CRITICAL;
    }
    if (icontains(sql, "union") && icontains(sql, "select")) {
        *cat_out = RASP_CAT_SQLI;
        snprintf(evidence, evidence_len, "union-based injection: %.120s", sql);
        return RASP_SEV_CRITICAL;
    }
    if (icontains(sql, "or 1=1") || icontains(sql, "or '1'='1") ||
        icontains(sql, "or 1 = 1")) {
        *cat_out = RASP_CAT_SQLI;
        snprintf(evidence, evidence_len, "tautology: %.120s", sql);
        return RASP_SEV_HIGH;
    }

    return RASP_SEV_NONE;
}
