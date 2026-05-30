/*
 * emitter.c -- send RASP verdicts to the trust engine as newline-delimited JSON
 *              over a unix domain socket. The Go side (trustscore.StartRASPIngest)
 *              decodes the same shape. Falls back to stderr when the socket is
 *              unavailable so a demo without the full stack is still legible.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "rasp_internal.h"

#define DEFAULT_SOCKET "/run/waf-rasp.sock"

static pthread_mutex_t g_emit_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_sock = -1;

/*
 * Fork safety. A backend that handles RCE execs the shell via fork()+exec(), and
 * our exec interposer emits a verdict from the *child* (between fork and exec).
 * If another request thread held g_emit_lock at the moment of fork, the child's
 * copy of that lock is permanently locked -> the child would deadlock inside
 * rasp_emit and hang the worker. After fork in the child we therefore reset the
 * lock to a clean state and drop the inherited socket fd so the child opens its
 * own connection rather than racing the parent's writes on a shared fd.
 *
 * (The backend must use fork(), not vfork(): a vfork child shares the parent's
 * address space, so emitting from it would corrupt the parent. The demo target
 * sets subprocess._USE_VFORK = False for exactly this reason.)
 */
static void
rasp_atfork_child(void)
{
    pthread_mutex_init(&g_emit_lock, NULL);
    g_sock = -1;
}

__attribute__((constructor))
static void
rasp_emitter_init(void)
{
    pthread_atfork(NULL, NULL, rasp_atfork_child);
}

const char *
rasp_severity_name(rasp_severity_t s)
{
    switch (s) {
    case RASP_SEV_CRITICAL: return "critical";
    case RASP_SEV_HIGH:     return "high";
    case RASP_SEV_MEDIUM:   return "medium";
    case RASP_SEV_LOW:      return "low";
    default:                return "none";
    }
}

const char *
rasp_category_name(rasp_category_t c)
{
    switch (c) {
    case RASP_CAT_RCE:       return "rce";
    case RASP_CAT_LFI:       return "lfi";
    case RASP_CAT_WEBSHELL:  return "webshell";
    case RASP_CAT_SSRF:      return "ssrf";
    case RASP_CAT_SQLI:      return "sqli";
    case RASP_CAT_DB_UNAUTH: return "db_unauth";
    case RASP_CAT_ANOMALY:   return "anomaly";
    default:                 return "none";
    }
}

const char *
rasp_action_name(rasp_action_t a)
{
    switch (a) {
    case RASP_ACT_BLOCK: return "blocked";
    case RASP_ACT_KILL:  return "killed";
    default:             return "observed";
    }
}

static const char *
socket_path(void)
{
    const char *p = getenv("RASP_SOCKET");
    return (p != NULL && p[0] != '\0') ? p : DEFAULT_SOCKET;
}

/* Connect (or reconnect) to the trust-engine ingest socket. Caller holds lock. */
static int
ensure_socket(void)
{
    if (g_sock >= 0) {
        return g_sock;
    }
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path(), sizeof(addr.sun_path) - 1);
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    g_sock = fd;
    return g_sock;
}

/* Append src to dst as a JSON string body, escaping the few chars that matter. */
static void
json_escape(char *dst, size_t cap, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src != NULL && src[i] != '\0' && j + 2 < cap; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            dst[j++] = '\\';
            dst[j++] = c;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            dst[j++] = ' ';
        } else if ((unsigned char) c < 0x20) {
            dst[j++] = ' ';
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

void
rasp_emit(rasp_category_t cat, rasp_severity_t sev,
          rasp_action_t act, const char *evidence)
{
    const rasp_reqctx_t *ctx = rasp_ctx_get();
    char ev_esc[RASP_MAX_EVIDENCE * 2 + 1];
    json_escape(ev_esc, sizeof(ev_esc), evidence);

    char line[1024];
    int n = snprintf(line, sizeof(line),
        "{\"request_id\":\"%s\",\"ip\":\"%s\",\"user_id\":\"%s\","
        "\"timestamp\":%ld,\"category\":\"%s\",\"severity\":\"%s\","
        "\"action\":\"%s\",\"evidence\":\"%s\"}\n",
        ctx ? ctx->request_id : "",
        ctx ? ctx->ip : "",
        ctx ? ctx->user : "",
        (long) time(NULL),
        rasp_category_name(cat), rasp_severity_name(sev),
        rasp_action_name(act), ev_esc);
    if (n < 0) {
        return;
    }
    if (n >= (int) sizeof(line)) {
        n = sizeof(line) - 1;
    }

    pthread_mutex_lock(&g_emit_lock);
    /* Try twice: a connection left stale by an ingest restart fails the first
     * write, so we drop it and reconnect for an immediate retry rather than
     * losing the event (which previously dropped the first emit after a restart). */
    int delivered = 0;
    for (int attempt = 0; attempt < 2 && !delivered; attempt++) {
        int fd = ensure_socket();
        if (fd < 0) {
            break;
        }
        if (write(fd, line, (size_t) n) == n) {
            delivered = 1;
        } else {
            close(g_sock);   /* broken connection; reconnect and retry once */
            g_sock = -1;
        }
    }
    if (!delivered) {
        /* Fallback: make the verdict visible even without the trust engine. */
        fprintf(stderr, "[RASP] %s", line);
    }
    pthread_mutex_unlock(&g_emit_lock);
}
