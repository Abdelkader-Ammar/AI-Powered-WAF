/*
 * context.c -- per-thread request attribution. The instrumented backend calls
 *              rasp_ctx_set/clear around each request so interposed effects can
 *              be attributed to the originating IP / user.
 */
#include <string.h>

#include "rasp_internal.h"

static __thread rasp_reqctx_t g_ctx;

static void
copy_field(char *dst, const char *src, size_t cap)
{
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

void
rasp_ctx_set(const char *request_id, const char *ip,
             const char *user, const char *route)
{
    copy_field(g_ctx.request_id, request_id, RASP_MAX_REQID);
    copy_field(g_ctx.ip, ip, RASP_MAX_IP);
    copy_field(g_ctx.user, user, RASP_MAX_USER);
    copy_field(g_ctx.route, route, RASP_MAX_ROUTE);
    g_ctx.valid = 1;
}

void
rasp_ctx_clear(void)
{
    memset(&g_ctx, 0, sizeof(g_ctx));
}

const rasp_reqctx_t *
rasp_ctx_get(void)
{
    return g_ctx.valid ? &g_ctx : NULL;
}
