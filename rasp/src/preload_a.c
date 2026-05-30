/*
 * preload_a.c -- Channel A: portable LD_PRELOAD interposition of the libc
 *                entry points a backend uses to execute processes, open files,
 *                and make outbound connections. Each interposer attributes the
 *                effect to the current request, classifies it, emits a verdict,
 *                and (when RASP_ENFORCE=1) refuses the dangerous action inline.
 *
 * Real functions are resolved with dlsym(RTLD_NEXT, ...), so this library links
 * no application code and can wrap any dynamically-linked backend.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <spawn.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "rasp_internal.h"

#define REAL(name) \
    static __typeof__(name) *real_##name; \
    if (real_##name == NULL) real_##name = dlsym(RTLD_NEXT, #name)

static rasp_action_t
action_for(rasp_severity_t sev)
{
    if (sev >= RASP_SEV_HIGH && rasp_enforce_enabled()) {
        return RASP_ACT_BLOCK;
    }
    return RASP_ACT_OBSERVE;
}

/* ── process execution → RCE ─────────────────────────────────────────────── */

/*
 * report_exec -- classify an exec of `path`, emit a verdict, and return 1 if it
 *                must be refused (errno set). Shared by the whole exec* family,
 *                because glibc's execv/execvp call execve INTERNALLY (bypassing
 *                the PLT), so interposing only execve misses subprocess/os.system
 *                style RCE. We hook each wrapper directly.
 */
static int
report_exec(const char *fn, const char *path)
{
    rasp_severity_t sev = rasp_classify_exec(path);
    if (sev == RASP_SEV_NONE) {
        return 0;
    }
    rasp_action_t act = action_for(sev);
    char ev[RASP_MAX_EVIDENCE];
    snprintf(ev, sizeof(ev), "%s %s", fn, path ? path : "(null)");
    rasp_emit(RASP_CAT_RCE, sev, act, ev);
    if (act != RASP_ACT_OBSERVE) {
        errno = EPERM;
        return 1;
    }
    return 0;
}

int
execve(const char *path, char *const argv[], char *const envp[])
{
    REAL(execve);
    if (report_exec("execve", path)) {
        return -1;
    }
    return real_execve(path, argv, envp);
}

int
execv(const char *path, char *const argv[])
{
    REAL(execv);
    if (report_exec("execv", path)) {
        return -1;
    }
    return real_execv(path, argv);
}

int
execvp(const char *file, char *const argv[])
{
    REAL(execvp);
    if (report_exec("execvp", file)) {
        return -1;
    }
    return real_execvp(file, argv);
}

int
execvpe(const char *file, char *const argv[], char *const envp[])
{
    REAL(execvpe);
    if (report_exec("execvpe", file)) {
        return -1;
    }
    return real_execvpe(file, argv, envp);
}

/* Modern CPython (subprocess, os.posix_spawn) execs via posix_spawn / spawnp,
 * which internally invoke execve without going through the PLT -- so we must
 * hook these directly too, or shell=True RCE slips past Channel A. */
int
posix_spawn(pid_t *pid, const char *path,
            const posix_spawn_file_actions_t *fa,
            const posix_spawnattr_t *attr,
            char *const argv[], char *const envp[])
{
    REAL(posix_spawn);
    if (report_exec("posix_spawn", path)) {
        return EPERM;   /* posix_spawn returns an errno, not -1 */
    }
    return real_posix_spawn(pid, path, fa, attr, argv, envp);
}

int
posix_spawnp(pid_t *pid, const char *file,
             const posix_spawn_file_actions_t *fa,
             const posix_spawnattr_t *attr,
             char *const argv[], char *const envp[])
{
    REAL(posix_spawnp);
    if (report_exec("posix_spawnp", file)) {
        return EPERM;
    }
    return real_posix_spawnp(pid, file, fa, attr, argv, envp);
}

int
system(const char *command)
{
    REAL(system);
    char ev[RASP_MAX_EVIDENCE];
    snprintf(ev, sizeof(ev), "system %s", command ? command : "(null)");
    rasp_action_t act = action_for(RASP_SEV_CRITICAL);
    rasp_emit(RASP_CAT_RCE, RASP_SEV_CRITICAL, act, ev);
    if (act != RASP_ACT_OBSERVE) {
        errno = EPERM;
        return -1;
    }
    return real_system(command);
}

/* ── file open → LFI / web-shell ─────────────────────────────────────────── */

static int
inspect_open(const char *path, int flags)
{
    rasp_severity_t sev = rasp_classify_open(path);
    rasp_category_t cat = RASP_CAT_LFI;

    /* A create+write of a script into a servable path looks like a web-shell. */
    if ((flags & O_CREAT) && path != NULL) {
        size_t n = strlen(path);
        if ((n > 4 && strcmp(path + n - 4, ".php") == 0) ||
            (n > 4 && strcmp(path + n - 4, ".jsp") == 0) ||
            (n > 3 && strcmp(path + n - 3, ".sh") == 0)) {
            sev = RASP_SEV_CRITICAL;
            cat = RASP_CAT_WEBSHELL;
        }
    }
    if (sev == RASP_SEV_NONE) {
        return 0;
    }
    rasp_action_t act = action_for(sev);
    char ev[RASP_MAX_EVIDENCE];
    snprintf(ev, sizeof(ev), "open %s", path ? path : "(null)");
    rasp_emit(cat, sev, act, ev);
    if (act != RASP_ACT_OBSERVE) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

int
open(const char *path, int flags, ...)
{
    REAL(open);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (inspect_open(path, flags) != 0) {
        return -1;
    }
    return real_open(path, flags, mode);
}

int
openat(int dirfd, const char *path, int flags, ...)
{
    REAL(openat);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (inspect_open(path, flags) != 0) {
        return -1;
    }
    return real_openat(dirfd, path, flags, mode);
}

/* Large-File-Support variants. CPython is built with _FILE_OFFSET_BITS=64, so it
 * actually calls open64/openat64 -- interposing only open/openat would miss LFI
 * (the same class of issue as posix_spawn vs execve). */
int
open64(const char *path, int flags, ...)
{
    REAL(open64);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (inspect_open(path, flags) != 0) {
        return -1;
    }
    return real_open64(path, flags, mode);
}

int
openat64(int dirfd, const char *path, int flags, ...)
{
    REAL(openat64);
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    if (inspect_open(path, flags) != 0) {
        return -1;
    }
    return real_openat64(dirfd, path, flags, mode);
}

/* ── outbound connection → SSRF ──────────────────────────────────────────── */

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    REAL(connect);
    if (addr != NULL && addr->sa_family == AF_INET) {
        const struct sockaddr_in *in = (const struct sockaddr_in *) addr;
        rasp_severity_t sev = rasp_classify_connect_v4(in->sin_addr.s_addr);
        if (sev != RASP_SEV_NONE) {
            rasp_action_t act = action_for(sev);
            char ip[INET_ADDRSTRLEN] = {0};
            unsigned int a = ntohl(in->sin_addr.s_addr);
            char ev[RASP_MAX_EVIDENCE];
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                     (a >> 24) & 0xff, (a >> 16) & 0xff,
                     (a >> 8) & 0xff, a & 0xff);
            snprintf(ev, sizeof(ev), "connect %s:%u", ip,
                     ntohs(in->sin_port));
            rasp_emit(RASP_CAT_SSRF, sev, act, ev);
            if (act != RASP_ACT_OBSERVE) {
                errno = ECONNREFUSED;
                return -1;
            }
        }
    }
    return real_connect(sockfd, addr, addrlen);
}
