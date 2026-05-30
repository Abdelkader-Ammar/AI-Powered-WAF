/*
 * rasp.h -- public vocabulary shared by every RASP module.
 *           status codes, severity ladder, detection categories, and the
 *           action an interception channel takes on a dangerous effect.
 *
 * This is the portable (LD_PRELOAD) channel of the RASP. The seccomp / BPF-LSM
 * enforcement cores described in the design document are Linux-version and
 * privilege dependent and are built separately; this library is the part the
 * demo target runs under and is buildable with a plain C toolchain.
 */
#ifndef RASP_H
#define RASP_H

#include <stddef.h>

#define RASP_OK            0
#define RASP_ERR_PARAM   (-1)
#define RASP_ERR_IO      (-3)

#define RASP_MAX_EVIDENCE  256   /* bytes of evidence string we keep   */
#define RASP_MAX_REQID      64   /* X-WAF-Request-ID length cap        */
#define RASP_MAX_IP         64
#define RASP_MAX_USER       64
#define RASP_MAX_ROUTE     128

/* First constant is an error value so a zeroed value is self-detecting. */
typedef enum rasp_severity_t {
    RASP_SEV_NONE = 0,
    RASP_SEV_LOW,
    RASP_SEV_MEDIUM,
    RASP_SEV_HIGH,
    RASP_SEV_CRITICAL
} rasp_severity_t;

typedef enum rasp_category_t {
    RASP_CAT_NONE = 0,
    RASP_CAT_RCE,            /* channel A: process execution             */
    RASP_CAT_LFI,            /* channel A: sensitive file read           */
    RASP_CAT_WEBSHELL,       /* channel A: executable write to web root  */
    RASP_CAT_SSRF,           /* channel A: unexpected outbound connect   */
    RASP_CAT_SQLI,           /* channel B: structural injection in query */
    RASP_CAT_DB_UNAUTH,      /* channel B: out-of-policy table/op access */
    RASP_CAT_ANOMALY
} rasp_category_t;

typedef enum rasp_action_t {
    RASP_ACT_OBSERVE = 0,    /* log + report only                        */
    RASP_ACT_BLOCK,          /* refuse the syscall / query inline        */
    RASP_ACT_KILL            /* refuse + close the request's connection  */
} rasp_action_t;

/* String names for the wire JSON the Go trust engine ingests. */
const char *rasp_severity_name(rasp_severity_t s);
const char *rasp_category_name(rasp_category_t c);
const char *rasp_action_name(rasp_action_t a);

#endif /* RASP_H */
