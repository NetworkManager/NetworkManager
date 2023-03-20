/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "libnm-glib-aux/nm-default-glib-i18n-lib.h"

#include "nm-logging.h"

#include <dlfcn.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <strings.h>

#if SYSTEMD_JOURNAL
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-journal.h>
#endif

#include "libnm-glib-aux/nm-logging-base.h"
#include "libnm-glib-aux/nm-time-utils.h"
#include "libnm-glib-aux/nm-str-buf.h"

/*****************************************************************************/

/* Notes about thread-safety:
 *
 * NetworkManager generally is single-threaded and uses a (GLib) mainloop.
 * However, nm-logging is in parts thread-safe. That means:
 *
 * - functions that configure logging (nm_logging_init(), nm_logging_setup()) and
 *   most other functions MUST be called only from the main-thread. These functions
 *   are expected to be called infrequently, so they may or may not use a mutex
 *   (but the overhead is negligible here).
 *
 * - functions that do the actual logging logging (nm_log(), nm_logging_enabled()) are
 *   thread-safe and may be used from multiple threads.
 *    - When called from the not-main-thread, @mt_require_locking must be set to %TRUE.
 *      In this case, a Mutex will be used for accessing the global state.
 *    - When called from the main-thread, they may optionally pass @mt_require_locking %FALSE.
 *      This avoids extra locking and is in particular interesting for nm_logging_enabled(),
 *      which is expected to be called frequently and from the main-thread.
 *
 * Note that the logging macros honor %NM_THREAD_SAFE_ON_MAIN_THREAD define, to automatically
 * set @mt_require_locking. That means, by default %NM_THREAD_SAFE_ON_MAIN_THREAD is "1",
 * and code that only runs on the main-thread (which is the majority), can get away
 * without locking.
 */

/*****************************************************************************/

G_STATIC_ASSERT(LOG_EMERG == 0);
G_STATIC_ASSERT(LOG_ALERT == 1);
G_STATIC_ASSERT(LOG_CRIT == 2);
G_STATIC_ASSERT(LOG_ERR == 3);
G_STATIC_ASSERT(LOG_WARNING == 4);
G_STATIC_ASSERT(LOG_NOTICE == 5);
G_STATIC_ASSERT(LOG_INFO == 6);
G_STATIC_ASSERT(LOG_DEBUG == 7);

/* We have more then 32 logging domains. Assert that it compiles to a 64 bit sized enum */
G_STATIC_ASSERT(sizeof(NMLogDomain) >= sizeof(guint64));

/* Combined domains */
#define LOGD_ALL_STRING     "ALL"
#define LOGD_DEFAULT_STRING "DEFAULT"
#define LOGD_DHCP_STRING    "DHCP"
#define LOGD_IP_STRING      "IP"

/*****************************************************************************/

typedef enum {
    LOG_BACKEND_GLIB,
    LOG_BACKEND_SYSLOG,
    LOG_BACKEND_JOURNAL,
} LogBackend;

typedef struct {
    NMLogDomain num;
    const char *name;
} LogDesc;

typedef struct {
    char *logging_domains_to_string;
} GlobalMain;

typedef struct {
    NMLogLevel  log_level;
    bool        uses_syslog : 1;
    bool        init_pre_done : 1;
    bool        init_done : 1;
    bool        debug_stderr : 1;
    const char *prefix;
    const char *syslog_identifier;

    /* before we setup syslog (during start), the backend defaults to GLIB, meaning:
     * we use g_log() for all logging. At that point, the application is not yet supposed
     * to do any logging and doing so indicates a bug.
     *
     * Afterwards, the backend is either SYSLOG or JOURNAL. From that point, also
     * g_log() is redirected to this backend via a logging handler. */
    LogBackend log_backend;
} Global;

/*****************************************************************************/

G_LOCK_DEFINE_STATIC(log);

/* This data must only be accessed from the main-thread (and as
 * such does not need any lock). */
static GlobalMain gl_main = {};

static union {
    /* a union with an immutable and a mutable alias for the Global.
     * Since nm-logging must be thread-safe, we must take care at which
     * places we only read value ("imm") and where we modify them ("mut"). */
    Global       mut;
    const Global imm;
} gl = {
    .imm =
        {
            /* nm_logging_setup ("INFO", LOGD_DEFAULT_STRING, NULL, NULL); */
            .log_level         = LOGL_INFO,
            .log_backend       = LOG_BACKEND_GLIB,
            .syslog_identifier = "SYSLOG_IDENTIFIER=NetworkManager",
            .prefix            = "",
        },
};

NMLogDomain _nm_logging_enabled_state[_LOGL_N_REAL] = {
    /* nm_logging_setup ("INFO", LOGD_DEFAULT_STRING, NULL, NULL);
     *
     * Note: LOGD_VPN_PLUGIN is special and must be disabled for
     * DEBUG and TRACE levels. */
    [LOGL_INFO] = LOGD_DEFAULT,
    [LOGL_WARN] = LOGD_DEFAULT,
    [LOGL_ERR]  = LOGD_DEFAULT,
};

/*****************************************************************************/

static const LogDesc domain_desc[] = {
    {LOGD_PLATFORM, "PLATFORM"},
    {LOGD_RFKILL, "RFKILL"},
    {LOGD_ETHER, "ETHER"},
    {LOGD_WIFI, "WIFI"},
    {LOGD_BT, "BT"},
    {LOGD_MB, "MB"},
    {LOGD_DHCP4, "DHCP4"},
    {LOGD_DHCP6, "DHCP6"},
    {LOGD_PPP, "PPP"},
    {LOGD_WIFI_SCAN, "WIFI_SCAN"},
    {LOGD_IP4, "IP4"},
    {LOGD_IP6, "IP6"},
    {LOGD_AUTOIP4, "AUTOIP4"},
    {LOGD_DNS, "DNS"},
    {LOGD_VPN, "VPN"},
    {LOGD_SHARING, "SHARING"},
    {LOGD_SUPPLICANT, "SUPPLICANT"},
    {LOGD_AGENTS, "AGENTS"},
    {LOGD_SETTINGS, "SETTINGS"},
    {LOGD_SUSPEND, "SUSPEND"},
    {LOGD_CORE, "CORE"},
    {LOGD_DEVICE, "DEVICE"},
    {LOGD_OLPC, "OLPC"},
    {LOGD_INFINIBAND, "INFINIBAND"},
    {LOGD_FIREWALL, "FIREWALL"},
    {LOGD_ADSL, "ADSL"},
    {LOGD_BOND, "BOND"},
    {LOGD_VLAN, "VLAN"},
    {LOGD_BRIDGE, "BRIDGE"},
    {LOGD_DBUS_PROPS, "DBUS_PROPS"},
    {LOGD_TEAM, "TEAM"},
    {LOGD_CONCHECK, "CONCHECK"},
    {LOGD_DCB, "DCB"},
    {LOGD_DISPATCH, "DISPATCH"},
    {LOGD_AUDIT, "AUDIT"},
    {LOGD_SYSTEMD, "SYSTEMD"},
    {LOGD_VPN_PLUGIN, "VPN_PLUGIN"},
    {LOGD_PROXY, "PROXY"},
    {0},
};

/*****************************************************************************/

static char *_domains_to_string(gboolean          include_level_override,
                                NMLogLevel        log_level,
                                const NMLogDomain log_state[static _LOGL_N_REAL]);

/*****************************************************************************/

static gboolean
_syslog_identifier_valid_domain(const char *domain)
{
    char c;

    if (!domain || !domain[0])
        return FALSE;

    /* we pass the syslog identifier as format string. No funny stuff. */

    for (; (c = domain[0]); domain++) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || NM_IN_SET(c, '-', '_'))
            continue;
        return FALSE;
    }
    return TRUE;
}

static gboolean
_syslog_identifier_assert(const char *syslog_identifier)
{
    g_assert(syslog_identifier);
    g_assert(g_str_has_prefix(syslog_identifier, "SYSLOG_IDENTIFIER="));
    g_assert(_syslog_identifier_valid_domain(&syslog_identifier[NM_STRLEN("SYSLOG_IDENTIFIER=")]));
    return TRUE;
}

static const char *
syslog_identifier_domain(const char *syslog_identifier)
{
    nm_assert(_syslog_identifier_assert(syslog_identifier));
    return &syslog_identifier[NM_STRLEN("SYSLOG_IDENTIFIER=")];
}

#if SYSTEMD_JOURNAL
static const char *
syslog_identifier_full(const char *syslog_identifier)
{
    nm_assert(_syslog_identifier_assert(syslog_identifier));
    return &syslog_identifier[0];
}
#endif

/*****************************************************************************/

static gboolean
match_log_level(const char *level, NMLogLevel *out_level, GError **error)
{
    if (_nm_log_parse_level(level, out_level))
        return TRUE;

    g_set_error(error,
                _NM_MANAGER_ERROR,
                _NM_MANAGER_ERROR_UNKNOWN_LOG_LEVEL,
                _("Unknown log level '%s'"),
                level);
    return FALSE;
}

gboolean
nm_logging_setup(const char *level, const char *domains, char **bad_domains, GError **error)
{
    GString             *unrecognized = NULL;
    NMLogDomain          cur_log_state[_LOGL_N_REAL];
    NMLogDomain          new_log_state[_LOGL_N_REAL];
    NMLogLevel           cur_log_level;
    NMLogLevel           new_log_level;
    gs_free const char **domains_v = NULL;
    gsize                i_d;
    int                  i;
    gboolean             had_platform_debug;
    gs_free char        *domains_free = NULL;

    NM_ASSERT_ON_MAIN_THREAD();

    g_return_val_if_fail(!bad_domains || !*bad_domains, FALSE);
    g_return_val_if_fail(!error || !*error, FALSE);

    cur_log_level = gl.imm.log_level;
    memcpy(cur_log_state, _nm_logging_enabled_state, sizeof(cur_log_state));

    new_log_level = cur_log_level;

    if (!domains || !*domains) {
        domains_free = _domains_to_string(FALSE, cur_log_level, cur_log_state);
        domains      = domains_free;
    }

    for (i = 0; i < G_N_ELEMENTS(new_log_state); i++)
        new_log_state[i] = 0;

    if (level && *level) {
        if (!match_log_level(level, &new_log_level, error))
            return FALSE;
        if (new_log_level == _LOGL_KEEP) {
            new_log_level = cur_log_level;
            for (i = 0; i < G_N_ELEMENTS(new_log_state); i++)
                new_log_state[i] = cur_log_state[i];
        }
    }

    domains_v = nm_strsplit_set(domains, ", ");
    for (i_d = 0; domains_v && domains_v[i_d]; i_d++) {
        const char    *s = domains_v[i_d];
        const char    *p;
        const LogDesc *diter;
        NMLogLevel     domain_log_level;
        NMLogDomain    bits;

        /* LOGD_VPN_PLUGIN is protected, that is, when setting ALL or DEFAULT,
         * it does not enable the verbose levels DEBUG and TRACE, because that
         * may expose sensitive data. */
        NMLogDomain protect = LOGD_NONE;

        p = strchr(s, ':');
        if (p) {
            *((char *) p) = '\0';
            if (!match_log_level(p + 1, &domain_log_level, error))
                return FALSE;
        } else
            domain_log_level = new_log_level;

        bits = 0;

        if (domains_free) {
            /* The caller didn't provide any domains to set (`nmcli general logging level DEBUG`).
             * We reset all domains that were previously set, but we still want to protect
             * VPN_PLUGIN domain. */
            protect = LOGD_VPN_PLUGIN;
        }

        /* Check for combined domains */
        if (!g_ascii_strcasecmp(s, LOGD_ALL_STRING)) {
            bits    = LOGD_ALL;
            protect = LOGD_VPN_PLUGIN;
        } else if (!g_ascii_strcasecmp(s, LOGD_DEFAULT_STRING)) {
            bits    = LOGD_DEFAULT;
            protect = LOGD_VPN_PLUGIN;
        } else if (!g_ascii_strcasecmp(s, LOGD_DHCP_STRING))
            bits = LOGD_DHCP;
        else if (!g_ascii_strcasecmp(s, LOGD_IP_STRING))
            bits = LOGD_IP;

        /* Check for compatibility domains */
        else if (!g_ascii_strcasecmp(s, "HW"))
            bits = LOGD_PLATFORM;
        else if (!g_ascii_strcasecmp(s, "WIMAX"))
            continue;

        else {
            for (diter = &domain_desc[0]; diter->name; diter++) {
                if (!g_ascii_strcasecmp(diter->name, s)) {
                    bits = diter->num;
                    break;
                }
            }

            if (!bits) {
                if (!bad_domains) {
                    g_set_error(error,
                                _NM_MANAGER_ERROR,
                                _NM_MANAGER_ERROR_UNKNOWN_LOG_DOMAIN,
                                _("Unknown log domain '%s'"),
                                s);
                    return FALSE;
                }

                if (unrecognized)
                    g_string_append(unrecognized, ", ");
                else
                    unrecognized = g_string_new(NULL);
                g_string_append(unrecognized, s);
                continue;
            }
        }

        if (domain_log_level == _LOGL_KEEP) {
            for (i = 0; i < G_N_ELEMENTS(new_log_state); i++)
                new_log_state[i] = (new_log_state[i] & ~bits) | (cur_log_state[i] & bits);
        } else {
            for (i = 0; i < G_N_ELEMENTS(new_log_state); i++) {
                if (i < domain_log_level)
                    new_log_state[i] &= ~bits;
                else {
                    new_log_state[i] |= bits;
                    if ((protect & bits) && i < LOGL_INFO)
                        new_log_state[i] &= ~protect;
                }
            }
        }
    }

    nm_clear_g_free(&gl_main.logging_domains_to_string);

    had_platform_debug = _nm_logging_enabled_lockfree(LOGL_DEBUG, LOGD_PLATFORM);

    G_LOCK(log);

    gl.mut.log_level = new_log_level;
    for (i = 0; i < G_N_ELEMENTS(new_log_state); i++)
        _nm_logging_enabled_state[i] = new_log_state[i];

    G_UNLOCK(log);

    if (had_platform_debug && !_nm_logging_enabled_lockfree(LOGL_DEBUG, LOGD_PLATFORM)) {
        /* when debug logging is enabled, platform will cache all access to
         * sysctl. When the user disables debug-logging, we want to clear that
         * cache right away.
         *
         * It's important that we call this without having a lock on "log", because
         * otherwise we might deadlock. */
        _nm_logging_clear_platform_logging_cache();
    }

    if (unrecognized)
        *bad_domains = g_string_free(unrecognized, FALSE);

    return TRUE;
}

const char *
nm_logging_level_to_string(void)
{
    NM_ASSERT_ON_MAIN_THREAD();

    return nm_log_level_desc[gl.imm.log_level].name;
}

const char *
nm_logging_all_levels_to_string(void)
{
    static GString *str;

    if (G_UNLIKELY(!str)) {
        int i;

        str = g_string_new(NULL);
        for (i = 0; i < G_N_ELEMENTS(nm_log_level_desc); i++) {
            if (str->len)
                g_string_append_c(str, ',');
            g_string_append(str, nm_log_level_desc[i].name);
        }
    }

    return str->str;
}

const char *
nm_logging_domains_to_string(void)
{
    NM_ASSERT_ON_MAIN_THREAD();

    if (G_UNLIKELY(!gl_main.logging_domains_to_string)) {
        gl_main.logging_domains_to_string =
            _domains_to_string(TRUE, gl.imm.log_level, _nm_logging_enabled_state);
    }

    return gl_main.logging_domains_to_string;
}

static char *
_domains_to_string(gboolean          include_level_override,
                   NMLogLevel        log_level,
                   const NMLogDomain log_state[static _LOGL_N_REAL])
{
    const LogDesc *diter;
    NMStrBuf       sbuf;
    int            i;

    /* We don't just return g_strdup() the logging domains that were set during
     * nm_logging_setup(), because we want to expand "DEFAULT" and "ALL".
     */

    sbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_40, FALSE);

    for (diter = &domain_desc[0]; diter->name; diter++) {
        /* If it's set for any lower level, it will also be set for LOGL_ERR */
        if (!(diter->num & log_state[LOGL_ERR]))
            continue;

        nm_str_buf_append_required_delimiter(&sbuf, ',');
        nm_str_buf_append(&sbuf, diter->name);

        if (!include_level_override)
            continue;

        /* Check if it's logging at a lower level than the default. */
        for (i = 0; i < log_level; i++) {
            if (diter->num & log_state[i]) {
                nm_str_buf_append_c(&sbuf, ':');
                nm_str_buf_append(&sbuf, nm_log_level_desc[i].name);
                break;
            }
        }
        /* Check if it's logging at a higher level than the default. */
        if (!(diter->num & log_state[log_level])) {
            for (i = log_level + 1; i < _LOGL_N_REAL; i++) {
                if (diter->num & log_state[i]) {
                    nm_str_buf_append_c(&sbuf, ':');
                    nm_str_buf_append(&sbuf, nm_log_level_desc[i].name);
                    break;
                }
            }
        }
    }
    return nm_str_buf_finalize(&sbuf, NULL);
}

static char _all_logging_domains_to_str[273];

const char *
nm_logging_all_domains_to_string(void)
{
    static const char *volatile str = NULL;
    const char *s;

again:
    s = g_atomic_pointer_get(&str);
    if (G_UNLIKELY(!s)) {
        static gsize   once = 0;
        const LogDesc *diter;
        gsize          buf_l;
        char          *buf_p;

        if (!g_once_init_enter(&once))
            goto again;

        buf_p = _all_logging_domains_to_str;
        buf_l = sizeof(_all_logging_domains_to_str);

        nm_strbuf_append_str(&buf_p, &buf_l, LOGD_DEFAULT_STRING);
        for (diter = &domain_desc[0]; diter->name; diter++) {
            nm_strbuf_append_c(&buf_p, &buf_l, ',');
            nm_strbuf_append_str(&buf_p, &buf_l, diter->name);
            if (diter->num == LOGD_DHCP6)
                nm_strbuf_append_str(&buf_p, &buf_l, "," LOGD_DHCP_STRING);
            else if (diter->num == LOGD_IP6)
                nm_strbuf_append_str(&buf_p, &buf_l, "," LOGD_IP_STRING);
        }
        nm_strbuf_append_str(&buf_p, &buf_l, LOGD_ALL_STRING);

        /* Did you modify the logging domains (or their names)? Adjust the size of
         * _all_logging_domains_to_str buffer above to have the exact size. */
        nm_assert(strlen(_all_logging_domains_to_str) == sizeof(_all_logging_domains_to_str) - 1);
        nm_assert(buf_l == 1);

        s = _all_logging_domains_to_str;
        g_atomic_pointer_set(&str, s);
        g_once_init_leave(&once, 1);
    }

    return s;
}

/**
 * nm_logging_get_level:
 * @domain: find the lowest enabled logging level for the
 *   given domain. If this is a set of multiple
 *   domains, the most verbose level will be returned.
 *
 * Returns: the lowest (most verbose) logging level for the
 *   give @domain, or %_LOGL_OFF if it is disabled.
 **/
NMLogLevel
nm_logging_get_level(NMLogDomain domain)
{
    NMLogLevel sl = _LOGL_OFF;

    G_STATIC_ASSERT(LOGL_TRACE == 0);
    while (sl > LOGL_TRACE && _nm_logging_enabled_lockfree(sl - 1, domain))
        sl--;
    return sl;
}

gboolean
_nm_logging_enabled_locking(NMLogLevel level, NMLogDomain domain)
{
    gboolean v;

    G_LOCK(log);
    v = _nm_logging_enabled_lockfree(level, domain);
    G_UNLOCK(log);
    return v;
}

gboolean
_nm_log_enabled_impl(gboolean mt_require_locking, NMLogLevel level, NMLogDomain domain)
{
    return nm_logging_enabled_mt(mt_require_locking, level, domain);
}

#if SYSTEMD_JOURNAL
static void
_iovec_set(struct iovec *iov, const void *str, gsize len)
{
    iov->iov_base = (void *) str;
    iov->iov_len  = len;
}

static void
_iovec_set_string(struct iovec *iov, const char *str)
{
    _iovec_set(iov, str, strlen(str));
}

#define _iovec_set_string_literal(iov, str) _iovec_set((iov), "" str "", NM_STRLEN(str))

_nm_printf(3, 4) static void _iovec_set_format(struct iovec *iov,
                                               char        **iov_free,
                                               const char   *format,
                                               ...)
{
    va_list ap;
    char   *str;

    va_start(ap, format);
    str = g_strdup_vprintf(format, ap);
    va_end(ap);

    _iovec_set_string(iov, str);
    *iov_free = str;
}

#define _iovec_set_format_a(iov, reserve_extra, format, ...)                   \
    G_STMT_START                                                               \
    {                                                                          \
        const gsize _size = (reserve_extra) + (NM_STRLEN(format) + 3);         \
        char *const _buf  = g_alloca(_size);                                   \
        int         _len;                                                      \
                                                                               \
        G_STATIC_ASSERT_EXPR((reserve_extra) + (NM_STRLEN(format) + 3) <= 96); \
                                                                               \
        _len = g_snprintf(_buf, _size, "" format "", ##__VA_ARGS__);           \
                                                                               \
        nm_assert(_len >= 0);                                                  \
        nm_assert(_len < _size);                                               \
        nm_assert(_len == strlen(_buf));                                       \
                                                                               \
        _iovec_set((iov), _buf, _len);                                         \
    }                                                                          \
    G_STMT_END

#define _iovec_set_format_str_a(iov, max_str_len, format, str_arg)  \
    G_STMT_START                                                    \
    {                                                               \
        const char *_str_arg = (str_arg);                           \
                                                                    \
        nm_assert(_str_arg &&strlen(_str_arg) < (max_str_len));     \
        _iovec_set_format_a((iov), (max_str_len), format, str_arg); \
    }                                                               \
    G_STMT_END

#endif

void
_nm_log_impl(const char *file,
             guint       line,
             const char *func,
             gboolean    mt_require_locking,
             NMLogLevel  level,
             NMLogDomain domain,
             int         error,
             const char *ifname,
             const char *conn_uuid,
             const char *fmt,
             ...)
{
    char               msg_stack[400];
    gs_free char      *msg_heap = NULL;
    const char        *msg;
    gint64             tv;
    int                errsv;
    const NMLogDomain *cur_log_state;
    NMLogDomain        cur_log_state_copy[_LOGL_N_REAL];
    Global             g_copy;
    const Global      *g;

    if (G_UNLIKELY(mt_require_locking)) {
        G_LOCK(log);
        /* we evaluate logging-enabled under lock. There is still a race that
         * we might log the message below *after* logging was disabled. That means,
         * when disabling logging, we might still log messages. */
        if (!_nm_logging_enabled_lockfree(level, domain)) {
            G_UNLOCK(log);
            return;
        }
        g_copy = gl.imm;
        memcpy(cur_log_state_copy, _nm_logging_enabled_state, sizeof(cur_log_state_copy));
        G_UNLOCK(log);
        g             = &g_copy;
        cur_log_state = cur_log_state_copy;
    } else {
        NM_ASSERT_ON_MAIN_THREAD();
        if (!_nm_logging_enabled_lockfree(level, domain))
            return;
        g             = &gl.imm;
        cur_log_state = _nm_logging_enabled_state;
    }

    (void) cur_log_state;

    errsv = errno;

    /* Make sure that %m maps to the specified error */
    if (error != 0) {
        if (error < 0)
            error = -error;
        errno = error;
    }

    msg = nm_vsprintf_buf_or_alloc(fmt, fmt, msg_stack, &msg_heap, NULL);

    /* We always print the level and the timestamp.
     *
     * Timestamps are very useful for understanding logfiles. While journalctl
     * might record the timestamp, it is not present in plain `journalctl` output.
     * Users who report a bug would simply send us the `journalctl` output and
     * requesting an output with timestamps (even if it's stored somewhere inside
     * journald) is not workable.
     *
     * We print the level, because this too, it's to quickly identify the severity
     * of a message.
     *
     * We also do this for all messages (for all levels), because then the logging
     * lines are formatted and aligned in a consistent way, which aids reading the
     * logs. */
#define MESSAGE_FMT "%s%-7s [%" G_GINT64_FORMAT ".%04d] %s"
#define MESSAGE_ARG(prefix, tv, msg)                                            \
    prefix, nm_log_level_desc[level].level_str, ((tv) / NM_UTILS_USEC_PER_SEC), \
        ((int) ((((tv) % NM_UTILS_USEC_PER_SEC)) / ((gint64) 100))), (msg)

    tv = g_get_real_time();

    if (g->debug_stderr)
        g_printerr(MESSAGE_FMT "\n", MESSAGE_ARG(g->prefix, tv, msg));

    switch (g->log_backend) {
#if SYSTEMD_JOURNAL
    case LOG_BACKEND_JOURNAL:
    {
        gint64         now, boottime;
        struct iovec   iov_data[15];
        struct iovec  *iov = iov_data;
        char          *iov_free_data[5];
        char         **iov_free = iov_free_data;
        const LogDesc *diter;
        NMLogDomain    dom_all;
        char  s_log_domains_buf[NM_STRLEN("NM_LOG_DOMAINS=") + sizeof(_all_logging_domains_to_str)];
        char *s_log_domains;
        gsize l_log_domains;

        now      = nm_utils_get_monotonic_timestamp_nsec();
        boottime = nm_utils_monotonic_timestamp_as_boottime(now, 1);

        _iovec_set_format_a(iov++, 30, "PRIORITY=%d", nm_log_level_desc[level].syslog_level);
        _iovec_set_format(iov++,
                          iov_free++,
                          "MESSAGE=" MESSAGE_FMT,
                          MESSAGE_ARG(g->prefix, tv, msg));
        _iovec_set_string(iov++, syslog_identifier_full(g->syslog_identifier));
        _iovec_set_format_a(iov++, 30, "SYSLOG_PID=%ld", (long) getpid());

        dom_all       = domain;
        s_log_domains = s_log_domains_buf;
        l_log_domains = sizeof(s_log_domains_buf);

        nm_strbuf_append_str(&s_log_domains, &l_log_domains, "NM_LOG_DOMAINS=");
        for (diter = &domain_desc[0]; dom_all != 0 && diter->name; diter++) {
            if (!NM_FLAGS_ANY(dom_all, diter->num))
                continue;
            if (dom_all != domain)
                nm_strbuf_append_c(&s_log_domains, &l_log_domains, ',');
            nm_strbuf_append_str(&s_log_domains, &l_log_domains, diter->name);
            dom_all &= ~diter->num;
        }
        nm_assert(l_log_domains > 0);
        _iovec_set(iov++, s_log_domains_buf, s_log_domains - s_log_domains_buf);

        G_STATIC_ASSERT_EXPR(LOG_FAC(LOG_DAEMON) == 3);
        _iovec_set_string_literal(iov++, "SYSLOG_FACILITY=3");
        _iovec_set_format_str_a(iov++, 15, "NM_LOG_LEVEL=%s", nm_log_level_desc[level].name);
        if (func)
            _iovec_set_format(iov++, iov_free++, "CODE_FUNC=%s", func);
        _iovec_set_format(iov++, iov_free++, "CODE_FILE=%s", file ?: "");
        _iovec_set_format_a(iov++, 20, "CODE_LINE=%u", line);
        _iovec_set_format_a(iov++,
                            60,
                            "TIMESTAMP_MONOTONIC=%lld.%06lld",
                            (long long) (now / NM_UTILS_NSEC_PER_SEC),
                            (long long) ((now % NM_UTILS_NSEC_PER_SEC) / 1000));
        _iovec_set_format_a(iov++,
                            60,
                            "TIMESTAMP_BOOTTIME=%lld.%06lld",
                            (long long) (boottime / NM_UTILS_NSEC_PER_SEC),
                            (long long) ((boottime % NM_UTILS_NSEC_PER_SEC) / 1000));
        if (error != 0)
            _iovec_set_format_a(iov++, 30, "ERRNO=%d", error);
        if (ifname)
            _iovec_set_format(iov++, iov_free++, "NM_DEVICE=%s", ifname);
        if (conn_uuid)
            _iovec_set_format(iov++, iov_free++, "NM_CONNECTION=%s", conn_uuid);

        nm_assert(iov <= &iov_data[G_N_ELEMENTS(iov_data)]);
        nm_assert(iov_free <= &iov_free_data[G_N_ELEMENTS(iov_free_data)]);

        sd_journal_sendv(iov_data, iov - iov_data);

        for (; --iov_free >= iov_free_data;)
            g_free(*iov_free);
    } break;
#endif
    case LOG_BACKEND_SYSLOG:
        syslog(nm_log_level_desc[level].syslog_level, MESSAGE_FMT, MESSAGE_ARG(g->prefix, tv, msg));
        break;
    default:
        g_log(syslog_identifier_domain(g->syslog_identifier),
              nm_log_level_desc[level].g_log_level,
              MESSAGE_FMT,
              MESSAGE_ARG(g->prefix, tv, msg));
        break;
    }

    errno = errsv;
}

/*****************************************************************************/

void
_nm_utils_monotonic_timestamp_initialized(const struct timespec *tp,
                                          gint64                 offset_sec,
                                          gboolean               is_boottime)
{
    NM_ASSERT_ON_MAIN_THREAD();

    if (_nm_logging_enabled_lockfree(LOGL_DEBUG, LOGD_CORE)) {
        time_t    now = time(NULL);
        struct tm tm;
        char      s[255];

        strftime(s, sizeof(s), "%Y-%m-%d %H:%M:%S", localtime_r(&now, &tm));
        nm_log_dbg(LOGD_CORE,
                   "monotonic timestamp started counting 1.%09ld seconds ago with "
                   "an offset of %lld.0 seconds to %s (local time is %s)",
                   tp->tv_nsec,
                   (long long) -offset_sec,
                   is_boottime ? "CLOCK_BOOTTIME" : "CLOCK_MONOTONIC",
                   s);
    }
}

/*****************************************************************************/

static void
nm_log_handler(const char *log_domain, GLogLevelFlags level, const char *message, gpointer ignored)
{
    int syslog_priority;

    switch (level & G_LOG_LEVEL_MASK) {
    case G_LOG_LEVEL_ERROR:
        syslog_priority = LOG_CRIT;
        break;
    case G_LOG_LEVEL_CRITICAL:
        syslog_priority = LOG_ERR;
        break;
    case G_LOG_LEVEL_WARNING:
        syslog_priority = LOG_WARNING;
        break;
    case G_LOG_LEVEL_MESSAGE:
        syslog_priority = LOG_NOTICE;
        break;
    case G_LOG_LEVEL_DEBUG:
        syslog_priority = LOG_DEBUG;
        break;
    case G_LOG_LEVEL_INFO:
    default:
        syslog_priority = LOG_INFO;
        break;
    }

    /* we don't need any locking here. The glib log handler gets only registered
     * once during nm_logging_init() and the global data is not modified afterwards. */
    nm_assert(gl.imm.init_done);

    if (gl.imm.debug_stderr)
        g_printerr("%s%s\n", gl.imm.prefix, message ?: "");

    switch (gl.imm.log_backend) {
#if SYSTEMD_JOURNAL
    case LOG_BACKEND_JOURNAL:
    {
        gint64 now, boottime;

        now      = nm_utils_get_monotonic_timestamp_nsec();
        boottime = nm_utils_monotonic_timestamp_as_boottime(now, 1);

        sd_journal_send("PRIORITY=%d",
                        syslog_priority,
                        "MESSAGE=%s%s",
                        gl.imm.prefix,
                        message ?: "",
                        syslog_identifier_full(gl.imm.syslog_identifier),
                        "SYSLOG_PID=%ld",
                        (long) getpid(),
                        "SYSLOG_FACILITY=3",
                        "GLIB_DOMAIN=%s",
                        log_domain ?: "",
                        "GLIB_LEVEL=%d",
                        (int) (level & G_LOG_LEVEL_MASK),
                        "TIMESTAMP_MONOTONIC=%lld.%06lld",
                        (long long) (now / NM_UTILS_NSEC_PER_SEC),
                        (long long) ((now % NM_UTILS_NSEC_PER_SEC) / 1000),
                        "TIMESTAMP_BOOTTIME=%lld.%06lld",
                        (long long) (boottime / NM_UTILS_NSEC_PER_SEC),
                        (long long) ((boottime % NM_UTILS_NSEC_PER_SEC) / 1000),
                        NULL);
    } break;
#endif
    default:
        syslog(syslog_priority, "%s%s", gl.imm.prefix, message ?: "");
        break;
    }
}

gboolean
nm_logging_syslog_enabled(void)
{
    NM_ASSERT_ON_MAIN_THREAD();

    return gl.imm.uses_syslog;
}

void
nm_logging_init_pre(const char *syslog_identifier, char *prefix_take)
{
    /* this function may be called zero or one times, and only
     * - on the main thread
     * - not after nm_logging_init(). */

    NM_ASSERT_ON_MAIN_THREAD();

    if (gl.imm.init_pre_done)
        g_return_if_reached();

    if (gl.imm.init_done)
        g_return_if_reached();

    if (!_syslog_identifier_valid_domain(syslog_identifier))
        g_return_if_reached();

    if (!prefix_take || !prefix_take[0])
        g_return_if_reached();

    G_LOCK(log);

    gl.mut.init_pre_done = TRUE;

    gl.mut.syslog_identifier = g_strdup_printf("SYSLOG_IDENTIFIER=%s", syslog_identifier);
    nm_assert(_syslog_identifier_assert(gl.imm.syslog_identifier));

    /* we pass the allocated string on and never free it. */
    gl.mut.prefix = prefix_take;

    G_UNLOCK(log);
}

void
nm_logging_init(const char *logging_backend, gboolean debug)
{
    gboolean   fetch_monotonic_timestamp = FALSE;
    gboolean   obsolete_debug_backend    = FALSE;
    LogBackend x_log_backend;

    /* this function may be called zero or one times, and only on the
     * main thread. */

    NM_ASSERT_ON_MAIN_THREAD();

    nm_assert(NM_IN_STRSET("" NM_CONFIG_DEFAULT_LOGGING_BACKEND,
                           NM_LOG_CONFIG_BACKEND_JOURNAL,
                           NM_LOG_CONFIG_BACKEND_SYSLOG));

    if (gl.imm.init_done)
        g_return_if_reached();

    if (!logging_backend)
        logging_backend = "" NM_CONFIG_DEFAULT_LOGGING_BACKEND;

    if (nm_streq(logging_backend, NM_LOG_CONFIG_BACKEND_DEBUG)) {
        /* "debug" was wrongly documented as a valid logging backend. It makes no sense however,
         * because printing to stderr only makes sense when not demonizing. Whether to daemonize
         * is only controlled via command line arguments (--no-daemon, --debug) and not via the
         * logging backend from configuration.
         *
         * Fall back to the default. */
        logging_backend        = "" NM_CONFIG_DEFAULT_LOGGING_BACKEND;
        obsolete_debug_backend = TRUE;
    }

    G_LOCK(log);

#if SYSTEMD_JOURNAL
    if (!nm_streq(logging_backend, NM_LOG_CONFIG_BACKEND_SYSLOG)) {
        x_log_backend = LOG_BACKEND_JOURNAL;

        /* We only log the monotonic-timestamp with structured logging (journal).
         * Only in this case, fetch the timestamp. */
        fetch_monotonic_timestamp = TRUE;
    } else
#endif
    {
        x_log_backend = LOG_BACKEND_SYSLOG;
        openlog(syslog_identifier_domain(gl.imm.syslog_identifier), LOG_PID, LOG_DAEMON);
    }

    gl.mut.init_done    = TRUE;
    gl.mut.log_backend  = x_log_backend;
    gl.mut.uses_syslog  = TRUE;
    gl.mut.debug_stderr = debug;

    g_log_set_handler(syslog_identifier_domain(gl.imm.syslog_identifier),
                      G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
                      nm_log_handler,
                      NULL);

    G_UNLOCK(log);

    if (fetch_monotonic_timestamp) {
        /* ensure we read a monotonic timestamp. Reading the timestamp the first
         * time causes a logging message. We don't want to do that during _nm_log_impl. */
        nm_utils_get_monotonic_timestamp_nsec();
    }

    if (obsolete_debug_backend)
        nm_log_dbg(LOGD_CORE,
                   "config: ignore deprecated logging backend 'debug', fallback to '%s'",
                   logging_backend);

    if (nm_streq(logging_backend, NM_LOG_CONFIG_BACKEND_SYSLOG)) {
        /* good */
    } else if (nm_streq(logging_backend, NM_LOG_CONFIG_BACKEND_JOURNAL)) {
#if !SYSTEMD_JOURNAL
        nm_log_warn(LOGD_CORE,
                    "config: logging backend 'journal' is not available, fallback to 'syslog'");
#endif
    } else {
        nm_log_warn(LOGD_CORE,
                    "config: invalid logging backend '%s', fallback to '%s'",
                    logging_backend,
#if SYSTEMD_JOURNAL
                    NM_LOG_CONFIG_BACKEND_JOURNAL
#else
                    NM_LOG_CONFIG_BACKEND_SYSLOG
#endif
        );
    }
}
