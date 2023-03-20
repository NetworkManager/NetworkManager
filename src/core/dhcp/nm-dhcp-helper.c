/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#include "libnm-glib-aux/nm-default-glib.h"

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include "libnm-glib-aux/nm-logging-syslog.h"

#include "nm-dhcp-helper-api.h"

/*****************************************************************************/

#if NM_MORE_LOGGING
#define _NMLOG_ENABLED(level) TRUE
#else
#define _NMLOG_ENABLED(level) ((level) <= LOG_ERR)
#endif

#define _NMLOG(always_enabled, level, ...)                                     \
    G_STMT_START                                                               \
    {                                                                          \
        if ((always_enabled) || _NMLOG_ENABLED(level)) {                       \
            gint64 _tv;                                                        \
                                                                               \
            _tv = g_get_real_time();                                           \
            g_print("nm-dhcp-helper[%ld] %-7s [%" G_GINT64_FORMAT              \
                    ".%04d] " _NM_UTILS_MACRO_FIRST(__VA_ARGS__) "\n",         \
                    (long) getpid(),                                           \
                    nm_utils_syslog_to_str(level),                             \
                    (_tv / NM_UTILS_USEC_PER_SEC),                             \
                    ((int) ((_tv % NM_UTILS_USEC_PER_SEC) / (((gint64) 100)))) \
                        _NM_UTILS_MACRO_REST(__VA_ARGS__));                    \
        }                                                                      \
    }                                                                          \
    G_STMT_END

#define _LOGD(...) _NMLOG(TRUE, LOG_INFO, __VA_ARGS__)
#define _LOGI(...) _NMLOG(TRUE, LOG_NOTICE, __VA_ARGS__)
#define _LOGW(...) _NMLOG(TRUE, LOG_WARNING, __VA_ARGS__)
#define _LOGE(...) _NMLOG(TRUE, LOG_ERR, __VA_ARGS__)

#define _LOGd(...) _NMLOG(FALSE, LOG_INFO, __VA_ARGS__)
#define _LOGi(...) _NMLOG(FALSE, LOG_NOTICE, __VA_ARGS__)
#define _LOGw(...) _NMLOG(FALSE, LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

static GVariant *
build_signal_parameters(void)
{
    const char *const *environ_iter;
    GVariantBuilder    builder;

    g_variant_builder_init(&builder, G_VARIANT_TYPE_VARDICT);

    /* List environment and format for dbus dict */
    for (environ_iter = (const char *const *) environ; *environ_iter; environ_iter++) {
        static const char *const ignore_with_prefix_list[] =
            {"PATH", "SHLVL", "_", "PWD", "dhc_dbus", NULL};
        const char        *item = *environ_iter;
        gs_free char      *name = NULL;
        const char        *val;
        const char *const *p;

        val = strchr(item, '=');
        if (!val || item == val)
            continue;

        name = g_strndup(item, val - item);
        val += 1;

        /* Ignore non-DHCP-related environment variables */
        for (p = ignore_with_prefix_list; *p; p++) {
            if (strncmp(name, *p, strlen(*p)) == 0)
                goto next;
        }

        if (!g_utf8_validate(name, -1, NULL))
            continue;

        /* Value passed as a byte array rather than a string, because there are
         * no character encoding guarantees with DHCP, and D-Bus requires
         * strings to be UTF-8.
         *
         * Note that we can't use g_variant_new_bytestring() here, because that
         * includes the trailing '\0'. (??!?)
         */
        g_variant_builder_add(&builder,
                              "{sv}",
                              name,
                              nm_g_variant_new_ay((const guint8 *) val, strlen(val)));

next:;
    }

    return g_variant_ref_sink(g_variant_new("(a{sv})", &builder));
}

int
main(int argc, char *argv[])
{
    gs_unref_object GDBusConnection *connection  = NULL;
    gs_free_error GError            *error       = NULL;
    gs_free_error GError            *error_flush = NULL;
    gs_unref_variant GVariant       *parameters  = NULL;
    gs_unref_variant GVariant       *result      = NULL;
    gs_free char                    *s_err       = NULL;
    gboolean                         success;
    guint                            try_count;
    gint64                           time_start;
    gint64                           time_end;
    gint64                           remaining_time;
    gboolean                         IS_IPv4;
    const char                      *reason;

    /* Connecting to the unix socket can fail with EAGAIN if there are too
     * many pending connections and the server can't accept them in time
     * before reaching backlog capacity. Ideally the server should increase
     * the backlog length, but GLib doesn't provide a way to change it for a
     * GDBus server. Retry for up to 5 seconds in case of failure. */
    time_start = g_get_monotonic_time();
    time_end   = time_start + (5000 * 1000L);
    try_count  = 0;

    reason = getenv("reason");

    _LOGi("nm-dhcp-helper: event called: %s", reason);

    IS_IPv4 = !NM_IN_STRSET(reason,
                            "PREINIT6",
                            "BOUND6",
                            "RENEW6",
                            "REBIND6",
                            "DEPREF6",
                            "EXPIRE6",
                            "RELEASE6",
                            "STOP6");

do_connect:
    try_count++;
    connection =
        g_dbus_connection_new_for_address_sync("unix:path=" NMRUNDIR "/private-dhcp",
                                               G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
                                               NULL,
                                               NULL,
                                               &error);
    if (!connection) {
        if (g_error_matches(error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
            remaining_time = time_end - g_get_monotonic_time();
            if (remaining_time > 0) {
                gint64 interval;

                _LOGi("failure to connect: %s (retry %u, waited %lld ms)",
                      error->message,
                      try_count,
                      (long long) (time_end - remaining_time - time_start) / 1000);
                interval = NM_CLAMP((gint64) (100L * (1L << NM_MIN(try_count, 31))), 5000, 100000);
                g_usleep(NM_MIN(interval, remaining_time));
                g_clear_error(&error);
                goto do_connect;
            }
        }

        g_dbus_error_strip_remote_error(error);
        _LOGE("could not connect to NetworkManager D-Bus socket: %s", error->message);
        success = FALSE;
        goto out;
    }

    parameters = build_signal_parameters();
    time_end   = g_get_monotonic_time() + (200 * 1000L); /* retry for at most 200 milliseconds */
    try_count  = 0;

do_notify:
    try_count++;
    result = g_dbus_connection_call_sync(connection,
                                         NULL,
                                         NM_DHCP_HELPER_SERVER_OBJECT_PATH,
                                         NM_DHCP_HELPER_SERVER_INTERFACE_NAME,
                                         NM_DHCP_HELPER_SERVER_METHOD_NOTIFY,
                                         parameters,
                                         NULL,
                                         G_DBUS_CALL_FLAGS_NONE,
                                         60000,
                                         NULL,
                                         &error);

    if (result) {
        success = TRUE;
        goto out;
    }

    s_err = g_dbus_error_get_remote_error(error);

    if (NM_IN_STRSET(s_err, "org.freedesktop.NetworkManager.Device.Failed")) {
        _LOGi("notify failed with reason: %s", error->message);
        success = FALSE;
        goto out;
    }

    if (!NM_IN_STRSET(s_err, "org.freedesktop.DBus.Error.UnknownMethod")) {
        /* Some unexpected error. We treat that as a failure. In particular,
         * the daemon will fail the request if ACD fails. This causes nm-dhcp-helper
         * to fail, which in turn causes dhclient to send a DECLINE. */
        _LOGW("failure to call notify: %s (try signal via Event)", error->message);
        success = FALSE;
        goto out;
    }

    /* I am not sure that a race can actually happen, as we register the object
     * on the server side during GDBusServer:new-connection signal.
     *
     * However, there was also a race for subscribing to an event, so let's just
     * do some retry. */
    remaining_time = time_end - g_get_monotonic_time();
    if (remaining_time > 0) {
        gint64 interval;

        _LOGi("failure to call notify: %s (retry %u)", error->message, try_count);
        interval = NM_CLAMP((gint64) (100L * (1L << NM_MIN(try_count, 31))), 5000, 25000);
        g_usleep(NM_MIN(interval, remaining_time));
        g_clear_error(&error);
        goto do_notify;
    }

    /* for backward compatibility, try to emit the signal. There is no stable
     * API between the dhcp-helper and NetworkManager. However, while upgrading
     * the NetworkManager package, a newer helper might want to notify an
     * older server, which still uses the "Event". */

    _LOGW("failure to call notify: %s (try signal via Event)", error->message);
    g_clear_error(&error);

    if (g_dbus_connection_emit_signal(connection,
                                      NULL,
                                      "/",
                                      NM_DHCP_CLIENT_DBUS_IFACE,
                                      "Event",
                                      parameters,
                                      &error)) {
        /* We were able to send the asynchronous Event. Consider that a success. */
        success = TRUE;
        goto out;
    }

    g_dbus_error_strip_remote_error(error);
    _LOGE("could not send DHCP Event signal: %s", error->message);
    success = FALSE;

out:
    if (connection && !g_dbus_connection_flush_sync(connection, NULL, &error_flush)) {
        _LOGE("could not flush D-Bus connection: %s", error_flush->message);
        /* if we considered this a success so far, don't fail because of this. */
    }

    _LOGi("success: %s", success ? "YES" : "NO");
    /* The error code to send a decline depends on the address family */
    return success ? EXIT_SUCCESS : (IS_IPv4 ? 1 : 3);
}
