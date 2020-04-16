// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include "nm-utils/nm-vpn-plugin-macros.h"

#include "nm-dhcp-helper-api.h"

/*****************************************************************************/

#if NM_MORE_LOGGING
#define _NMLOG_ENABLED(level) TRUE
#else
#define _NMLOG_ENABLED(level) ((level) <= LOG_ERR)
#endif

#define _NMLOG(always_enabled, level, ...) \
	G_STMT_START { \
		if ((always_enabled) || _NMLOG_ENABLED (level)) { \
			GTimeVal _tv; \
			\
			g_get_current_time (&_tv); \
			g_print ("nm-dhcp-helper[%ld] %-7s [%ld.%04ld] " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
			         (long) getpid (), \
			         nm_utils_syslog_to_str (level), \
			         _tv.tv_sec, _tv.tv_usec / 100 \
			         _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
		} \
	} G_STMT_END

#define _LOGD(...) _NMLOG(TRUE,  LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(TRUE,  LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(TRUE,  LOG_WARNING, __VA_ARGS__)
#define _LOGE(...) _NMLOG(TRUE,  LOG_ERR,     __VA_ARGS__)

#define _LOGd(...) _NMLOG(FALSE, LOG_INFO,    __VA_ARGS__)
#define _LOGi(...) _NMLOG(FALSE, LOG_NOTICE,  __VA_ARGS__)
#define _LOGw(...) _NMLOG(FALSE, LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

static const char * ignore[] = {"PATH", "SHLVL", "_", "PWD", "dhc_dbus", NULL};

static GVariant *
build_signal_parameters (void)
{
	char **item;
	GVariantBuilder builder;

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	/* List environment and format for dbus dict */
	for (item = environ; *item; item++) {
		char *name, *val, **p;

		/* Split on the = */
		name = g_strdup (*item);
		val = strchr (name, '=');
		if (!val || val == name)
			goto next;
		*val++ = '\0';

		/* Ignore non-DCHP-related environment variables */
		for (p = (char **) ignore; *p; p++) {
			if (strncmp (name, *p, strlen (*p)) == 0)
				goto next;
		}

		/* Value passed as a byte array rather than a string, because there are
		 * no character encoding guarantees with DHCP, and D-Bus requires
		 * strings to be UTF-8.
		 *
		 * Note that we can't use g_variant_new_bytestring() here, because that
		 * includes the trailing '\0'. (??!?)
		 */
		g_variant_builder_add (&builder, "{sv}",
		                       name,
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                  val, strlen (val), 1));

	next:
		g_free (name);
	}

	return g_variant_ref_sink (g_variant_new ("(a{sv})", &builder));
}

static void
kill_pid (void)
{
	const char *pid_str;
	pid_t pid = 0;

	pid_str = getenv ("pid");
	if (pid_str)
		pid = strtol (pid_str, NULL, 10);
	if (pid) {
		_LOGI ("a fatal error occurred, kill dhclient instance with pid %d", pid);
		kill (pid, SIGTERM);
	}
}

int
main (int argc, char *argv[])
{
	gs_unref_object GDBusConnection *connection = NULL;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *parameters = NULL;
	gs_unref_variant GVariant *result = NULL;
	gboolean success = FALSE;
	guint try_count;
	gint64 time_start;
	gint64 time_end;

	/* Connecting to the unix socket can fail with EAGAIN if there are too
	 * many pending connections and the server can't accept them in time
	 * before reaching backlog capacity. Ideally the server should increase
	 * the backlog length, but GLib doesn't provide a way to change it for a
	 * GDBus server. Retry for up to 5 seconds in case of failure. */
	time_start = g_get_monotonic_time ();
	time_end = time_start + (5000 * 1000L);
	try_count = 0;

do_connect:
	try_count++;
	connection = g_dbus_connection_new_for_address_sync ("unix:path=" NMRUNDIR "/private-dhcp",
	                                                     G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
	                                                     NULL, NULL, &error);
	if (!connection) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_WOULD_BLOCK)) {
			gint64 time_remaining = time_end - g_get_monotonic_time ();
			gint64 interval;

			if (time_remaining > 0) {
				_LOGi ("failure to connect: %s (retry %u, waited %lld ms)",
				       error->message, try_count,
				       (long long) (time_end - time_remaining - time_start) / 1000);
				interval = NM_CLAMP ((gint64) (100L * (1L << NM_MIN (try_count, 31))),
				                     5000,
				                     100000);
				g_usleep (NM_MIN (interval, time_remaining));
				g_clear_error (&error);
				goto do_connect;
			}
		}

		g_dbus_error_strip_remote_error (error);
		_LOGE ("could not connect to NetworkManager D-Bus socket: %s",
		       error->message);
		goto out;
	}

	parameters = build_signal_parameters ();
	time_end = g_get_monotonic_time () + (200 * 1000L); /* retry for at most 200 milliseconds */
	try_count = 0;

do_notify:
	try_count++;
	result = g_dbus_connection_call_sync (connection,
	                                      NULL,
	                                      NM_DHCP_HELPER_SERVER_OBJECT_PATH,
	                                      NM_DHCP_HELPER_SERVER_INTERFACE_NAME,
	                                      NM_DHCP_HELPER_SERVER_METHOD_NOTIFY,
	                                      parameters,
	                                      NULL,
	                                      G_DBUS_CALL_FLAGS_NONE,
	                                      1000,
	                                      NULL,
	                                      &error);

	if (!result) {
		gs_free char *s_err = NULL;

		s_err = g_dbus_error_get_remote_error (error);
		if (NM_IN_STRSET (s_err, "org.freedesktop.DBus.Error.UnknownMethod")) {
			gint64 remaining_time = time_end - g_get_monotonic_time ();
			gint64 interval;

			/* I am not sure that a race can actually happen, as we register the object
			 * on the server side during GDBusServer:new-connection signal.
			 *
			 * However, there was also a race for subscribing to an event, so let's just
			 * do some retry. */
			if (remaining_time > 0) {
				_LOGi ("failure to call notify: %s (retry %u)", error->message, try_count);
				interval = NM_CLAMP ((gint64) (100L * (1L << NM_MIN (try_count, 31))),
				                     5000,
				                     25000);
				g_usleep (NM_MIN (interval, remaining_time));
				g_clear_error (&error);
				goto do_notify;
			}
		}
		_LOGW ("failure to call notify: %s (try signal via Event)", error->message);
		g_clear_error (&error);

		/* for backward compatibility, try to emit the signal. There is no stable
		 * API between the dhcp-helper and NetworkManager. However, while upgrading
		 * the NetworkManager package, a newer helper might want to notify an
		 * older server, which still uses the "Event". */
		if (!g_dbus_connection_emit_signal (connection,
		                                    NULL,
		                                    "/",
		                                    NM_DHCP_CLIENT_DBUS_IFACE,
		                                    "Event",
		                                    parameters,
		                                    &error)) {
			g_dbus_error_strip_remote_error (error);
			_LOGE ("could not send DHCP Event signal: %s", error->message);
			goto out;
		}
		/* We were able to send the asynchronous Event. Consider that a success. */
		success = TRUE;
	} else
		success = TRUE;

	if (!g_dbus_connection_flush_sync (connection, NULL, &error)) {
		g_dbus_error_strip_remote_error (error);
		_LOGE ("could not flush D-Bus connection: %s", error->message);
		success = FALSE;
		goto out;
	}

out:
	if (!success)
		kill_pid ();
	return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

