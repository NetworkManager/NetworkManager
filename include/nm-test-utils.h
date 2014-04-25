/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_TEST_UTILS_H__
#define __NM_TEST_UTILS_H__


#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <glib.h>
#include <glib-object.h>
#include <string.h>
#include <errno.h>

#include "nm-utils.h"
#include "nm-glib-compat.h"


struct __nmtst_internal
{
	GRand *rand0;
	guint32 rand_seed;
	GRand *rand;
	gboolean is_debug;
	gboolean assert_logging;
	gboolean no_expect_message;
	char *sudo_cmd;
	char **orig_argv;
};

extern struct __nmtst_internal __nmtst_internal;

#define NMTST_DEFINE() \
	struct __nmtst_internal __nmtst_internal = { 0 };


inline static gboolean
nmtst_initialized (void)
{
	return !!__nmtst_internal.rand0;
}

#define __NMTST_LOG(cmd, fmt, ...) \
	G_STMT_START { \
		g_assert (nmtst_initialized ()); \
		if (!__nmtst_internal.assert_logging || __nmtst_internal.no_expect_message) { \
			cmd (fmt, __VA_ARGS__); \
		} else { \
			printf (fmt "\n", __VA_ARGS__); \
		} \
	} G_STMT_END

/* split the string inplace at specific delimiters, allowing escaping with '\\'.
 * Returns a zero terminated array of pointers into @str.
 *
 * The caller must g_free() the returned argv array.
 **/
inline static char **
nmtst_str_split (char *str, const char *delimiters)
{
	const char *d;
	GArray *result = g_array_sized_new (TRUE, FALSE, sizeof (char *), 3);

	g_assert (str);
	g_assert (delimiters && !strchr (delimiters, '\\'));

	while (*str) {
		gsize i = 0, j = 0;

		while (TRUE) {
			char c = str[i];

			if (c == '\0') {
				str[j++] = 0;
				break;
			} else if (c == '\\') {
				str[j++] = str[++i];
				if (!str[i])
					break;
			} else {
				for (d = delimiters; *d; d++) {
					if (c == *d) {
						str[j++] = 0;
						i++;
						goto BREAK_INNER_LOOPS;
					}
				}
				str[j++] = c;
			}
			i++;
		}

BREAK_INNER_LOOPS:
		g_array_append_val (result, str);
		str = &str[i];
	}

	return (char **) g_array_free (result, FALSE);
}


/* free instances allocated by nmtst (especially nmtst_init()) on shutdown
 * to release memory. After nmtst_free(), the test is uninitialized again. */
inline static void
nmtst_free (void)
{
	if (!nmtst_initialized ())
		return;

	g_rand_free (__nmtst_internal.rand0);
	if (__nmtst_internal.rand)
		g_rand_free (__nmtst_internal.rand);
	g_free (__nmtst_internal.sudo_cmd);
	g_strfreev (__nmtst_internal.orig_argv);

	memset (&__nmtst_internal, 0, sizeof (__nmtst_internal));
}

inline static void
__nmtst_init (int *argc, char ***argv, gboolean assert_logging, const char *log_level, const char *log_domains)
{
	static gsize atexit_registered = 0;
	GError *error = NULL;
	const char *nmtst_debug;
	gboolean is_debug = FALSE;
	char *c_log_level = NULL, *c_log_domains = NULL;
	char *sudo_cmd = NULL;
	GArray *debug_messages = g_array_new (TRUE, FALSE, sizeof (char *));
	int i;
	gboolean no_expect_message = FALSE;

	g_assert (!nmtst_initialized ());

	g_assert (!((!!argc) ^ (!!argv)));
	g_assert (!argc || (g_strv_length (*argv) == *argc));
	g_assert (!assert_logging || (!log_level && !log_domains));

	if (argc)
		__nmtst_internal.orig_argv = g_strdupv (*argv);

	if (argc && !g_test_initialized ()) {
		/* g_test_init() is a variadic function, so we cannot pass it
		 * (variadic) arguments. If you need to pass additional parameters,
		 * call nmtst_init() with argc==NULL and call g_test_init() yourself. */

		/* g_test_init() sets g_log_set_always_fatal() for G_LOG_LEVEL_WARNING
		 * and G_LOG_LEVEL_CRITICAL. So, beware that the test will fail if you
		 * have any WARN or ERR log messages -- unless you g_test_expect_message(). */
		g_test_init (argc, argv, NULL);
	}

	__nmtst_internal.assert_logging = !!assert_logging;

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	is_debug = g_test_verbose ();

	nmtst_debug = g_getenv ("NMTST_DEBUG");
	if (nmtst_debug) {
		char **d_argv, **i_argv, *nmtst_debug_copy;

		/* By setting then NMTST_DEBUG variable, @is_debug is set automatically.
		 * This can be reverted with no-debug (on command line or environment variable). */
		is_debug = TRUE;

		nmtst_debug_copy = g_strdup (nmtst_debug);
		d_argv = nmtst_str_split (nmtst_debug_copy, ",; \t\r\n");

		for (i_argv = d_argv; *i_argv; i_argv++) {
			const char *debug = *i_argv;

			if (!g_ascii_strcasecmp (debug, "debug"))
				is_debug = TRUE;
			else if (!g_ascii_strcasecmp (debug, "no-debug")) {
				/* when specifying the NMTST_DEBUG variable, we set is_debug to true. Use this flag to disable this
				 * (e.g. for only setting the log-level, but not is_debug). */
				is_debug = FALSE;
			} else if (!g_ascii_strncasecmp (debug, "log-level=", strlen ("log-level="))) {
				g_free (c_log_level);
				log_level = c_log_level = g_strdup (&debug[strlen ("log-level=")]);
			} else if (!g_ascii_strncasecmp (debug, "log-domains=", strlen ("log-domains="))) {
				g_free (c_log_domains);
				log_domains = c_log_domains = g_strdup (&debug[strlen ("log-domains=")]);
			} else if (!g_ascii_strncasecmp (debug, "sudo-cmd=", strlen ("sudo-cmd="))) {
				g_free (sudo_cmd);
				sudo_cmd = g_strdup (&debug[strlen ("sudo-cmd=")]);
			} else if (!g_ascii_strcasecmp (debug, "no-expect-message")) {
				no_expect_message = TRUE;
			} else {
				char *msg = g_strdup_printf (">>> nmtst: ignore unrecognized NMTST_DEBUG option \"%s\"", debug);

				g_array_append_val (debug_messages, msg);
			}
		}

		g_free (d_argv);
		g_free (nmtst_debug_copy);
	}

	if (argv && *argv) {
		 char **a = *argv;

		 for (; *a; a++) {
			if (!g_ascii_strcasecmp (*a, "--debug"))
				is_debug = TRUE;
			else if (!g_ascii_strcasecmp (*a, "--no-debug"))
				is_debug = FALSE;
		 }
	}

	__nmtst_internal.is_debug = is_debug;
	__nmtst_internal.rand0 = g_rand_new_with_seed (0);
	__nmtst_internal.sudo_cmd = sudo_cmd;
	__nmtst_internal.no_expect_message = no_expect_message;

	if (!log_level && log_domains) {
		/* if the log level is not specified (but the domain is), we assume
		 * the caller wants to set it depending on is_debug */
		log_level = is_debug ? "DEBUG" : "WARN";
	}

	if (!__nmtst_internal.assert_logging) {
		gboolean success = TRUE;
#ifdef NM_LOGGING_H
		success = nm_logging_setup (log_level, log_domains, NULL, NULL);
#endif
		g_assert (success);
	} else if (__nmtst_internal.no_expect_message) {
		/* We have a test that would be assert_logging, but the user specified no_expect_message.
		 * This transforms g_test_expect_message() into a NOP, but we also have to relax
		 * g_log_set_always_fatal(), which was set by g_test_init(). */
		g_log_set_always_fatal (G_LOG_FATAL_MASK);
	} else {
#if GLIB_CHECK_VERSION(2,34,0)
		/* We were called not to set logging levels. This means, that the user
		 * expects to assert against (all) messages. Any uncought message is fatal. */
		g_log_set_always_fatal (G_LOG_LEVEL_MASK);
#else
		/* g_test_expect_message() is a NOP, so allow any messages */
		g_log_set_always_fatal (G_LOG_FATAL_MASK);
#endif
	}

	if ((!__nmtst_internal.assert_logging || (__nmtst_internal.assert_logging && __nmtst_internal.no_expect_message)) &&
	    (is_debug || (log_level && !g_ascii_strcasecmp (log_level, "DEBUG"))) &&
	    !g_getenv ("G_MESSAGES_DEBUG"))
	{
		/* if we are @is_debug or @log_level=="DEBUG" and
		 * G_MESSAGES_DEBUG is unset, we set G_MESSAGES_DEBUG=all.
		 * To disable this default behaviour, set G_MESSAGES_DEBUG='' */

		/* Note that g_setenv is not thread safe, but you should anyway call
		 * nmtst_init() at the very start. */
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);
	}

	if (!nm_utils_init (&error))
		g_error ("failed to initialize libnm-util: %s", error->message);
	g_assert (!error);

	/* Delay messages until we setup logging. */
	for (i = 0; i < debug_messages->len; i++)
		__NMTST_LOG (g_message, "%s", g_array_index (debug_messages, const char *, i));

	g_strfreev ((char **) g_array_free (debug_messages, FALSE));
	g_free (c_log_level);
	g_free (c_log_domains);

	if (g_once_init_enter (&atexit_registered)) {
		atexit (nmtst_free);
		g_once_init_leave (&atexit_registered, 1);
	}
}

#ifdef NM_LOGGING_H
inline static void
nmtst_init_with_logging (int *argc, char ***argv, const char *log_level, const char *log_domains)
{
	__nmtst_init (argc, argv, FALSE, log_level, log_domains);
}
inline static void
nmtst_init_assert_logging (int *argc, char ***argv)
{
	__nmtst_init (argc, argv, TRUE, NULL, NULL);
}
#else
inline static void
nmtst_init (int *argc, char ***argv, gboolean assert_logging)
{
	__nmtst_init (argc, argv, assert_logging, NULL, NULL);
}
#endif

inline static gboolean
nmtst_is_debug (void)
{
	g_assert (nmtst_initialized ());
	return __nmtst_internal.is_debug;
}

#if GLIB_CHECK_VERSION(2,34,0)
#undef g_test_expect_message
#define g_test_expect_message(...) \
	G_STMT_START { \
		g_assert (nmtst_initialized ()); \
		if (__nmtst_internal.assert_logging && __nmtst_internal.no_expect_message) { \
			g_debug ("nmtst: swallow g_test_expect_message %s", G_STRINGIFY ((__VA_ARGS__))); \
		} else { \
			G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
			g_test_expect_message (__VA_ARGS__); \
			G_GNUC_END_IGNORE_DEPRECATIONS \
		} \
	} G_STMT_END
#endif

inline static GRand *
nmtst_get_rand0 ()
{
	g_assert (nmtst_initialized ());
	return __nmtst_internal.rand0;
}

inline static GRand *
nmtst_get_rand ()
{
	g_assert (nmtst_initialized ());

	if (G_UNLIKELY (!__nmtst_internal.rand)) {
		guint32 seed;
		const char *str;

		if ((str = g_getenv ("NMTST_SEED_RAND"))) {
			gchar *s;
			gint64 i;

			i = g_ascii_strtoll (str, &s, 0);
			g_assert (s[0] == '\0' && i >= 0 && i < G_MAXINT32);

			seed = i;
			__nmtst_internal.rand = g_rand_new_with_seed (seed);
		} else {
			__nmtst_internal.rand = g_rand_new ();

			seed = g_rand_int (__nmtst_internal.rand);
			g_rand_set_seed (__nmtst_internal.rand, seed);
		}
		__nmtst_internal.rand_seed = seed;

		__NMTST_LOG (g_message, ">> initialize nmtst_get_rand() with seed=%u", seed);
	}
	return __nmtst_internal.rand;
}

inline static const char *
nmtst_get_sudo_cmd (void)
{
	g_assert (nmtst_initialized ());
	return __nmtst_internal.sudo_cmd;
}

inline static void
nmtst_reexec_sudo (void)
{
	char *str;
	char **argv;
	int i;
	int errsv;

	g_assert (nmtst_initialized ());
	g_assert (__nmtst_internal.orig_argv);

	if (!__nmtst_internal.sudo_cmd)
		return;

	str = g_strjoinv (" ", __nmtst_internal.orig_argv);
	__NMTST_LOG (g_message, ">> exec %s %s", __nmtst_internal.sudo_cmd, str);

	argv = g_new0 (char *, 1 + g_strv_length (__nmtst_internal.orig_argv) + 1);
	argv[0] = __nmtst_internal.sudo_cmd;
	for (i = 0; __nmtst_internal.orig_argv[i]; i++)
		argv[i+1] = __nmtst_internal.orig_argv[i];

	execvp (__nmtst_internal.sudo_cmd, argv);

	errsv = errno;
	g_error (">> exec %s failed: %d - %s", __nmtst_internal.sudo_cmd, errsv, strerror (errsv));
}

#define __define_nmtst_static(NUM,SIZE) \
inline static const char * \
nmtst_static_##SIZE##_##NUM (const char *str) \
{ \
	gsize l; \
	static char buf[SIZE]; \
\
	if (!str) \
		return NULL; \
	l = g_strlcpy (buf, str, sizeof (buf)); \
	g_assert (l < sizeof (buf)); \
	return buf; \
}
__define_nmtst_static(01, 1024)
__define_nmtst_static(02, 1024)
__define_nmtst_static(03, 1024)
#undef __define_nmtst_static


#define NMTST_SWAP(x,y) \
	G_STMT_START { \
		char __nmtst_swap_temp[sizeof(x) == sizeof(y) ? (signed) sizeof(x) : -1]; \
		memcpy(__nmtst_swap_temp, &y, sizeof(x)); \
		memcpy(&y,                &x, sizeof(x)); \
		memcpy(&x, __nmtst_swap_temp, sizeof(x)); \
	} G_STMT_END

inline static guint32
nmtst_inet4_from_string (const char *str)
{
	guint32 addr;
	int success;

	if (!str)
		return 0;

	success = inet_pton (AF_INET, str, &addr);

	g_assert (success == 1);

	return addr;
}

inline static const struct in6_addr *
nmtst_inet6_from_string (const char *str)
{
	static struct in6_addr addr;
	int success;

	if (!str)
		addr = in6addr_any;
	else {
		success = inet_pton (AF_INET6, str, &addr);
		g_assert (success == 1);
	}

	return &addr;
}

inline static void
FAIL(const char *test_name, const char *fmt, ...)
{
	va_list args;
	char buf[500];

	g_snprintf (buf, 500, "FAIL: (%s) %s\n", test_name, fmt);

	va_start (args, fmt);
	vfprintf (stderr, buf, args);
	va_end (args);
	_exit (1);
}

#define ASSERT(x, test_name, fmt, ...) \
	if (!(x)) { \
		FAIL (test_name, fmt, ## __VA_ARGS__); \
	}


#define nmtst_spawn_sync(working_directory, standard_out, standard_err, assert_exit_status, ...) \
	__nmtst_spawn_sync (working_directory, standard_out, standard_err, assert_exit_status, ##__VA_ARGS__, NULL)
inline static gint
__nmtst_spawn_sync (const char *working_directory, char **standard_out, char **standard_err, int assert_exit_status, ...) G_GNUC_NULL_TERMINATED;
inline static gint
__nmtst_spawn_sync (const char *working_directory, char **standard_out, char **standard_err, int assert_exit_status, ...)
{
	gint exit_status = 0;
	GError *error = NULL;
	char *arg;
	va_list va_args;
	GPtrArray *argv = g_ptr_array_new ();
	gboolean success;

	va_start (va_args, assert_exit_status);
	while ((arg = va_arg (va_args, char *)))
		g_ptr_array_add (argv, arg);
	va_end (va_args);

	g_assert (argv->len >= 1);
	g_ptr_array_add (argv, NULL);

	success = g_spawn_sync (working_directory,
	                        (char**) argv->pdata,
	                        NULL,
	                        0 /*G_SPAWN_DEFAULT*/,
	                        NULL,
	                        NULL,
	                        standard_out,
	                        standard_err,
	                        &exit_status,
	                        &error);
	if (!success)
		g_error ("nmtst_spawn_sync(%s): %s", ((char **) argv->pdata)[0], error->message);
	g_assert (!error);

	g_assert (!standard_out || *standard_out);
	g_assert (!standard_err || *standard_err);

	if (assert_exit_status != -1) {
		/* exit status is a guint8 on success. Set @assert_exit_status to -1
		 * not to check for the exit status. */
		g_assert (WIFEXITED (exit_status));
		g_assert_cmpint (WEXITSTATUS (exit_status), ==, assert_exit_status);
	}

	g_ptr_array_free (argv, TRUE);
	return exit_status;
}

/*******************************************************************************/

#ifdef NM_PLATFORM_H

inline static NMPlatformIP6Address *
nmtst_platform_ip6_address (const char *address, const char *peer_address, guint plen)
{
	static NMPlatformIP6Address addr;

	memset (&addr, 0, sizeof (addr));
	addr.address = *nmtst_inet6_from_string (address);
	addr.peer_address = *nmtst_inet6_from_string (peer_address);
	addr.plen = plen;

	return &addr;
}

inline static NMPlatformIP6Address *
nmtst_platform_ip6_address_full (const char *address, const char *peer_address, guint plen,
                                 int ifindex, NMPlatformSource source, guint32 timestamp,
                                 guint32 lifetime, guint32 preferred, guint flags)
{
	NMPlatformIP6Address *addr = nmtst_platform_ip6_address (address, peer_address, plen);

	addr->ifindex = ifindex;
	addr->source = source;
	addr->timestamp = timestamp;
	addr->lifetime = lifetime;
	addr->preferred = preferred;
	addr->flags = flags;

	return addr;
}

inline static NMPlatformIP6Route *
nmtst_platform_ip6_route (const char *network, guint plen, const char *gateway)
{
	static NMPlatformIP6Route route;

	memset (&route, 0, sizeof (route));
	route.network = *nmtst_inet6_from_string (network);
	route.plen = plen;
	route.gateway = *nmtst_inet6_from_string (gateway);

	return &route;
}

inline static NMPlatformIP6Route *
nmtst_platform_ip6_route_full (const char *network, guint plen, const char *gateway,
                               int ifindex, NMPlatformSource source,
                               guint metric, guint mss)
{
	NMPlatformIP6Route *route = nmtst_platform_ip6_route (network, plen, gateway);

	route->ifindex = ifindex;
	route->source = source;
	route->metric = metric;
	route->mss = mss;

	return route;
}

inline static void
nmtst_platform_ip4_routes_equal (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b, gsize len)
{
	gsize i;

	g_assert (a);
	g_assert (b);

	for (i = 0; i < len; i++) {
		if (nm_platform_ip4_route_cmp (&a[i], &b[i]) != 0) {
			g_error ("Error comparing IPv4 route[%lu]: %s vs %s", (long unsigned) i,
			         nmtst_static_1024_01 (nm_platform_ip4_route_to_string (&a[i])),
			         nmtst_static_1024_02 (nm_platform_ip4_route_to_string (&b[i])));
			g_assert_not_reached ();
		}

		/* also check with memcmp, though this might fail for valid programs (due to field alignment) */
		g_assert_cmpint (memcmp (&a[i], &b[i], sizeof (a[i])), ==, 0);
	}
}

inline static void
nmtst_platform_ip6_routes_equal (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b, gsize len)
{
	gsize i;

	g_assert (a);
	g_assert (b);

	for (i = 0; i < len; i++) {
		if (nm_platform_ip6_route_cmp (&a[i], &b[i]) != 0) {
			g_error ("Error comparing IPv6 route[%lu]: %s vs %s", (long unsigned) i,
			         nmtst_static_1024_01 (nm_platform_ip6_route_to_string (&a[i])),
			         nmtst_static_1024_02 (nm_platform_ip6_route_to_string (&b[i])));
			g_assert_not_reached ();
		}

		/* also check with memcmp, though this might fail for valid programs (due to field alignment) */
		g_assert_cmpint (memcmp (&a[i], &b[i], sizeof (a[i])), ==, 0);
	}
}

#endif


#ifdef NM_IP4_CONFIG_H

inline static NMIP4Config *
nmtst_ip4_config_clone (NMIP4Config *config)
{
	NMIP4Config *copy = nm_ip4_config_new ();

	g_assert (copy);
	g_assert (config);
	nm_ip4_config_replace (copy, config, NULL);
	return copy;
}

#endif


#ifdef NM_IP6_CONFIG_H

inline static NMIP6Config *
nmtst_ip6_config_clone (NMIP6Config *config)
{
	NMIP6Config *copy = nm_ip6_config_new ();

	g_assert (copy);
	g_assert (config);
	nm_ip6_config_replace (copy, config, NULL);
	return copy;
}

#endif


#endif /* __NM_TEST_UTILS_H__ */

