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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NM_TEST_UTILS_H__
#define __NM_TEST_UTILS_H__

/*******************************************************************************
 * HOWTO run tests.
 *
 * Our tests (make check) include this header-only file nm-test-utils.h.
 *
 * Logging:
 *   In tests, nm-logging redirects to glib logging. By default, glib suppresses all debug
 *   messages unless you set G_MESSAGES_DEBUG. To enable debug logging, you can explicitly set
 *   G_MESSAGES_DEBUG. Otherwise, nm-test will set G_MESSAGES_DEBUG=all in debug mode (see below).
 *   For nm-logging, you can configure the log-level and domains via NMTST_DEBUG environment
 *   variable.
 *
 * Assert-logging:
 *   Some tests assert against logged messages (g_test_expect_message()).
 *   By specifying no-expect-message in NMTST_DEBUG, you can disable assert logging
 *   and g_test_assert_expected_messages() will not fail.
 *
 * NMTST_SEED_RAND environment variable:
 *   Tests that use random numbers from nmtst_get_rand() get seeded randomly at each start.
 *   You can specify the seed by setting NMTST_SEED_RAND. Also, tests will print the seed
 *   to stdout, so that you know the choosen seed.
 *
 *
 * NMTST_DEBUG environment variable:
 *
 * "debug", "no-debug": when at test is run in debug mode, it might behave differently,
 *   depending on the test. See nmtst_is_debug().
 *   Known differences:
 *    - a test might leave the logging level unspecified. In this case, running in
 *      debug mode, will turn on DEBUG logging, otherwise WARN logging only.
 *    - if G_MESSAGES_DEBUG is unset, nm-test will set G_MESSAGES_DEBUG=all
 *      for tests that don't do assert-logging.
 *   Debug mode is determined as follows (highest priority first):
 *    - command line option --debug/--no-debug
 *    - NMTST_DEBUG=debug/no-debug
 *    - setting NMTST_DEBUG implies debugging turned on
 *    - g_test_verbose()
 *
 * "no-expect-message": for tests that would assert against log messages, disable
 *   those asserts.
 *
 * "log-level=LEVEL", "log-domains=DOMAIN": reset the log level and domain for tests.
 *    It only has an effect for nm-logging messages.
 *    This has no effect if the test asserts against logging (unless no-expect-message),
 *    otherwise, changing the logging would break tests.
 *    If you set the level to DEBUG or TRACE, it also sets G_MESSAGES_DEBUG=all (unless
 *    in assert-logging mode and unless G_MESSAGES_DEBUG is already defined).
 *
 * "sudo-cmd=PATH": when running root tests as normal user, the test will execute
 *   itself by invoking sudo at PATH.
 *   For example
 *     NMTST_DEBUG="sudo-cmd=$PWD/tools/test-sudo-wrapper.sh" make -C src/platform/tests/ check
 *
 * "slow|quick|thorough": enable/disable long-running tests. This sets nmtst_test_quick().
 *   Whether long-running tests are enabled is determined as follows (highest priority first):
 *     - specifying the value in NMTST_DEBUG has highest priority
 *     - respect g_test_quick(), if the command line contains '-mslow', '-mquick', '-mthorough'.
 *     - use compile time default
 *
 *******************************************************************************/

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "nm-default.h"
#include "nm-utils.h"
#include "nm-macros-internal.h"

#ifdef __NETWORKMANAGER_LOGGING_H__
/* We are running tests under src/. Let's include some files by default.
 * They are useful, and affect how nm-test-utils.h itself behaves. */
#include "NetworkManagerUtils.h"
#include "nm-keyfile-internal.h"
#endif

/*******************************************************************************/

/* general purpose functions that have no dependency on other nmtst functions */

inline static void
nmtst_assert_error (GError *error,
                    GQuark expect_error_domain,
                    gint expect_error_code,
                    const char *expect_error_pattern)
{
	if (expect_error_domain)
		g_assert_error (error, expect_error_domain, expect_error_code);
	else
		g_assert (error);
	g_assert (error->message);
	if (   expect_error_pattern
	    && !g_pattern_match_simple (expect_error_pattern, error->message)) {
		g_error ("error message does not have expected pattern '%s'. Instead it is '%s' (%s, %d)",
		         expect_error_pattern, error->message, g_quark_to_string (error->domain), error->code);
	}
}

#define NMTST_BUSY_WAIT(max_wait_ms, condition, wait) \
	G_STMT_START { \
		gint64 _nmtst_end, _nmtst_max_wait_us = (max_wait_ms) * 1000L; \
		\
		_nmtst_end = g_get_monotonic_time () + _nmtst_max_wait_us; \
		while (!(condition)) { \
			{ wait }; \
			if (g_get_monotonic_time () > _nmtst_end) \
				g_assert_not_reached (); \
		} \
	} G_STMT_END

inline static void
_nmtst_assert_success (gboolean success, GError *error, const char *file, int line)
{
	if (!success || error)
		g_error ("(%s:%d) FAILURE success=%d, error=%s", file, line, success, error && error->message ? error->message : "(no error)");
}
#define nmtst_assert_success(success, error) _nmtst_assert_success ((success), (error), __FILE__, __LINE__)

/*******************************************************************************/

struct __nmtst_internal
{
	GRand *rand0;
	guint32 rand_seed;
	GRand *rand;
	gboolean is_debug;
	gboolean assert_logging;
	gboolean no_expect_message;
	gboolean test_quick;
	char *sudo_cmd;
	char **orig_argv;
};

extern struct __nmtst_internal __nmtst_internal;

#define NMTST_DEFINE() \
struct __nmtst_internal __nmtst_internal = { 0 }; \
\
__attribute__ ((destructor)) static void \
_nmtst_exit (void) \
{ \
	__nmtst_internal.assert_logging = FALSE; \
	g_test_assert_expected_messages (); \
	nmtst_free (); \
}


inline static gboolean
nmtst_initialized (void)
{
	return !!__nmtst_internal.rand0;
}

#define __NMTST_LOG(cmd, ...) \
	G_STMT_START { \
		g_assert (nmtst_initialized ()); \
		if (!__nmtst_internal.assert_logging || __nmtst_internal.no_expect_message) { \
			cmd (__VA_ARGS__); \
		} else { \
			printf (_NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n" _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
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
__nmtst_init (int *argc, char ***argv, gboolean assert_logging, const char *log_level, const char *log_domains, gboolean *out_set_logging)
{
	const char *nmtst_debug;
	gboolean is_debug = FALSE;
	char *c_log_level = NULL, *c_log_domains = NULL;
	char *sudo_cmd = NULL;
	GArray *debug_messages = g_array_new (TRUE, FALSE, sizeof (char *));
	int i;
	gboolean no_expect_message = FALSE;
	gboolean _out_set_logging;
	gboolean test_quick = FALSE;
	gboolean test_quick_set = FALSE;
	gboolean test_quick_argv = FALSE;

	if (!out_set_logging)
		out_set_logging = &_out_set_logging;
	*out_set_logging = FALSE;

	g_assert (!nmtst_initialized ());

	g_assert (!((!!argc) ^ (!!argv)));
	g_assert (!argc || (g_strv_length (*argv) == *argc));
	g_assert (!assert_logging || (!log_level && !log_domains));

#ifdef __NETWORKMANAGER_UTILS_H__
	if (!nm_utils_get_testing_initialized ())
		_nm_utils_set_testing (_NM_UTILS_TEST_GENERAL);
#endif

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

	nm_g_type_init ();

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
			} else if (!g_ascii_strcasecmp (debug, "slow") || !g_ascii_strcasecmp (debug, "thorough")) {
				test_quick = FALSE;
				test_quick_set = TRUE;
			} else if (!g_ascii_strcasecmp (debug, "quick")) {
				test_quick = TRUE;
				test_quick_set = TRUE;
			} else {
				char *msg = g_strdup_printf (">>> nmtst: ignore unrecognized NMTST_DEBUG option \"%s\"", debug);

				g_array_append_val (debug_messages, msg);
			}
		}

		g_free (d_argv);
		g_free (nmtst_debug_copy);
	}

	if (__nmtst_internal.orig_argv) {
		char **a = __nmtst_internal.orig_argv;

		for (; *a; a++) {
			if (!g_ascii_strcasecmp (*a, "--debug"))
				is_debug = TRUE;
			else if (!g_ascii_strcasecmp (*a, "--no-debug"))
				is_debug = FALSE;
			else if (   !strcmp (*a, "-m=slow")
			         || !strcmp (*a, "-m=thorough")
			         || !strcmp (*a, "-m=quick")
			         || (!strcmp (*a, "-m") && *(a+1)
			                                && (   !strcmp (*(a+1), "quick")
			                                    || !strcmp (*(a+1), "slow")
			                                    || !strcmp (*(a+1), "thorough"))))
				test_quick_argv = TRUE;
		}
	}

	if (test_quick_set)
		__nmtst_internal.test_quick = test_quick;
	else if (test_quick_argv)
		__nmtst_internal.test_quick = g_test_quick ();
	else {
#ifdef NMTST_TEST_QUICK
		__nmtst_internal.test_quick = NMTST_TEST_QUICK;
#else
		__nmtst_internal.test_quick = FALSE;
#endif
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
#ifdef __NETWORKMANAGER_LOGGING_H__
		success = nm_logging_setup (log_level, log_domains, NULL, NULL);
		*out_set_logging = TRUE;
#endif
		g_assert (success);
	} else if (__nmtst_internal.no_expect_message) {
		/* We have a test that would be assert_logging, but the user specified no_expect_message.
		 * This transforms g_test_expect_message() into a NOP, but we also have to relax
		 * g_log_set_always_fatal(), which was set by g_test_init(). */
		g_log_set_always_fatal (G_LOG_FATAL_MASK);
#ifdef __NETWORKMANAGER_LOGGING_H__
		if (c_log_domains || c_log_level) {
			/* Normally, tests with assert_logging do not overwrite the logging level/domains because
			 * the logging statements are part of the assertions. But if the test is run with
			 * no-expect-message *and* the logging is set explicitly via environment variables,
			 * we still reset the logging. */
			gboolean success;

			success = nm_logging_setup (log_level, log_domains, NULL, NULL);
			*out_set_logging = TRUE;
			g_assert (success);
		}
#endif
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
	    (is_debug || (c_log_level && (!g_ascii_strcasecmp (c_log_level, "DEBUG") || !g_ascii_strcasecmp (c_log_level, "TRACE")))) &&
	    !g_getenv ("G_MESSAGES_DEBUG"))
	{
		/* if we are @is_debug or @log_level=="DEBUG" and
		 * G_MESSAGES_DEBUG is unset, we set G_MESSAGES_DEBUG=all.
		 * To disable this default behaviour, set G_MESSAGES_DEBUG='' */

		/* Note that g_setenv is not thread safe, but you should anyway call
		 * nmtst_init() at the very start. */
		g_setenv ("G_MESSAGES_DEBUG", "all", TRUE);
	}

	/* Delay messages until we setup logging. */
	for (i = 0; i < debug_messages->len; i++)
		__NMTST_LOG (g_message, "%s", g_array_index (debug_messages, const char *, i));

	g_strfreev ((char **) g_array_free (debug_messages, FALSE));
	g_free (c_log_level);
	g_free (c_log_domains);

#ifdef __NETWORKMANAGER_UTILS_H__
	/* ensure that monotonic timestamp is called (because it initially logs a line) */
	nm_utils_get_monotonic_timestamp_s ();
#endif

#ifdef NM_UTILS_H
	{
		gs_free_error GError *error = NULL;

		if (!nm_utils_init (&error))
			g_assert_not_reached ();
		g_assert_no_error (error);
	}
#endif
}

#ifdef __NETWORKMANAGER_LOGGING_H__
inline static void
nmtst_init_with_logging (int *argc, char ***argv, const char *log_level, const char *log_domains)
{
	__nmtst_init (argc, argv, FALSE, log_level, log_domains, NULL);
}
inline static void
nmtst_init_assert_logging (int *argc, char ***argv, const char *log_level, const char *log_domains)
{
	gboolean set_logging;

	__nmtst_init (argc, argv, TRUE, NULL, NULL, &set_logging);

	if (!set_logging) {
		gboolean success;

		success = nm_logging_setup (log_level, log_domains, NULL, NULL);
		g_assert (success);
	}
}
#else
inline static void
nmtst_init (int *argc, char ***argv, gboolean assert_logging)
{
	__nmtst_init (argc, argv, assert_logging, NULL, NULL, NULL);
}
#endif

inline static gboolean
nmtst_is_debug (void)
{
	g_assert (nmtst_initialized ());
	return __nmtst_internal.is_debug;
}

inline static gboolean
nmtst_test_quick (void)
{
	g_assert (nmtst_initialized ());
	return __nmtst_internal.test_quick;
}

#if GLIB_CHECK_VERSION(2,34,0)
#undef g_test_expect_message
#define g_test_expect_message(...) \
	G_STMT_START { \
		g_assert (nmtst_initialized ()); \
		if (__nmtst_internal.assert_logging && __nmtst_internal.no_expect_message) { \
			g_debug ("nmtst: assert-logging: g_test_expect_message %s", G_STRINGIFY ((__VA_ARGS__))); \
		} else { \
			G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
			g_test_expect_message (__VA_ARGS__); \
			G_GNUC_END_IGNORE_DEPRECATIONS \
		} \
	} G_STMT_END
#undef g_test_assert_expected_messages_internal
#define g_test_assert_expected_messages_internal(domain, file, line, func) \
	G_STMT_START { \
		const char *_domain = (domain); \
		const char *_file = (file); \
		const char *_func = (func); \
		int _line = (line); \
		\
		g_assert (nmtst_initialized ()); \
		if (__nmtst_internal.assert_logging && __nmtst_internal.no_expect_message) \
			g_debug ("nmtst: assert-logging: g_test_assert_expected_messages(%s, %s:%d, %s)", _domain?:"", _file?:"", _line, _func?:""); \
		\
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		g_test_assert_expected_messages_internal (_domain, _file, _line, _func); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	} G_STMT_END
#endif

inline static GRand *
nmtst_get_rand0 (void)
{
	g_assert (nmtst_initialized ());
	return __nmtst_internal.rand0;
}

inline static GRand *
nmtst_get_rand (void)
{
	g_assert (nmtst_initialized ());

	if (G_UNLIKELY (!__nmtst_internal.rand)) {
		guint32 seed;
		const char *str;

		if ((str = g_getenv ("NMTST_SEED_RAND"))) {
			gchar *s;
			gint64 i;

			i = g_ascii_strtoll (str, &s, 0);
			g_assert (s[0] == '\0' && i >= 0 && i < G_MAXUINT32);

			seed = i;
			__nmtst_internal.rand = g_rand_new_with_seed (seed);
		} else {
			__nmtst_internal.rand = g_rand_new ();

			seed = g_rand_int (__nmtst_internal.rand);
			g_rand_set_seed (__nmtst_internal.rand, seed);
		}
		__nmtst_internal.rand_seed = seed;

		g_print ("\nnmtst: initialize nmtst_get_rand() with NMTST_SEED_RAND=%u\n", seed);
	}
	return __nmtst_internal.rand;
}

inline static guint32
nmtst_get_rand_int (void)
{
	return g_rand_int (nmtst_get_rand ());
}

inline static void *
nmtst_rand_perm (GRand *rand, void *dst, const void *src, gsize elmt_size, gsize n_elmt)
{
	gsize i, j;
	char *p_, *pj;
	char *bu;

	g_assert (dst);
	g_assert (elmt_size > 0);
	g_assert (n_elmt < G_MAXINT32);

	if (n_elmt == 0)
		return dst;

	if (src && dst != src)
		memcpy (dst, src, elmt_size * n_elmt);

	if (!rand)
		rand = nmtst_get_rand ();

	bu = g_slice_alloc (elmt_size);

	p_ = dst;
	for (i = n_elmt; i > 1; i--) {
		j = g_rand_int_range (rand, 0, i);

		if (j != 0) {
			pj = &p_[j * elmt_size];

			/* swap */
			memcpy (bu, p_, elmt_size);
			memcpy (p_, pj, elmt_size);
			memcpy (pj, bu, elmt_size);
		}
		p_ += elmt_size;
	}

	g_slice_free1 (elmt_size, bu);
	return dst;
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

#define nmtst_assert_str_has_substr(str, substr) \
	G_STMT_START { \
		const char *__str = (str); \
		const char *__substr = (substr); \
		\
		g_assert (__str); \
		g_assert (__substr); \
		if (strstr (__str, __substr) == NULL) \
			g_error ("%s:%d: Expects \"%s\" but got \"%s\"", __FILE__, __LINE__, __substr, __str); \
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
_nmtst_assert_ip4_address (const char *file, int line, in_addr_t addr, const char *str_expected)
{
	if (nmtst_inet4_from_string (str_expected) != addr) {
		char buf[100];

		g_error ("%s:%d: Unexpected IPv4 address: expected %s, got %s",
		         file, line, str_expected ? str_expected : "0.0.0.0",
		         inet_ntop (AF_INET, &addr, buf, sizeof (buf)));
	}
}
#define nmtst_assert_ip4_address(addr, str_expected) _nmtst_assert_ip4_address (__FILE__, __LINE__, addr, str_expected)

inline static void
_nmtst_assert_ip6_address (const char *file, int line, const struct in6_addr *addr, const char *str_expected)
{
	struct in6_addr any = in6addr_any;

	if (!addr)
		addr = &any;

	if (memcmp (nmtst_inet6_from_string (str_expected), addr, sizeof (*addr)) != 0) {
		char buf[100];

		g_error ("%s:%d: Unexpected IPv6 address: expected %s, got %s",
		         file, line, str_expected ? str_expected : "::",
		         inet_ntop (AF_INET6, &addr, buf, sizeof (buf)));
	}
}
#define nmtst_assert_ip6_address(addr, str_expected) _nmtst_assert_ip6_address (__FILE__, __LINE__, addr, str_expected)

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

inline static char *
nmtst_file_resolve_relative_path (const char *rel, const char *cwd)
{
	gs_free char *cwd_free = NULL;

	g_assert (rel && *rel);

	if (g_path_is_absolute (rel))
		return g_strdup (rel);

	if (!cwd)
		cwd = cwd_free = g_get_current_dir ();
	return g_build_filename (cwd, rel, NULL);
}

inline static void
_nmtst_assert_resolve_relative_path_equals (const char *f1, const char *f2, const char *file, int line)
{
	gs_free char *p1 = NULL, *p2 = NULL;

	p1 = nmtst_file_resolve_relative_path (f1, NULL);
	p2 = nmtst_file_resolve_relative_path (f2, NULL);
	g_assert (p1 && *p1);

	/* Fixme: later we might need to coalesce repeated '/', "./", and "../".
	 * For now, it's good enough. */
	if (g_strcmp0 (p1, p2) != 0)
		g_error ("%s:%d : filenames don't match \"%s\" vs. \"%s\" // \"%s\" - \"%s\"", file, line, f1, f2, p1, p2);
}
#define nmtst_assert_resolve_relative_path_equals(f1, f2) _nmtst_assert_resolve_relative_path_equals (f1, f2, __FILE__, __LINE__);

/*******************************************************************************/

#ifdef __NETWORKMANAGER_PLATFORM_H__

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
                                 int ifindex, NMIPConfigSource source, guint32 timestamp,
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

inline static NMPlatformIP4Route *
nmtst_platform_ip4_route (const char *network, guint plen, const char *gateway)
{
	static NMPlatformIP4Route route;

	memset (&route, 0, sizeof (route));
	route.network = nmtst_inet4_from_string (network);
	route.plen = plen;
	route.gateway = nmtst_inet4_from_string (gateway);

	return &route;
}

inline static NMPlatformIP4Route *
nmtst_platform_ip4_route_full (const char *network, guint plen, const char *gateway,
                               int ifindex, NMIPConfigSource source,
                               guint metric, guint mss,
                               guint8 scope,
                               const char *pref_src)
{
	NMPlatformIP4Route *route = nmtst_platform_ip4_route (network, plen, gateway);

	route->ifindex = ifindex;
	route->source = source;
	route->metric = metric;
	route->mss = mss;
	route->scope_inv = nm_platform_route_scope_inv (scope);
	route->pref_src = nmtst_inet4_from_string (pref_src);

	return route;
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
                               int ifindex, NMIPConfigSource source,
                               guint metric, guint mss)
{
	NMPlatformIP6Route *route = nmtst_platform_ip6_route (network, plen, gateway);

	route->ifindex = ifindex;
	route->source = source;
	route->metric = metric;
	route->mss = mss;

	return route;
}

inline static int
_nmtst_platform_ip4_routes_equal_sort (gconstpointer a, gconstpointer b, gpointer user_data)
{
	return nm_platform_ip4_route_cmp ((const NMPlatformIP4Route *) a, (const NMPlatformIP4Route *) b);
}

inline static void
nmtst_platform_ip4_routes_equal (const NMPlatformIP4Route *a, const NMPlatformIP4Route *b, gsize len, gboolean ignore_order)
{
	gsize i;
	gs_free const NMPlatformIP4Route *c_a = NULL, *c_b = NULL;

	g_assert (a);
	g_assert (b);

	if (ignore_order) {
		a = c_a = g_memdup (a, sizeof (NMPlatformIP4Route) * len);
		b = c_b = g_memdup (b, sizeof (NMPlatformIP4Route) * len);
		g_qsort_with_data (c_a, len, sizeof (NMPlatformIP4Route), _nmtst_platform_ip4_routes_equal_sort, NULL);
		g_qsort_with_data (c_b, len, sizeof (NMPlatformIP4Route), _nmtst_platform_ip4_routes_equal_sort, NULL);
	}

	for (i = 0; i < len; i++) {
		if (nm_platform_ip4_route_cmp (&a[i], &b[i]) != 0) {
			g_error ("Error comparing IPv4 route[%lu]: %s vs %s", (long unsigned) i,
			         nmtst_static_1024_01 (nm_platform_ip4_route_to_string (&a[i])),
			         nmtst_static_1024_02 (nm_platform_ip4_route_to_string (&b[i])));
			g_assert_not_reached ();
		}
	}
}

inline static int
_nmtst_platform_ip6_routes_equal_sort (gconstpointer a, gconstpointer b, gpointer user_data)
{
	return nm_platform_ip6_route_cmp ((const NMPlatformIP6Route *) a, (const NMPlatformIP6Route *) b);
}

inline static void
nmtst_platform_ip6_routes_equal (const NMPlatformIP6Route *a, const NMPlatformIP6Route *b, gsize len, gboolean ignore_order)
{
	gsize i;
	gs_free const NMPlatformIP6Route *c_a = NULL, *c_b = NULL;

	g_assert (a);
	g_assert (b);

	if (ignore_order) {
		a = c_a = g_memdup (a, sizeof (NMPlatformIP6Route) * len);
		b = c_b = g_memdup (b, sizeof (NMPlatformIP6Route) * len);
		g_qsort_with_data (c_a, len, sizeof (NMPlatformIP6Route), _nmtst_platform_ip6_routes_equal_sort, NULL);
		g_qsort_with_data (c_b, len, sizeof (NMPlatformIP6Route), _nmtst_platform_ip6_routes_equal_sort, NULL);
	}

	for (i = 0; i < len; i++) {
		if (nm_platform_ip6_route_cmp (&a[i], &b[i]) != 0) {
			g_error ("Error comparing IPv6 route[%lu]: %s vs %s", (long unsigned) i,
			         nmtst_static_1024_01 (nm_platform_ip6_route_to_string (&a[i])),
			         nmtst_static_1024_02 (nm_platform_ip6_route_to_string (&b[i])));
			g_assert_not_reached ();
		}
	}
}

#endif


#ifdef __NETWORKMANAGER_IP4_CONFIG_H__

inline static NMIP4Config *
nmtst_ip4_config_clone (NMIP4Config *config)
{
	NMIP4Config *copy = nm_ip4_config_new (-1);

	g_assert (copy);
	g_assert (config);
	nm_ip4_config_replace (copy, config, NULL);
	return copy;
}

#endif


#ifdef __NETWORKMANAGER_IP6_CONFIG_H__

inline static NMIP6Config *
nmtst_ip6_config_clone (NMIP6Config *config)
{
	NMIP6Config *copy = nm_ip6_config_new (-1);

	g_assert (copy);
	g_assert (config);
	nm_ip6_config_replace (copy, config, NULL);
	return copy;
}

#endif

#if defined(__NM_SIMPLE_CONNECTION_H__) && defined(__NM_SETTING_CONNECTION_H__)

inline static NMConnection *
nmtst_create_minimal_connection (const char *id, const char *uuid, const char *type, NMSettingConnection **out_s_con)
{
	NMConnection *con;
	NMSetting *s_base = NULL;
	NMSettingConnection *s_con;
	gs_free char *uuid_free = NULL;

	g_assert (id);

	if (uuid)
		g_assert (nm_utils_is_uuid (uuid));
	else
		uuid = uuid_free = nm_utils_uuid_generate ();

	if (type) {
		GType type_g = nm_setting_lookup_type (type);

		g_assert (type_g != G_TYPE_INVALID);

		s_base = g_object_new (type_g, NULL);
		g_assert (NM_IS_SETTING (s_base));
	}

	con = nm_simple_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, id,
	              NM_SETTING_CONNECTION_UUID, uuid,
	              NM_SETTING_CONNECTION_TYPE, type,
	              NULL);
	nm_connection_add_setting (con, NM_SETTING (s_con));

	if (s_base)
		nm_connection_add_setting (con, s_base);

	if (out_s_con)
		*out_s_con = s_con;
	return con;
}

inline static gboolean
_nmtst_connection_normalize_v (NMConnection *connection, va_list args)
{
	GError *error = NULL;
	gboolean success;
	gboolean was_modified = FALSE;
	GHashTable *parameters = NULL;
	const char *p_name;

	g_assert (NM_IS_CONNECTION (connection));

	while ((p_name = va_arg (args, const char *))) {
		if (!parameters)
			parameters =  g_hash_table_new (g_str_hash, g_str_equal);
		g_hash_table_insert (parameters, (gpointer *) p_name, va_arg (args, gpointer));
	}

	success = nm_connection_normalize (connection,
	                                   parameters,
	                                   &was_modified,
	                                   &error);
	g_assert_no_error (error);
	g_assert (success);

	if (parameters)
		g_hash_table_destroy (parameters);

	return was_modified;
}

inline static gboolean
_nmtst_connection_normalize (NMConnection *connection, ...)
{
	gboolean was_modified;
	va_list args;

	va_start (args, connection);
	was_modified = _nmtst_connection_normalize_v (connection, args);
	va_end (args);

	return was_modified;
}
#define nmtst_connection_normalize(connection, ...) \
    _nmtst_connection_normalize(connection, ##__VA_ARGS__, NULL)

inline static NMConnection *
_nmtst_connection_duplicate_and_normalize (NMConnection *connection, ...)
{
	gboolean was_modified;
	va_list args;

	g_assert (NM_IS_CONNECTION (connection));

	connection = nm_simple_connection_new_clone (connection);

	va_start (args, connection);
	was_modified = _nmtst_connection_normalize_v (connection, args);
	va_end (args);

	return connection;
}
#define nmtst_connection_duplicate_and_normalize(connection, ...) \
    _nmtst_connection_duplicate_and_normalize(connection, ##__VA_ARGS__, NULL)

inline static void
nmtst_assert_connection_equals (NMConnection *a, gboolean normalize_a, NMConnection *b, gboolean normalize_b)
{
	gboolean compare;
	gs_unref_object NMConnection *a2 = NULL;
	gs_unref_object NMConnection *b2 = NULL;
	GHashTable *out_settings = NULL;

	g_assert (NM_IS_CONNECTION (a));
	g_assert (NM_IS_CONNECTION (b));

	if (normalize_a)
		a = a2 = nmtst_connection_duplicate_and_normalize (a);
	if (normalize_b)
		b = b2 = nmtst_connection_duplicate_and_normalize (b);

	compare = nm_connection_diff (a, b, NM_SETTING_COMPARE_FLAG_EXACT, &out_settings);
	if (!compare || out_settings) {
		const char *name, *pname;
		GHashTable *setting;
		GHashTableIter iter, iter2;

		__NMTST_LOG (g_message, ">>> ASSERTION nmtst_assert_connection_equals() fails");
		if (out_settings) {
			g_hash_table_iter_init (&iter, out_settings);
			while (g_hash_table_iter_next (&iter, (gpointer *) &name, (gpointer *) &setting)) {
				__NMTST_LOG (g_message, ">>> differences in setting '%s':", name);

				g_hash_table_iter_init (&iter2, setting);
				while (g_hash_table_iter_next (&iter2, (gpointer *) &pname, NULL))
					__NMTST_LOG (g_message, ">>> differences in setting '%s.%s'", name, pname);
			}
		}

#ifdef __NM_KEYFILE_INTERNAL_H__
		{
			gs_unref_keyfile GKeyFile *kf_a = NULL, *kf_b = NULL;
			gs_free char *str_a = NULL, *str_b = NULL;

			kf_a = nm_keyfile_write (a, NULL, NULL, NULL);
			kf_b = nm_keyfile_write (b, NULL, NULL, NULL);

			if (kf_a)
				str_a = g_key_file_to_data (kf_a, NULL, NULL);
			if (kf_b)
				str_b = g_key_file_to_data (kf_b, NULL, NULL);

			__NMTST_LOG (g_message, ">>> Connection A as kf (*WARNING: keyfile representation might not show the difference*):\n%s", str_a);
			__NMTST_LOG (g_message, ">>> Connection B as kf (*WARNING: keyfile representation might not show the difference*):\n%s", str_b);
		}
#endif
	}
	g_assert (compare);
	g_assert (!out_settings);

	compare = nm_connection_compare (a, b, NM_SETTING_COMPARE_FLAG_EXACT);
	g_assert (compare);
}

inline static void
nmtst_assert_connection_verifies_without_normalization (NMConnection *con)
{
	/* assert that the connection verifies and does not need any normalization */

	GError *error = NULL;
	gboolean success;
	gboolean was_modified = FALSE;
	gs_unref_object NMConnection *clone = NULL;

	g_assert (NM_IS_CONNECTION (con));

	clone = nm_simple_connection_new_clone (con);

	success = nm_connection_verify (con, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = nm_connection_normalize (con, NULL, &was_modified, &error);
	g_assert_no_error (error);
	g_assert (success);
	nmtst_assert_connection_equals (con, FALSE, clone, FALSE);
	g_assert (!was_modified);
}

inline static void
nmtst_assert_connection_verifies_and_normalizable (NMConnection *con)
{
	/* assert that the connection does verify, but normalization still modifies it */
	GError *error = NULL;
	gboolean success;
	gboolean was_modified = FALSE;

	g_assert (NM_IS_CONNECTION (con));

	success = nm_connection_verify (con, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_clear_error (&error);

	success = nm_connection_normalize (con, NULL, &was_modified, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (was_modified);

	/* again! */
	nmtst_assert_connection_verifies_without_normalization (con);
}

inline static void
nmtst_assert_connection_verifies_after_normalization (NMConnection *con,
                                                      GQuark expect_error_domain,
                                                      gint expect_error_code)
{
	/* assert that the connection does not verify, but normalization does fix it */
	GError *error = NULL;
	gboolean success;
	gboolean was_modified = FALSE;

	g_assert (NM_IS_CONNECTION (con));

	success = nm_connection_verify (con, &error);
	nmtst_assert_error (error, expect_error_domain, expect_error_code, NULL);
	g_assert (!success);
	g_clear_error (&error);

	success = nm_connection_normalize (con, NULL, &was_modified, &error);
	g_assert_no_error (error);
	g_assert (success);
	g_assert (was_modified);

	/* again! */
	nmtst_assert_connection_verifies_without_normalization (con);
}

inline static void
nmtst_assert_connection_unnormalizable (NMConnection *con,
                                        GQuark expect_error_domain,
                                        gint expect_error_code)
{
	/* assert that the connection does not verify, and it cannot be fixed by normalization */

	GError *error = NULL;
	gboolean success;
	gboolean was_modified = FALSE;

	g_assert (NM_IS_CONNECTION (con));

	success = nm_connection_verify (con, &error);
	nmtst_assert_error (error, expect_error_domain, expect_error_code, NULL);
	g_assert (!success);
	g_clear_error (&error);

	success = nm_connection_normalize (con, NULL, &was_modified, &error);
	nmtst_assert_error (error, expect_error_domain, expect_error_code, NULL);
	g_assert (!success);
	g_assert (!was_modified);
	g_clear_error (&error);
}

inline static void
nmtst_assert_setting_verifies (NMSetting *setting)
{
	/* assert that the setting verifies without an error */

	GError *error = NULL;
	gboolean success;

	g_assert (NM_IS_SETTING (setting));

	success = nm_setting_verify (setting, NULL, &error);
	g_assert_no_error (error);
	g_assert (success);
}

inline static void
nmtst_assert_setting_verify_fails (NMSetting *setting,
                                   GQuark expect_error_domain,
                                   gint expect_error_code)
{
	/* assert that the setting verification fails */

	GError *error = NULL;
	gboolean success;

	g_assert (NM_IS_SETTING (setting));

	success = nm_setting_verify (setting, NULL, &error);
	nmtst_assert_error (error, expect_error_domain, expect_error_code, NULL);
	g_assert (!success);
	g_clear_error (&error);
}

#endif

#ifdef __NM_UTILS_H__
static inline void
nmtst_assert_hwaddr_equals (gconstpointer hwaddr1, gssize hwaddr1_len, const char *expected, const char *loc)
{
	guint8 buf2[NM_UTILS_HWADDR_LEN_MAX];
	gsize hwaddr2_len = 1;
	const char *p;
	gboolean success;

	g_assert (hwaddr1_len > 0 && hwaddr1_len <= NM_UTILS_HWADDR_LEN_MAX);

	g_assert (expected);
	for (p = expected; *p; p++) {
		if (*p == ':' || *p == '-')
			hwaddr2_len++;
	}
	g_assert (hwaddr2_len <= NM_UTILS_HWADDR_LEN_MAX);
	g_assert (nm_utils_hwaddr_aton (expected, buf2, hwaddr2_len));

	/* Manually check the entire hardware address instead of using
	 * nm_utils_hwaddr_matches() because that function doesn't compare
	 * entire InfiniBand addresses for various (legitimate) reasons.
	 */
	success = (hwaddr1_len == hwaddr2_len);
	if (success)
		success = !memcmp (hwaddr1, buf2, hwaddr1_len);
	if (!success) {
		g_error ("assert: %s: hwaddr '%s' (%zd) expected, but got %s (%zd)",
		         loc, expected, hwaddr2_len, nm_utils_hwaddr_ntoa (hwaddr1, hwaddr1_len), hwaddr1_len);
	}
}
#define nmtst_assert_hwaddr_equals(hwaddr1, hwaddr1_len, expected) \
    nmtst_assert_hwaddr_equals (hwaddr1, hwaddr1_len, expected, G_STRLOC)
#endif

#if defined(__NM_SIMPLE_CONNECTION_H__) && defined(__NM_SETTING_CONNECTION_H__) && defined(__NM_KEYFILE_INTERNAL_H__)

inline static NMConnection *
nmtst_create_connection_from_keyfile (const char *keyfile_str, const char *keyfile_name, const char *base_dir)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gboolean success;
	NMConnection *con;

	g_assert (keyfile_str);

	keyfile =  g_key_file_new ();
	success = g_key_file_load_from_data (keyfile, keyfile_str, strlen (keyfile_str), G_KEY_FILE_NONE, &error);
	g_assert_no_error (error);
	g_assert (success);

	con = nm_keyfile_read (keyfile, keyfile_name, base_dir, NULL, NULL, &error);
	g_assert_no_error (error);
	g_assert (NM_IS_CONNECTION (con));

	g_key_file_unref (keyfile);

	nmtst_connection_normalize (con);

	return con;
}

#endif

#ifdef __NM_CONNECTION_H__

typedef enum {
	NMTST_VARIANT_EDITOR_CONNECTION,
	NMTST_VARIANT_EDITOR_SETTING,
	NMTST_VARIANT_EDITOR_PROPERTY
} NmtstVariantEditorPhase;

#define NMTST_VARIANT_EDITOR(__connection_variant, __code) \
	G_STMT_START { \
		GVariantIter __connection_iter, *__setting_iter; \
		GVariantBuilder __connection_builder, __setting_builder; \
		const char *__cur_setting_name, *__cur_property_name; \
		GVariant *__property_val; \
		NmtstVariantEditorPhase __phase; \
                                                                        \
		g_variant_builder_init (&__connection_builder, NM_VARIANT_TYPE_CONNECTION); \
		g_variant_iter_init (&__connection_iter, __connection_variant); \
		 \
		__phase = NMTST_VARIANT_EDITOR_CONNECTION; \
		__cur_setting_name = NULL; \
		__cur_property_name = NULL; \
		__code; \
		while (g_variant_iter_next (&__connection_iter, "{&sa{sv}}", &__cur_setting_name, &__setting_iter)) { \
			g_variant_builder_init (&__setting_builder, NM_VARIANT_TYPE_SETTING); \
			__phase = NMTST_VARIANT_EDITOR_SETTING; \
			__cur_property_name = NULL; \
			__code; \
			 \
			while (   __cur_setting_name \
			       && g_variant_iter_next (__setting_iter, "{&sv}", &__cur_property_name, &__property_val)) { \
				__phase = NMTST_VARIANT_EDITOR_PROPERTY; \
				__code; \
				 \
				if (__cur_property_name) { \
					g_variant_builder_add (&__setting_builder, "{sv}", \
					                       __cur_property_name, \
					                       __property_val); \
				} \
				g_variant_unref (__property_val); \
			} \
			 \
			if (__cur_setting_name) \
				g_variant_builder_add (&__connection_builder, "{sa{sv}}", __cur_setting_name, &__setting_builder); \
			g_variant_iter_free (__setting_iter); \
		} \
		 \
		g_variant_unref (__connection_variant); \
		 \
		__connection_variant = g_variant_builder_end (&__connection_builder); \
	} G_STMT_END;

#define NMTST_VARIANT_ADD_SETTING(__setting_name, __setting_variant) \
	G_STMT_START { \
		if (__phase == NMTST_VARIANT_EDITOR_CONNECTION) \
			g_variant_builder_add (&__connection_builder, "{s@a{sv}}", __setting_name, __setting_variant); \
	} G_STMT_END

#define NMTST_VARIANT_DROP_SETTING(__setting_name) \
	G_STMT_START { \
		if (__phase == NMTST_VARIANT_EDITOR_SETTING && __cur_setting_name) { \
			if (!strcmp (__cur_setting_name, __setting_name)) \
				__cur_setting_name = NULL; \
		} \
	} G_STMT_END

#define NMTST_VARIANT_ADD_PROPERTY(__setting_name, __property_name, __format_string, __value) \
	G_STMT_START { \
		if (__phase == NMTST_VARIANT_EDITOR_SETTING) { \
			if (!strcmp (__cur_setting_name, __setting_name)) { \
				g_variant_builder_add (&__setting_builder, "{sv}", __property_name, \
				                       g_variant_new (__format_string, __value)); \
			} \
		} \
	} G_STMT_END

#define NMTST_VARIANT_DROP_PROPERTY(__setting_name, __property_name) \
	G_STMT_START { \
		if (__phase == NMTST_VARIANT_EDITOR_PROPERTY && __cur_property_name) { \
			if (   !strcmp (__cur_setting_name, __setting_name) \
			    && !strcmp (__cur_property_name, __property_name)) \
				__cur_property_name = NULL; \
		} \
	} G_STMT_END

#define NMTST_VARIANT_CHANGE_PROPERTY(__setting_name, __property_name, __format_string, __value) \
	G_STMT_START { \
		NMTST_VARIANT_DROP_PROPERTY (__setting_name, __property_name); \
		NMTST_VARIANT_ADD_PROPERTY (__setting_name, __property_name, __format_string, __value); \
	} G_STMT_END

#endif /* __NM_CONNECTION_H__ */

#endif /* __NM_TEST_UTILS_H__ */
