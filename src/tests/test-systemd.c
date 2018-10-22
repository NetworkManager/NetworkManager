/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "systemd/nm-sd.h"
#include "systemd/nm-sd-utils.h"

#include "nm-test-utils-core.h"

/*****************************************************************************
 * Stub implementations of libNetworkManagerBase symbols
 *****************************************************************************/

gboolean
nm_utils_get_testing_initialized (void)
{
	return TRUE;
}

void
_nm_utils_set_testing (NMUtilsTestFlags flags)
{
	g_assert_not_reached ();
}

gint32
nm_utils_get_monotonic_timestamp_s (void)
{
	return 1;
}

NMLogDomain _nm_logging_enabled_state[_LOGL_N_REAL];

void
_nm_log_impl (const char *file,
              guint line,
              const char *func,
              NMLogLevel level,
              NMLogDomain domain,
              int error,
              const char *ifname,
              const char *con_uuid,
              const char *fmt,
              ...)
{
}

gboolean
nm_logging_setup (const char  *level,
                  const char  *domains,
                  char       **bad_domains,
                  GError     **error)
{
	return TRUE;
}

/*****************************************************************************/

static void
test_dhcp_create (void)
{
	sd_dhcp_client *client4 = NULL;
	int r;

	r = sd_dhcp_client_new (&client4, FALSE);
	g_assert (r == 0);
	g_assert (client4);

	if (/* never true */ client4 == (gpointer) &r) {
		/* we don't want to call this, but ensure that the linker
		 * includes all these symbols. */
		sd_dhcp_client_start (client4);
	}

	sd_dhcp_client_unref (client4);
}

/*****************************************************************************/

static void
test_lldp_create (void)
{
	sd_lldp *lldp = NULL;
	int r;

	r = sd_lldp_new (&lldp);
	g_assert (r == 0);
	g_assert (lldp);

	sd_lldp_unref (lldp);
}

/*****************************************************************************/

typedef struct {
	GMainLoop *mainloop;
	sd_event_source *event_source;
} TestSdEventData;

static int
_test_sd_event_timeout_cb (sd_event_source *s, uint64_t usec, void *userdata)
{
	TestSdEventData *user_data = userdata;

	g_assert (user_data);
	g_assert (user_data->mainloop);
	g_assert (user_data->event_source);

	user_data->event_source = sd_event_source_unref (user_data->event_source);
	g_main_loop_quit (user_data->mainloop);
	return 0;
}

static void
test_sd_event (void)
{
	int repeat;

	for (repeat = 0; repeat < 2; repeat++) {
		guint sd_id = 0;
		int r;
		int i, n;
		sd_event *other_events[3] = { NULL }, *event = NULL;
		TestSdEventData user_data = { 0 };

		g_assert_cmpint (sd_event_default (NULL), ==, 0);

		for (i = 0, n = (nmtst_get_rand_int () % (G_N_ELEMENTS (other_events) + 1)); i < n; i++) {
			r = sd_event_default (&other_events[i]);
			g_assert (r >= 0 && other_events[i]);
		}

		sd_id = nm_sd_event_attach_default ();

		r = sd_event_default (&event);
		g_assert (r >= 0 && event);

		r = sd_event_add_time (event, &user_data.event_source, CLOCK_MONOTONIC, 1, 0, _test_sd_event_timeout_cb, &user_data);
		g_assert (r >= 0 && user_data.event_source);

		user_data.mainloop = g_main_loop_new (NULL, FALSE);
		g_main_loop_run (user_data.mainloop);
		g_main_loop_unref (user_data.mainloop);

		g_assert (!user_data.event_source);

		event = sd_event_unref (event);
		for (i = 0, n = (nmtst_get_rand_int () % (G_N_ELEMENTS (other_events) + 1)); i < n; i++)
			other_events[i] = sd_event_unref (other_events[i]);
		nm_clear_g_source (&sd_id);
		for (i = 0, n = G_N_ELEMENTS (other_events); i < n; i++)
			other_events[i] = sd_event_unref (other_events[i]);

		g_assert_cmpint (sd_event_default (NULL), ==, 0);
	}
}

/*****************************************************************************/

static void
test_path_equal (void)
{
#define _path_equal_check1(path, kill_dots, expected) \
	G_STMT_START { \
		const gboolean _kill_dots = (kill_dots); \
		const char *_path0 = (path); \
		const char *_expected = (expected); \
		gs_free char *_path = g_strdup (_path0); \
		const char *_path_result; \
		\
		if (   !_kill_dots \
		    && !nm_sd_utils_path_equal (_path0, _expected)) \
			g_error ("Paths \"%s\" and \"%s\" don't compare equal", _path0, _expected); \
		\
		_path_result = nm_sd_utils_path_simplify (_path, _kill_dots); \
		g_assert (_path_result == _path); \
		g_assert_cmpstr (_path, ==, _expected); \
	} G_STMT_END

#define _path_equal_check(path, expected_no_kill_dots, expected_kill_dots) \
	G_STMT_START { \
		_path_equal_check1 (path, FALSE, expected_no_kill_dots); \
		_path_equal_check1 (path, TRUE,  expected_kill_dots ?: expected_no_kill_dots); \
	} G_STMT_END

	_path_equal_check ("",                  "",                NULL);
	_path_equal_check (".",                 ".",               "");
	_path_equal_check ("..",                "..",              NULL);
	_path_equal_check ("/..",               "/..",             NULL);
	_path_equal_check ("//..",              "/..",             NULL);
	_path_equal_check ("/.",                "/.",              "/");
	_path_equal_check ("./",                ".",               "");
	_path_equal_check ("./.",               "./.",             "");
	_path_equal_check (".///.",             "./.",             "");
	_path_equal_check (".///./",            "./.",             "");
	_path_equal_check (".////",             ".",               "");
	_path_equal_check ("//..//foo/",        "/../foo",         NULL);
	_path_equal_check ("///foo//./bar/.",   "/foo/./bar/.",    "/foo/bar");
	_path_equal_check (".//./foo//./bar/.", "././foo/./bar/.", "foo/bar");
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "ALL");

	g_test_add_func ("/systemd/dhcp/create", test_dhcp_create);
	g_test_add_func ("/systemd/lldp/create", test_lldp_create);
	g_test_add_func ("/systemd/sd-event", test_sd_event);
	g_test_add_func ("/systemd/test_path_equal", test_path_equal);

	return g_test_run ();
}
