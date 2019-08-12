// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2019 Red Hat
 */

#include "nm-default.h"

#include "nm-service-providers.h"

#include "nm-test-utils-core.h"

static void
test_positive_cb (const char *apn,
                  const char *username,
                  const char *password,
                  const char *gateway,
                  const char *auth_method,
                  const GSList *dns,
                  GError *error,
                  gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
	g_assert_no_error (error);
	g_assert_cmpstr (apn, ==, "gprs.example.com");
	g_assert_cmpstr (username, ==, "praise");
	g_assert_cmpstr (password, ==, "santa");
	g_assert_cmpstr (gateway, ==, "192.0.2.3");
	g_assert_cmpstr (auth_method, ==, "pap");

	g_assert_nonnull (dns);
	g_assert_cmpstr (dns->data, ==, "192.0.2.2");
	dns = dns->next;
	g_assert_nonnull (dns);
	g_assert_cmpstr (dns->data, ==, "192.0.2.1");
	g_assert_null (dns->next);
}

static void
test_positive (void)
{
	GMainLoop *loop = g_main_loop_new (NULL, FALSE);

	nm_service_providers_find_gsm_apn (NM_BUILD_SRCDIR"/src/devices/wwan/tests/test-service-providers.xml",
	                                   "13337", NULL, test_positive_cb, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
}

/*****************************************************************************/

static void
test_negative_cb (const char *apn,
                  const char *username,
                  const char *password,
                  const char *gateway,
                  const char *auth_method,
                  const GSList *dns,
                  GError *error,
                  gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
	g_assert_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN);
}

static void
test_negative (void)
{
	GMainLoop *loop = g_main_loop_new (NULL, FALSE);

	nm_service_providers_find_gsm_apn (NM_BUILD_SRCDIR"/src/devices/wwan/tests/test-service-providers.xml",
	                                   "78130", NULL, test_negative_cb, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
}

/*****************************************************************************/

static void
test_nonexistent_cb (const char *apn,
                     const char *username,
                     const char *password,
                     const char *gateway,
                     const char *auth_method,
                     const GSList *dns,
                     GError *error,
                     gpointer user_data)
{
	GMainLoop *loop = user_data;

	g_main_loop_quit (loop);
	g_assert_error (error, G_IO_ERROR, G_IO_ERROR_AGAIN);
}

static void
test_nonexistent (void)
{
	GMainLoop *loop = g_main_loop_new (NULL, FALSE);

	nm_service_providers_find_gsm_apn ("nonexistent.xml", "13337", NULL,
	                                   test_nonexistent_cb, loop);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/service-providers/positive", test_positive);
	g_test_add_func ("/service-providers/negative", test_negative);
	g_test_add_func ("/service-providers/nonexistent", test_nonexistent);

	return g_test_run ();
}

