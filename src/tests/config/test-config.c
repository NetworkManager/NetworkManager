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
 * Copyright 2013 Red Hat, Inc.
 *
 */

#include "config.h"

#include <unistd.h>

#include <glib.h>

#include <nm-config.h>
#include "nm-test-device.h"
#include "nm-fake-platform.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"

#include "nm-test-utils.h"

static NMConfig *
setup_config (GError **error, const char *config_file, const char *config_dir, ...)
{
	va_list ap;
	GPtrArray *args;
	char **argv, *arg;
	int argc;
	GOptionContext *context;
	gboolean success;
	NMConfig *config;
	GError *local_error = NULL;
	NMConfigCmdLineOptions *cli;

	g_assert (!error || !*error);

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "test-config");
	g_ptr_array_add (args, "--config");
	g_ptr_array_add (args, (char *)config_file);
	g_ptr_array_add (args, "--config-dir");
	g_ptr_array_add (args, (char *)config_dir);

	va_start (ap, config_dir);
	while ((arg = va_arg (ap, char *)))
		g_ptr_array_add (args, arg);
	va_end (ap);

	argv = (char **)args->pdata;
	argc = args->len;

	cli = nm_config_cmd_line_options_new ();

	context = g_option_context_new (NULL);
	nm_config_cmd_line_options_add_to_entries (cli, context);
	success = g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (!success)
		g_printerr ("Invalid options.\n");

	g_ptr_array_free (args, TRUE);

	config = nm_config_setup (cli, &local_error);
	if (error) {
		g_assert (!config);
		g_assert (local_error);
		g_propagate_error (error, local_error);
	} else {
		g_assert (config);
		g_assert_no_error (local_error);
	}
	nm_config_cmd_line_options_free (cli);
	return config;
}

static void
test_config_simple (void)
{
	NMConfig *config;
	const char **plugins;
	char *value;
	gs_unref_object NMDevice *dev50 = nm_test_device_new ("00:00:00:00:00:50");
	gs_unref_object NMDevice *dev51 = nm_test_device_new ("00:00:00:00:00:51");
	gs_unref_object NMDevice *dev52 = nm_test_device_new ("00:00:00:00:00:52");

	config = setup_config (NULL, SRCDIR "/NetworkManager.conf", "/no/such/dir", NULL);

	g_assert_cmpstr (nm_config_data_get_config_main_file (nm_config_get_data_orig (config)), ==, SRCDIR "/NetworkManager.conf");
	g_assert_cmpstr (nm_config_get_dhcp_client (config), ==, "dhclient");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpint (nm_config_data_get_connectivity_interval (nm_config_get_data_orig (config)), ==, 100);

	plugins = nm_config_get_plugins (config);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 3);
	g_assert_cmpstr (plugins[0], ==, "foo");
	g_assert_cmpstr (plugins[1], ==, "bar");
	g_assert_cmpstr (plugins[2], ==, "baz");

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "extra-section", "extra-key");
	g_assert_cmpstr (value, ==, "some value");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "extra-section", "no-key");
	g_assert (!value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "no-section", "no-key");
	g_assert (!value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "connection", "ipv6.ip6_privacy");
	g_assert_cmpstr (value, ==, "0");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "connection.dev51", "ipv4.route-metric");
	g_assert_cmpstr (value, ==, "51");
	g_free (value);


	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv6.route-metric", NULL);
	g_assert_cmpstr (value, ==, NULL);
	g_free (value);


	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", NULL);
	g_assert_cmpstr (value, ==, "50");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", dev50);
	g_assert_cmpstr (value, ==, "50");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", dev51);
	g_assert_cmpstr (value, ==, "51");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", dev52);
	g_assert_cmpstr (value, ==, "52");
	g_free (value);


	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test1", dev51);
	g_assert_cmpstr (value, ==, "yes");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test1", dev50);
	g_assert_cmpstr (value, ==, "no");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test2", dev51);
	g_assert_cmpstr (value, ==, NULL);
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test2", dev50);
	g_assert_cmpstr (value, ==, "no");
	g_free (value);


	g_object_unref (config);
}

static void
test_config_non_existent (void)
{
	GError *error = NULL;

	setup_config (&error, SRCDIR "/no-such-file", "/no/such/dir", NULL);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND);
	g_clear_error (&error);
}

static void
test_config_parse_error (void)
{
	GError *error = NULL;

	setup_config (&error, SRCDIR "/bad.conf", "/no/such/dir", NULL);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error (&error);
}

static void
test_config_override (void)
{
	NMConfig *config;
	const char **plugins;

	config = setup_config (NULL, SRCDIR "/NetworkManager.conf", "/no/such/dir",
	                       "--plugins", "alpha,beta,gamma,delta",
	                       "--connectivity-interval", "12",
	                       NULL);

	g_assert_cmpstr (nm_config_data_get_config_main_file (nm_config_get_data_orig (config)), ==, SRCDIR "/NetworkManager.conf");
	g_assert_cmpstr (nm_config_get_dhcp_client (config), ==, "dhclient");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpint (nm_config_data_get_connectivity_interval (nm_config_get_data_orig (config)), ==, 12);

	plugins = nm_config_get_plugins (config);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 4);
	g_assert_cmpstr (plugins[0], ==, "alpha");
	g_assert_cmpstr (plugins[1], ==, "beta");
	g_assert_cmpstr (plugins[2], ==, "gamma");
	g_assert_cmpstr (plugins[3], ==, "delta");

	g_object_unref (config);
}

static void
test_config_no_auto_default (void)
{
	NMConfig *config;
	GError *error = NULL;
	int fd, nwrote;
	char *state_file;
	NMDevice *dev1, *dev2, *dev3, *dev4;

	fd = g_file_open_tmp (NULL, &state_file, &error);
	g_assert_no_error (error);

	nwrote = write (fd, "22:22:22:22:22:22\n", 18);
	g_assert_cmpint (nwrote, ==, 18);
	nwrote = write (fd, "44:44:44:44:44:44\n", 18);
	g_assert_cmpint (nwrote, ==, 18);
	close (fd);

	config = setup_config (NULL, SRCDIR "/NetworkManager.conf", "/no/such/dir",
	                       "--no-auto-default", state_file,
	                       NULL);

	dev1 = nm_test_device_new ("11:11:11:11:11:11");
	dev2 = nm_test_device_new ("22:22:22:22:22:22");
	dev3 = nm_test_device_new ("33:33:33:33:33:33");
	dev4 = nm_test_device_new ("44:44:44:44:44:44");

	g_assert (nm_config_get_no_auto_default_for_device (config, dev1));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev2));
	g_assert (!nm_config_get_no_auto_default_for_device (config, dev3));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev4));

	g_test_expect_message ("NetworkManager", G_LOG_LEVEL_MESSAGE, "*config: update * (no-auto-default)*");
	nm_config_set_no_auto_default_for_device (config, dev3);
	g_test_assert_expected_messages ();

	g_assert (nm_config_get_no_auto_default_for_device (config, dev3));

	g_object_unref (config);

	config = setup_config (NULL, SRCDIR "/NetworkManager.conf", "/no/such/dir",
	                       "--no-auto-default", state_file,
	                       NULL);

	g_assert (nm_config_get_no_auto_default_for_device (config, dev1));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev2));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev3));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev4));

	g_object_unref (config);

	g_object_unref (dev1);
	g_object_unref (dev2);
	g_object_unref (dev3);
	g_object_unref (dev4);

	unlink (state_file);
	g_free (state_file);
}

static void
test_config_confdir (void)
{
	NMConfig *config;
	const char **plugins;
	char *value;

	config = setup_config (NULL, SRCDIR "/NetworkManager.conf", SRCDIR "/conf.d", NULL);

	g_assert_cmpstr (nm_config_data_get_config_main_file (nm_config_get_data_orig (config)), ==, SRCDIR "/NetworkManager.conf");
	g_assert_cmpstr (nm_config_get_dhcp_client (config), ==, "dhcpcd");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpstr (nm_config_get_log_domains (config), ==, "PLATFORM,DNS,WIFI");
	g_assert_cmpstr (nm_config_data_get_connectivity_uri (nm_config_get_data_orig (config)), ==, "http://example.net");
	g_assert_cmpint (nm_config_data_get_connectivity_interval (nm_config_get_data_orig (config)), ==, 100);

	plugins = nm_config_get_plugins (config);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 5);
	g_assert_cmpstr (plugins[0], ==, "foo");
	g_assert_cmpstr (plugins[1], ==, "bar");
	g_assert_cmpstr (plugins[2], ==, "baz");
	g_assert_cmpstr (plugins[3], ==, "one");
	g_assert_cmpstr (plugins[4], ==, "two");

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "main", "extra");
	g_assert_cmpstr (value, ==, "hello");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "main", "new");
	g_assert_cmpstr (value, ==, "something"); /* not ",something" */
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "order", "a");
	g_assert_cmpstr (value, ==, "90");
	g_free (value);
	value = nm_config_data_get_value (nm_config_get_data_orig (config), "order", "b");
	g_assert_cmpstr (value, ==, "10");
	g_free (value);
	value = nm_config_data_get_value (nm_config_get_data_orig (config), "order", "c");
	g_assert_cmpstr (value, ==, "0");
	g_free (value);

#define ASSERT_GET_CONN_DEFAULT(xconfig, xname, xvalue) \
	G_STMT_START { \
		gs_free char *_value = nm_config_data_get_connection_default (nm_config_get_data_orig (xconfig), (xname), NULL); \
		g_assert_cmpstr (_value, ==, (xvalue)); \
	} G_STMT_END
	ASSERT_GET_CONN_DEFAULT (config, "ord.key00", "A-0.0.00");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key01", "A-0.3.01");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key02", "A-0.2.02");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key03", "A-0.1.03");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key04", "B-1.3.04");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key05", "B-1.2.05");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key06", "B-1.1.06");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key07", "C-2.3.07");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key08", "C-2.2.08");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key09", "C-2.1.09");
	ASSERT_GET_CONN_DEFAULT (config, "ord.ovw01", "C-0.1.ovw01");

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "append", "val1");
	g_assert_cmpstr (value, ==, "a,c");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "append", "val2");
	g_assert_cmpstr (value, ==, "VAL2");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "append", "val3");
	g_assert_cmpstr (value, ==, NULL);
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "append", "val4");
	g_assert_cmpstr (value, ==, "vb,vb");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "append", "val5");
	g_assert_cmpstr (value, ==, "VAL5");
	g_free (value);

	g_object_unref (config);
}

static void
test_config_confdir_parse_error (void)
{
	GError *error = NULL;

	/* Using SRCDIR as the conf dir will pick up bad.conf */
	setup_config (&error, SRCDIR "/NetworkManager.conf", SRCDIR, NULL);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error (&error);
}

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	/* Initialize the DBus manager singleton explicitly, because it is accessed by
	 * the class initializer of NMDevice (used by the NMTestDevice stub).
	 * This way, we skip calling nm_dbus_manager_init_bus() which would
	 * either fail and/or cause unexpected actions in the test.
	 * */
	nm_dbus_manager_setup (g_object_new (NM_TYPE_DBUS_MANAGER, NULL));

	nm_fake_platform_setup ();

	g_test_add_func ("/config/simple", test_config_simple);
	g_test_add_func ("/config/non-existent", test_config_non_existent);
	g_test_add_func ("/config/parse-error", test_config_parse_error);
	g_test_add_func ("/config/no-auto-default", test_config_no_auto_default);
	g_test_add_func ("/config/confdir", test_config_confdir);
	g_test_add_func ("/config/confdir-parse-error", test_config_confdir_parse_error);

	/* This one has to come last, because it leaves its values in
	 * nm-config.c's global variables, and there's no way to reset
	 * those to NULL.
	 */
	g_test_add_func ("/config/override", test_config_override);

	return g_test_run ();
}

