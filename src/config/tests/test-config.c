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

static void
setup_config (const char *config_file, const char *config_dir, ...)
{
	va_list ap;
	GPtrArray *args;
	char **argv, *arg;
	int argc;
	GOptionContext *context;
	gboolean success;

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

	context = g_option_context_new (NULL);
	g_option_context_add_main_entries (context, nm_config_get_options (), NULL);
	success = g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (!success)
		g_printerr ("Invalid options.\n");

	g_ptr_array_free (args, TRUE);
}

static void
test_config_simple (void)
{
	NMConfig *config;
	GError *error = NULL;
	const char **plugins;
	char *value;

	setup_config (SRCDIR "/NetworkManager.conf", "/no/such/dir", NULL);
	config = nm_config_new (&error);
	g_assert_no_error (error);

	g_assert_cmpstr (nm_config_get_path (config), ==, SRCDIR "/NetworkManager.conf");
	g_assert_cmpstr (nm_config_get_dhcp_client (config), ==, "dhclient");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpint (nm_config_get_connectivity_interval (config), ==, 100);

	plugins = nm_config_get_plugins (config);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 3);
	g_assert_cmpstr (plugins[0], ==, "foo");
	g_assert_cmpstr (plugins[1], ==, "bar");
	g_assert_cmpstr (plugins[2], ==, "baz");

	value = nm_config_get_value (config, "extra-section", "extra-key", NULL);
	g_assert_cmpstr (value, ==, "some value");
	g_free (value);

	value = nm_config_get_value (config, "extra-section", "no-key", &error);
	g_assert (!value);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_KEY_NOT_FOUND);
	g_clear_error (&error);

	value = nm_config_get_value (config, "no-section", "no-key", &error);
	g_assert (!value);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_GROUP_NOT_FOUND);
	g_clear_error (&error);

	g_object_unref (config);
}

static void
test_config_non_existent (void)
{
	NMConfig *config;
	GError *error = NULL;

	setup_config (SRCDIR "/no-such-file", "/no/such/dir", NULL);
	config = nm_config_new (&error);
	g_assert (!config);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND);
}

static void
test_config_parse_error (void)
{
	NMConfig *config;
	GError *error = NULL;

	setup_config (SRCDIR "/bad.conf", "/no/such/dir", NULL);
	config = nm_config_new (&error);
	g_assert (!config);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
}

static void
test_config_override (void)
{
	NMConfig *config;
	GError *error = NULL;
	const char **plugins;

	setup_config (SRCDIR "/NetworkManager.conf", "/no/such/dir",
	              "--plugins", "alpha,beta,gamma,delta",
	              "--connectivity-interval", "12",
	              NULL);
	config = nm_config_new (&error);
	g_assert_no_error (error);

	g_assert_cmpstr (nm_config_get_path (config), ==, SRCDIR "/NetworkManager.conf");
	g_assert_cmpstr (nm_config_get_dhcp_client (config), ==, "dhclient");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpint (nm_config_get_connectivity_interval (config), ==, 12);

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
	NMTestDevice *dev1, *dev2, *dev3, *dev4;

	fd = g_file_open_tmp (NULL, &state_file, &error);
	g_assert_no_error (error);

	nwrote = write (fd, "22:22:22:22:22:22\n", 18);
	g_assert_cmpint (nwrote, ==, 18);
	nwrote = write (fd, "44:44:44:44:44:44\n", 18);
	g_assert_cmpint (nwrote, ==, 18);
	close (fd);

	setup_config (SRCDIR "/NetworkManager.conf", "/no/such/dir",
	              "--no-auto-default", state_file,
	              NULL);
	config = nm_config_new (&error);
	g_assert_no_error (error);

	dev1 = nm_test_device_new ("11:11:11:11:11:11");
	dev2 = nm_test_device_new ("22:22:22:22:22:22");
	dev3 = nm_test_device_new ("33:33:33:33:33:33");
	dev4 = nm_test_device_new ("44:44:44:44:44:44");

	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev1)));
	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev2)));
	g_assert (nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev3)));
	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev4)));

	nm_config_set_ethernet_no_auto_default (config, NM_CONFIG_DEVICE (dev3));
	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev3)));

	g_object_unref (config);

	setup_config (SRCDIR "/NetworkManager.conf", "/no/such/dir",
	              "--no-auto-default", state_file,
	              NULL);
	config = nm_config_new (&error);
	g_assert_no_error (error);

	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev1)));
	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev2)));
	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev3)));
	g_assert (!nm_config_get_ethernet_can_auto_default (config, NM_CONFIG_DEVICE (dev4)));

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
	GError *error = NULL;
	const char **plugins;
	char *value;

	setup_config (SRCDIR "/NetworkManager.conf", SRCDIR "/conf.d", NULL);
	config = nm_config_new (&error);
	g_assert_no_error (error);

	g_assert_cmpstr (nm_config_get_path (config), ==, SRCDIR "/NetworkManager.conf");
	g_assert_cmpstr (nm_config_get_dhcp_client (config), ==, "dhcpcd");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpstr (nm_config_get_log_domains (config), ==, "PLATFORM,DNS,WIFI");
	g_assert_cmpstr (nm_config_get_connectivity_uri (config), ==, "http://example.net");
	g_assert_cmpint (nm_config_get_connectivity_interval (config), ==, 100);

	plugins = nm_config_get_plugins (config);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 5);
	g_assert_cmpstr (plugins[0], ==, "foo");
	g_assert_cmpstr (plugins[1], ==, "bar");
	g_assert_cmpstr (plugins[2], ==, "baz");
	g_assert_cmpstr (plugins[3], ==, "one");
	g_assert_cmpstr (plugins[4], ==, "two");

	value = nm_config_get_value (config, "main", "extra", NULL);
	g_assert_cmpstr (value, ==, "hello");
	g_free (value);

	value = nm_config_get_value (config, "main", "new", NULL);
	g_assert_cmpstr (value, ==, "something"); /* not ",something" */
	g_free (value);

	value = nm_config_get_value (config, "order", "a", NULL);
	g_assert_cmpstr (value, ==, "90");
	g_free (value);
	value = nm_config_get_value (config, "order", "b", NULL);
	g_assert_cmpstr (value, ==, "10");
	g_free (value);
	value = nm_config_get_value (config, "order", "c", NULL);
	g_assert_cmpstr (value, ==, "0");
	g_free (value);

	g_object_unref (config);
}

static void
test_config_confdir_parse_error (void)
{
	NMConfig *config;
	GError *error = NULL;

	/* Using SRCDIR as the conf dir will pick up bad.conf */
	setup_config (SRCDIR "/NetworkManager.conf", SRCDIR, NULL);
	config = nm_config_new (&error);
	g_assert (!config);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
}

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_test_init (&argc, &argv, NULL);

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

