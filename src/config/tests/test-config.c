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

#include <glib.h>

#include <nm-config.h>

static void
test_config_simple (void)
{
	NMConfig *config;
	GError *error = NULL;
	const char **plugins;

	config = nm_config_new (SRCDIR "/NetworkManager.conf",
	                        NULL, NULL, NULL, NULL, -1, NULL,
	                        &error);
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

	g_object_unref (config);
}

static void
test_config_non_existent (void)
{
	NMConfig *config;
	GError *error = NULL;

	config = nm_config_new (SRCDIR "/no-such-file",
	                        NULL, NULL, NULL, NULL, -1, NULL,
	                        &error);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND);
}

static void
test_config_parse_error (void)
{
	NMConfig *config;
	GError *error = NULL;

	config = nm_config_new (SRCDIR "/bad.conf",
	                        NULL, NULL, NULL, NULL, -1, NULL,
	                        &error);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
}

static void
test_config_override (void)
{
	NMConfig *config;
	GError *error = NULL;
	const char **plugins;

	config = nm_config_new (SRCDIR "/NetworkManager.conf",
	                        "alpha,beta,gamma,delta", NULL, NULL, NULL, 12, NULL,
	                        &error);
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

int
main (int argc, char **argv)
{
	g_type_init ();
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/config/simple", test_config_simple);
	g_test_add_func ("/config/non-existent", test_config_non_existent);
	g_test_add_func ("/config/parse-error", test_config_parse_error);

	/* This one has to come last, because it leaves its values in
	 * nm-config.c's global variables, and there's no way to reset
	 * those to NULL.
	 */
	g_test_add_func ("/config/override", test_config_override);

	return g_test_run ();
}

