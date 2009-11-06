/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 *
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
 * Copyright (C) 2008 - 2009 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>

#include "nm-test-helpers.h"
#include <nm-utils.h>

#include "nm-setting-connection.h"
#include "nm-setting-vpn.h"


static void
vpn_check_func (const char *key, const char *value, gpointer user_data)
{
	const char *test = user_data;

	if (!strcmp (key, "foobar1")) {
		ASSERT (strcmp (value, "blahblah1") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar2")) {
		ASSERT (strcmp (value, "blahblah2") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar3")) {
		ASSERT (strcmp (value, "blahblah3") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	if (!strcmp (key, "foobar4")) {
		ASSERT (strcmp (value, "blahblah4") == 0,
				test, "unexpected vpn item '%s' / '%s'", key, value);
		return;
	}

	ASSERT (FALSE, test, "unexpected vpn item '%s'", key);
}

static void
vpn_check_empty_func (const char *key, const char *value, gpointer user_data)
{
	const char *test = user_data;

	/* We don't expect any values */
	ASSERT (FALSE, test, "unexpected vpn item '%s'", key);
}

static void
test_setting_vpn_items (void)
{
	NMSettingVPN *s_vpn;

	s_vpn = (NMSettingVPN *) nm_setting_vpn_new ();
	ASSERT (s_vpn != NULL,
	        "vpn-items",
	        "error creating vpn setting");

	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_data_item (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_data_item (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_data_item (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_func, "vpn-data");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar1");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar2");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar3");
	nm_setting_vpn_remove_data_item (s_vpn, "foobar4");

	nm_setting_vpn_add_secret (s_vpn, "foobar1", "blahblah1");
	nm_setting_vpn_add_secret (s_vpn, "foobar2", "blahblah2");
	nm_setting_vpn_add_secret (s_vpn, "foobar3", "blahblah3");
	nm_setting_vpn_add_secret (s_vpn, "foobar4", "blahblah4");

	/* Ensure that added values are all present */
	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_func, "vpn-secrets");
	nm_setting_vpn_remove_secret (s_vpn, "foobar1");
	nm_setting_vpn_remove_secret (s_vpn, "foobar2");
	nm_setting_vpn_remove_secret (s_vpn, "foobar3");
	nm_setting_vpn_remove_secret (s_vpn, "foobar4");

	/* Try to add some blank values and make sure they are rejected */
	nm_setting_vpn_add_data_item (s_vpn, NULL, NULL);
	nm_setting_vpn_add_data_item (s_vpn, "", "");
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", NULL);
	nm_setting_vpn_add_data_item (s_vpn, "foobar1", "");
	nm_setting_vpn_add_data_item (s_vpn, NULL, "blahblah1");
	nm_setting_vpn_add_data_item (s_vpn, "", "blahblah1");

	nm_setting_vpn_foreach_data_item (s_vpn, vpn_check_empty_func, "vpn-data-empty");

	/* Try to add some blank secrets and make sure they are rejected */
	nm_setting_vpn_add_secret (s_vpn, NULL, NULL);
	nm_setting_vpn_add_secret (s_vpn, "", "");
	nm_setting_vpn_add_secret (s_vpn, "foobar1", NULL);
	nm_setting_vpn_add_secret (s_vpn, "foobar1", "");
	nm_setting_vpn_add_secret (s_vpn, NULL, "blahblah1");
	nm_setting_vpn_add_secret (s_vpn, "", "blahblah1");

	nm_setting_vpn_foreach_secret (s_vpn, vpn_check_empty_func, "vpn-secrets-empty");

	g_object_unref (s_vpn);
}

int main (int argc, char **argv)
{
	GError *error = NULL;
	DBusGConnection *bus;
	char *base;

	g_type_init ();
	bus = dbus_g_bus_get (DBUS_BUS_SESSION, NULL);

	if (!nm_utils_init (&error))
		FAIL ("nm-utils-init", "failed to initialize libnm-util: %s", error->message);

	/* The tests */
	test_setting_vpn_items ();

	base = g_path_get_basename (argv[0]);
	fprintf (stdout, "%s: SUCCESS\n", base);
	g_free (base);
	return 0;
}

