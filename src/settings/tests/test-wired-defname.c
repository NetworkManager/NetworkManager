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
 * Copyright (C) 2010 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <glib-object.h>

#include <nm-connection.h>
#include <nm-setting-connection.h>
#include "nm-settings-utils.h"

static NMConnection *
_new_connection (const char *id)
{
	NMConnection *a;
	NMSetting *setting;

	a = nm_connection_new ();
	setting = nm_setting_connection_new ();
	g_object_set (setting, NM_SETTING_CONNECTION_ID, id, NULL);
	nm_connection_add_setting (a, setting);
	return a;
}

/*******************************************/

static void
test_defname_no_connections (void)
{
	GHashTable *hash;
	char *name;

	hash = g_hash_table_new (g_direct_hash, g_direct_equal);

	name = nm_settings_utils_get_default_wired_name (hash);
	g_assert_cmpstr (name, ==, "Wired connection 1");

	g_hash_table_destroy (hash);
}

/*******************************************/

static void
test_defname_no_conflict (void)
{
	GHashTable *hash;
	char *name;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_object_unref);

	g_hash_table_insert (hash, "a", _new_connection ("asdfasdfasdfadf"));
	g_hash_table_insert (hash, "b", _new_connection ("work wifi"));
	g_hash_table_insert (hash, "c", _new_connection ("random gsm connection"));

	name = nm_settings_utils_get_default_wired_name (hash);
	g_assert_cmpstr (name, ==, "Wired connection 1");

	g_hash_table_destroy (hash);
}

/*******************************************/

static void
test_defname_conflict (void)
{
	GHashTable *hash;
	char *name;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_object_unref);

	g_hash_table_insert (hash, "a", _new_connection ("asdfasdfasdfadf"));
	g_hash_table_insert (hash, "b", _new_connection ("Wired connection 1"));
	g_hash_table_insert (hash, "c", _new_connection ("random gsm connection"));

	name = nm_settings_utils_get_default_wired_name (hash);
	g_assert_cmpstr (name, ==, "Wired connection 2");

	g_hash_table_destroy (hash);
}

/*******************************************/

static void
test_defname_multiple_conflicts (void)
{
	GHashTable *hash;
	char *name;

	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) g_object_unref);

	g_hash_table_insert (hash, "a", _new_connection ("random gsm connection"));
	g_hash_table_insert (hash, "b", _new_connection ("home wifi"));
	g_hash_table_insert (hash, "c", _new_connection ("Wired connection 1"));
	g_hash_table_insert (hash, "d", _new_connection ("Wired connection 2"));
	g_hash_table_insert (hash, "e", _new_connection ("Wired connection 3"));
	g_hash_table_insert (hash, "f", _new_connection ("work wifi"));
	g_hash_table_insert (hash, "g", _new_connection ("a vpn"));

	name = nm_settings_utils_get_default_wired_name (hash);
	g_assert_cmpstr (name, ==, "Wired connection 4");

	g_hash_table_destroy (hash);
}

/*******************************************/

int
main (int argc, char **argv)
{
#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/defname/no_connections", test_defname_no_connections);
	g_test_add_func ("/defname/no_conflict", test_defname_no_conflict);
	g_test_add_func ("/defname/conflict", test_defname_conflict);
	g_test_add_func ("/defname/multiple_conflicts", test_defname_multiple_conflicts);

	return g_test_run ();
}

