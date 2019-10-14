// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-simple-connection.h"
#include "nm-setting-connection.h"
#include "devices/nm-device-ethernet-utils.h"

#include "nm-test-utils-core.h"

static NMConnection *
_new_connection (const char *id)
{
	NMConnection *a;
	NMSetting *setting;

	a = nm_simple_connection_new ();
	setting = nm_setting_connection_new ();
	g_object_set (setting, NM_SETTING_CONNECTION_ID, id, NULL);
	nm_connection_add_setting (a, setting);
	return a;
}

/*****************************************************************************/

static char *
_get_default_wired_name (GSList *list)
{
	gs_unref_hashtable GHashTable *existing_ids = NULL;

	if (list) {
		existing_ids = g_hash_table_new (nm_str_hash, g_str_equal);
		for (; list; list = list->next)
			g_hash_table_add (existing_ids, (char *) nm_connection_get_id (list->data));
	}
	return nm_device_ethernet_utils_get_default_wired_name (existing_ids);
}

/*****************************************************************************/

static void
test_defname_no_connections (void)
{
	gs_free char *name = NULL;

	name = _get_default_wired_name (NULL);
	g_assert_cmpstr (name, ==, "Wired connection 1");
}

/*****************************************************************************/

static void
test_defname_no_conflict (void)
{
	GSList *list = NULL;
	gs_free char *name = NULL;

	list = g_slist_append (list, _new_connection ("asdfasdfasdfadf"));
	list = g_slist_append (list, _new_connection ("work wifi"));
	list = g_slist_append (list, _new_connection ("random gsm connection"));

	name = _get_default_wired_name (list);
	g_assert_cmpstr (name, ==, "Wired connection 1");

	g_slist_free_full (list, g_object_unref);
}

/*****************************************************************************/

static void
test_defname_conflict (void)
{
	GSList *list = NULL;
	gs_free char *name = NULL;

	list = g_slist_append (list, _new_connection ("asdfasdfasdfadf"));
	list = g_slist_append (list, _new_connection ("Wired connection 1"));
	list = g_slist_append (list, _new_connection ("random gsm connection"));

	name = _get_default_wired_name (list);
	g_assert_cmpstr (name, ==, "Wired connection 2");

	g_slist_free_full (list, g_object_unref);
}

/*****************************************************************************/

static void
test_defname_multiple_conflicts (void)
{
	GSList *list = NULL;
	gs_free char *name = NULL;

	list = g_slist_append (list, _new_connection ("random gsm connection"));
	list = g_slist_append (list, _new_connection ("home wifi"));
	list = g_slist_append (list, _new_connection ("Wired connection 1"));
	list = g_slist_append (list, _new_connection ("Wired connection 2"));
	list = g_slist_append (list, _new_connection ("Wired connection 3"));
	list = g_slist_append (list, _new_connection ("work wifi"));
	list = g_slist_append (list, _new_connection ("a vpn"));

	name = _get_default_wired_name (list);
	g_assert_cmpstr (name, ==, "Wired connection 4");

	g_slist_free_full (list, g_object_unref);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	g_test_add_func ("/defname/no_connections", test_defname_no_connections);
	g_test_add_func ("/defname/no_conflict", test_defname_no_conflict);
	g_test_add_func ("/defname/conflict", test_defname_conflict);
	g_test_add_func ("/defname/multiple_conflicts", test_defname_multiple_conflicts);

	return g_test_run ();
}

