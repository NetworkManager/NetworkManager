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

#include "config.h"


#include <nm-simple-connection.h>
#include <nm-setting-connection.h>
#include "nm-default.h"
#include "nm-device-ethernet-utils.h"

#include "nm-test-utils.h"

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

/*******************************************/

static void
test_defname_no_connections (void)
{
	gs_free char *name = NULL;

	name = nm_device_ethernet_utils_get_default_wired_name (NULL);
	g_assert_cmpstr (name, ==, "Wired connection 1");
}

/*******************************************/

static void
test_defname_no_conflict (void)
{
	GSList *list = NULL;
	gs_free char *name = NULL;

	list = g_slist_append (list, _new_connection ("asdfasdfasdfadf"));
	list = g_slist_append (list, _new_connection ("work wifi"));
	list = g_slist_append (list, _new_connection ("random gsm connection"));

	name = nm_device_ethernet_utils_get_default_wired_name (list);
	g_assert_cmpstr (name, ==, "Wired connection 1");

	g_slist_free_full (list, g_object_unref);
}

/*******************************************/

static void
test_defname_conflict (void)
{
	GSList *list = NULL;
	gs_free char *name = NULL;

	list = g_slist_append (list, _new_connection ("asdfasdfasdfadf"));
	list = g_slist_append (list, _new_connection ("Wired connection 1"));
	list = g_slist_append (list, _new_connection ("random gsm connection"));

	name = nm_device_ethernet_utils_get_default_wired_name (list);
	g_assert_cmpstr (name, ==, "Wired connection 2");

	g_slist_free_full (list, g_object_unref);
}

/*******************************************/

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

	name = nm_device_ethernet_utils_get_default_wired_name (list);
	g_assert_cmpstr (name, ==, "Wired connection 4");

	g_slist_free_full (list, g_object_unref);
}

/*******************************************/

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

