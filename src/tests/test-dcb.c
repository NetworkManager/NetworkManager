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
 * Copyright (C) 2013 Red Hat, Inc.
 *
 */

#include <glib.h>
#include <string.h>

#include "nm-dcb.h"

typedef struct {
	guint num;
	const char *cmds[];
} DcbExpected;

static gboolean
test_dcb_func (char **argv, guint which, gpointer user_data, GError **error)
{
	DcbExpected *e = user_data;
	char *f;

	g_assert (argv[0] == NULL);
	argv[0] = (which == DCBTOOL) ? "dcbtool" : "fcoeadm";

	f = g_strjoinv (" ", argv);
	if (e->cmds[e->num] == NULL)
		g_assert_cmpstr (f, ==, NULL);
	g_assert_cmpstr (e->cmds[e->num], !=, NULL);
	g_assert_cmpstr (f, ==, e->cmds[e->num++]);
	g_free (f);
	return TRUE;
}

#define DCB_FLAGS_ALL (NM_SETTING_DCB_FLAG_ENABLE | \
                       NM_SETTING_DCB_FLAG_ADVERTISE | \
                       NM_SETTING_DCB_FLAG_WILLING)

static void
test_dcb_fcoe (void)
{
	static DcbExpected expected = { 0,
		{ "dcbtool sc eth0 app:fcoe e:1 a:1 w:1",
		  "dcbtool sc eth0 app:fcoe appcfg:40",
		  "dcbtool sc eth0 app:iscsi e:0 a:0 w:0",
		  "dcbtool sc eth0 app:fip e:0 a:0 w:0",
		  "dcbtool sc eth0 pfc e:0 a:0 w:0",
		  "dcbtool sc eth0 pg e:0",
		  NULL },
	};
	NMSettingDcb *s_dcb;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FCOE_FLAGS, DCB_FLAGS_ALL,
	              NM_SETTING_DCB_APP_FCOE_PRIORITY, 6,
	              NULL);

	success = _dcb_setup ("eth0", s_dcb, test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
	g_object_unref (s_dcb);
}

static void
test_dcb_iscsi (void)
{
	static DcbExpected expected = { 0,
		{ "dcbtool sc eth0 app:fcoe e:0 a:0 w:0",
		  "dcbtool sc eth0 app:iscsi e:1 a:0 w:1",
		  "dcbtool sc eth0 app:iscsi appcfg:08",
		  "dcbtool sc eth0 app:fip e:0 a:0 w:0",
		  "dcbtool sc eth0 pfc e:0 a:0 w:0",
		  "dcbtool sc eth0 pg e:0",
		  NULL },
	};
	NMSettingDcb *s_dcb;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_ISCSI_FLAGS, (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_WILLING),
	              NM_SETTING_DCB_APP_ISCSI_PRIORITY, 3,
	              NULL);

	success = _dcb_setup ("eth0", s_dcb, test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
	g_object_unref (s_dcb);
}

static void
test_dcb_fip (void)
{
	static DcbExpected expected = { 0,
		{ "dcbtool sc eth0 app:fcoe e:0 a:0 w:0",
		  "dcbtool sc eth0 app:iscsi e:0 a:0 w:0",
		  "dcbtool sc eth0 app:fip e:1 a:1 w:0",
		  "dcbtool sc eth0 app:fip appcfg:01",
		  "dcbtool sc eth0 pfc e:0 a:0 w:0",
		  "dcbtool sc eth0 pg e:0",
		  NULL },
	};
	NMSettingDcb *s_dcb;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FIP_FLAGS, (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE),
	              NM_SETTING_DCB_APP_FIP_PRIORITY, 0,
	              NULL);

	success = _dcb_setup ("eth0", s_dcb, test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
	g_object_unref (s_dcb);
}

static void
test_dcb_fip_default_prio (void)
{
	static DcbExpected expected = { 0,
		{ "dcbtool sc eth0 app:fcoe e:0 a:0 w:0",
		  "dcbtool sc eth0 app:iscsi e:0 a:0 w:0",
		  "dcbtool sc eth0 app:fip e:1 a:1 w:0",
		  "dcbtool sc eth0 pfc e:0 a:0 w:0",
		  "dcbtool sc eth0 pg e:0",
		  NULL },
	};
	NMSettingDcb *s_dcb;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FIP_FLAGS, (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE),
	              NM_SETTING_DCB_APP_FIP_PRIORITY, -1,
	              NULL);

	success = _dcb_setup ("eth0", s_dcb, test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
	g_object_unref (s_dcb);
}

static void
test_dcb_pfc (void)
{
	static DcbExpected expected = { 0,
		{ "dcbtool sc eth0 app:fcoe e:0 a:0 w:0",
		  "dcbtool sc eth0 app:iscsi e:0 a:0 w:0",
		  "dcbtool sc eth0 app:fip e:0 a:0 w:0",
		  "dcbtool sc eth0 pfc e:1 a:1 w:1",
		  "dcbtool sc eth0 pfc pfcup:01101100",
		  "dcbtool sc eth0 pg e:0",
		  NULL },
	};
	NMSettingDcb *s_dcb;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, DCB_FLAGS_ALL,
	              NULL);

	nm_setting_dcb_set_priority_flow_control (s_dcb, 0, FALSE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 1, TRUE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 2, TRUE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 3, FALSE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 4, TRUE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 5, TRUE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 6, FALSE);
	nm_setting_dcb_set_priority_flow_control (s_dcb, 7, FALSE);

	success = _dcb_setup ("eth0", s_dcb, test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
	g_object_unref (s_dcb);
}

static void
test_dcb_priority_groups (void)
{
	static DcbExpected expected = { 0,
		{ "dcbtool sc eth0 app:fcoe e:0 a:0 w:0",
		  "dcbtool sc eth0 app:iscsi e:0 a:0 w:0",
		  "dcbtool sc eth0 app:fip e:0 a:0 w:0",
		  "dcbtool sc eth0 pfc e:0 a:0 w:0",
		  "dcbtool sc eth0 pg e:1 a:1 w:1" \
		      " pgid:765f3210" \
		      " pgpct:10,40,5,10,5,20,7,3" \
		      " uppct:100,50,33,25,20,16,14,12" \
		      " strict:01010101" \
		      " up2tc:01201201",
		  NULL },
	};
	NMSettingDcb *s_dcb;
	GError *error = NULL;
	gboolean success;
	guint i;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, DCB_FLAGS_ALL,
	              NULL);

	for (i = 0; i < 8; i++) {
		/* Make sure at least one 15/f is present in the group IDs */
		nm_setting_dcb_set_priority_group_id (s_dcb, i, (i == 3) ? 15 : 7 - i);
		nm_setting_dcb_set_priority_bandwidth (s_dcb, i, 100 / (i + 1));
		nm_setting_dcb_set_priority_strict_bandwidth (s_dcb, i, i % 2);
		nm_setting_dcb_set_priority_traffic_class (s_dcb, i, i % 3);
	}

	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 0, 10);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 1, 40);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 2, 5);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 3, 10);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 4, 5);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 5, 20);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 6, 7);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 7, 3);

	success = _dcb_setup ("eth0", s_dcb, test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
	g_object_unref (s_dcb);
}

static void
test_dcb_cleanup (void)
{
	static DcbExpected expected = { 0,
		{ "fcoeadm -d eth0",
		  "dcbtool sc eth0 app:fcoe e:0",
		  "dcbtool sc eth0 app:iscsi e:0",
		  "dcbtool sc eth0 app:fip e:0",
		  "dcbtool sc eth0 pfc e:0",
		  "dcbtool sc eth0 pg e:0",
		  "dcbtool sc eth0 dcb off",
		  NULL },
	};
	GError *error = NULL;
	gboolean success;

	success = _fcoe_cleanup ("eth0", test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	success = _dcb_cleanup ("eth0", test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpstr (expected.cmds[expected.num], ==, NULL);
}

static void
test_fcoe_create (void)
{
	static DcbExpected expected1 = { 0,
		{ "fcoeadm -m fabric -c eth0", NULL },
	};
	static DcbExpected expected2 = { 0,
		{ "fcoeadm -m vn2vn -c eth0", NULL },
	};
	GError *error = NULL;
	gboolean success;
	NMSettingDcb *s_dcb;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FCOE_FLAGS, DCB_FLAGS_ALL,
	              NULL);

	/* Default mode is fabric */
	success = _fcoe_setup ("eth0", s_dcb, test_dcb_func, &expected1, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Test VN2VN */
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_APP_FCOE_MODE, NM_SETTING_DCB_FCOE_MODE_VN2VN, NULL);
	success = _fcoe_setup ("eth0", s_dcb, test_dcb_func, &expected2, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_object_unref (s_dcb);
}

static void
test_fcoe_cleanup (void)
{
	static DcbExpected expected = { 0,
		{ "fcoeadm -d eth0", NULL },
	};
	GError *error = NULL;
	gboolean success;

	success = _fcoe_cleanup ("eth0", test_dcb_func, &expected, &error);
	g_assert_no_error (error);
	g_assert (success);
}

/*******************************************/

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	g_test_add_func ("/dcb/fcoe", test_dcb_fcoe);
	g_test_add_func ("/dcb/iscsi", test_dcb_iscsi);
	g_test_add_func ("/dcb/fip", test_dcb_fip);
	g_test_add_func ("/dcb/fip-default-priority", test_dcb_fip_default_prio);
	g_test_add_func ("/dcb/pfc", test_dcb_pfc);
	g_test_add_func ("/dcb/priority-groups", test_dcb_priority_groups);
	g_test_add_func ("/dcb/cleanup", test_dcb_cleanup);
	g_test_add_func ("/fcoe/create", test_fcoe_create);
	g_test_add_func ("/fcoe/cleanup", test_fcoe_cleanup);

	return g_test_run ();
}

