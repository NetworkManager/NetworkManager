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
 * Copyright 2013 Red Hat, Inc.
 *
 */

#include "config.h"

#include <string.h>
#include <nm-utils.h>
#include "nm-glib.h"
#include "nm-setting-dcb.h"
#include "nm-connection.h"
#include "nm-errors.h"

#include "nm-test-utils.h"

#define DCB_FLAGS_ALL (NM_SETTING_DCB_FLAG_ENABLE | \
                       NM_SETTING_DCB_FLAG_ADVERTISE | \
                       NM_SETTING_DCB_FLAG_WILLING)

static void
test_dcb_flags_valid (void)
{
	gs_unref_object NMSettingDcb *s_dcb = NULL;
	GError *error = NULL;
	gboolean success;
	guint i;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_assert (s_dcb);

	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_flags (s_dcb), ==, 0);
	g_assert_cmpint (nm_setting_dcb_get_app_iscsi_flags (s_dcb), ==, 0);
	g_assert_cmpint (nm_setting_dcb_get_app_fip_flags (s_dcb), ==, 0);
	g_assert_cmpint (nm_setting_dcb_get_priority_flow_control_flags (s_dcb), ==, 0);
	g_assert_cmpint (nm_setting_dcb_get_priority_group_flags (s_dcb), ==, 0);

	g_object_set (G_OBJECT (s_dcb),
	              NM_SETTING_DCB_APP_FCOE_FLAGS, DCB_FLAGS_ALL,
	              NM_SETTING_DCB_APP_ISCSI_FLAGS, DCB_FLAGS_ALL,
	              NM_SETTING_DCB_APP_FIP_FLAGS, DCB_FLAGS_ALL,
	              NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, DCB_FLAGS_ALL,
	              NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, DCB_FLAGS_ALL,
	              NULL);
	/* Priority Group Bandwidth must total 100% */
	for (i = 0; i < 7; i++)
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, i, 12);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 7, 16);

	success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error);
	g_assert_no_error (error);
	g_assert (success);

	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_flags (s_dcb), ==, DCB_FLAGS_ALL);
	g_assert_cmpint (nm_setting_dcb_get_app_iscsi_flags (s_dcb), ==, DCB_FLAGS_ALL);
	g_assert_cmpint (nm_setting_dcb_get_app_fip_flags (s_dcb), ==, DCB_FLAGS_ALL);
	g_assert_cmpint (nm_setting_dcb_get_priority_flow_control_flags (s_dcb), ==, DCB_FLAGS_ALL);
	g_assert_cmpint (nm_setting_dcb_get_priority_group_flags (s_dcb), ==, DCB_FLAGS_ALL);
}

#define TEST_FLAG(p, f, v) \
{ \
	/* GObject property min/max should ensure the property does not get set to \
	 * the invalid value, so we ensure the value we just tried to set is 0 and \
	 * that verify is successful since the property never got set. \
	 */ \
	g_object_set (G_OBJECT (s_dcb), p, v, NULL); \
	g_assert_cmpint (f (s_dcb), ==, 0); \
	success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error); \
	g_assert_no_error (error); \
	g_assert (success); \
}

static void
test_dcb_flags_invalid (void)
{
	gs_unref_object NMSettingDcb *s_dcb = NULL;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_assert (s_dcb);

	g_test_expect_message ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_APP_FCOE_FLAGS, nm_setting_dcb_get_app_fcoe_flags, 0x332523);
	g_test_assert_expected_messages ();

	g_test_expect_message ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_APP_ISCSI_FLAGS, nm_setting_dcb_get_app_iscsi_flags, 0xFF);
	g_test_assert_expected_messages ();

	g_test_expect_message ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_APP_FIP_FLAGS, nm_setting_dcb_get_app_fip_flags, 0x1111);
	g_test_assert_expected_messages ();

	g_test_expect_message ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, nm_setting_dcb_get_priority_flow_control_flags, G_MAXUINT32);
	g_test_assert_expected_messages ();

	g_test_expect_message ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, nm_setting_dcb_get_priority_group_flags,
	           (NM_SETTING_DCB_FLAG_ENABLE | NM_SETTING_DCB_FLAG_ADVERTISE | NM_SETTING_DCB_FLAG_WILLING) + 1);
	g_test_assert_expected_messages ();
}

#define TEST_APP_PRIORITY(lcprop, ucprop, v) \
{ \
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_APP_##ucprop##_FLAGS, NM_SETTING_DCB_FLAG_NONE, NULL); \
 \
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_APP_##ucprop##_PRIORITY, v, NULL); \
	g_assert_cmpint (nm_setting_dcb_get_app_##lcprop##_priority (s_dcb), ==, v); \
 \
	/* Assert that the setting is invalid while the app is disabled unless v is default */ \
	success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error); \
	if (v >= 0) { \
		g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY); \
		g_assert (success == FALSE); \
	} else { \
		g_assert_no_error (error); \
		g_assert (success); \
	} \
	g_clear_error (&error); \
 \
	/* Set the enable flag and re-verify, this time it should be valid */ \
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_APP_##ucprop##_FLAGS, NM_SETTING_DCB_FLAG_ENABLE, NULL); \
	success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error); \
	g_assert_no_error (error); \
	g_assert (success); \
 \
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_APP_##ucprop##_PRIORITY, 0, NULL); \
}

static void
test_dcb_app_priorities (void)
{
	gs_unref_object NMSettingDcb *s_dcb = NULL;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_assert (s_dcb);

	/* Defaults */
	g_assert_cmpint (nm_setting_dcb_get_app_fcoe_priority (s_dcb), ==, -1);
	g_assert_cmpint (nm_setting_dcb_get_app_iscsi_priority (s_dcb), ==, -1);
	g_assert_cmpint (nm_setting_dcb_get_app_fip_priority (s_dcb), ==, -1);

	TEST_APP_PRIORITY (fcoe, FCOE, 6);
	TEST_APP_PRIORITY (iscsi, ISCSI, 5);
	TEST_APP_PRIORITY (fip, FIP, 4);

	TEST_APP_PRIORITY (fcoe, FCOE, -1);
	TEST_APP_PRIORITY (iscsi, ISCSI, -1);
	TEST_APP_PRIORITY (fip, FIP, -1);
}

#define TEST_PRIORITY_VALID(fn, id, val, flagsprop, verify) \
{ \
	/* Assert that setting the value gets the same value back out */ \
	nm_setting_dcb_set_priority_##fn (s_dcb, id, val); \
	g_assert_cmpint (nm_setting_dcb_get_priority_##fn (s_dcb, id), ==, val); \
 \
	if (verify) { \
		if (val != 0) { \
			/* Assert that verify fails because the flags do not include 'enabled' \
			 * and a value has been set. \
			 */ \
			success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error); \
			g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY); \
			g_assert (success == FALSE); \
			g_clear_error (&error); \
		} \
 \
		/* Assert that adding the 'enabled' flag verifies the setting */ \
		g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_PRIORITY_##flagsprop##_FLAGS, NM_SETTING_DCB_FLAG_ENABLE, NULL); \
		success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error); \
		g_assert_no_error (error); \
		g_assert (success); \
	} \
 \
	/* Reset everything */ \
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_PRIORITY_##flagsprop##_FLAGS, NM_SETTING_DCB_FLAG_NONE, NULL); \
	nm_setting_dcb_set_priority_##fn (s_dcb, id, 0); \
}

/* If Priority Groups are enabled, PG bandwidth must equal 100% */
#define SET_VALID_PRIORITY_GROUP_BANDWIDTH \
{ \
	guint x; \
	for (x = 0; x < 7; x++) \
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, x, 12); \
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 7, 16); \
}

static void
test_dcb_priorities_valid (void)
{
	gs_unref_object NMSettingDcb *s_dcb = NULL;
	GError *error = NULL;
	gboolean success;
	guint i;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_assert (s_dcb);

	for (i = 0; i < 8; i++)
		TEST_PRIORITY_VALID (flow_control, i, TRUE, FLOW_CONTROL, TRUE);

	SET_VALID_PRIORITY_GROUP_BANDWIDTH
	for (i = 0; i < 8; i++) {
		TEST_PRIORITY_VALID (group_id, i, i, GROUP, TRUE);
		TEST_PRIORITY_VALID (group_id, i, 7 - i, GROUP, TRUE);
	}

	/* Clear PG bandwidth from earlier tests */
	for (i = 0; i < 8; i++)
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, i, 0);

	/* Priority Group Bandwidth must add up to 100% if enabled, which requires
	 * some dancing for verifying individual values here.
	 */
	for (i = 0; i < 8; i++) {
		guint other = 7 - (i % 8);

		/* Set another priority group to the remaining bandwidth */
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, other, 100 - i);
		TEST_PRIORITY_VALID (group_bandwidth, i, i, GROUP, TRUE);

		/* Set another priority group to the remaining bandwidth */
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, other, 100 - (7 - i));
		TEST_PRIORITY_VALID (group_bandwidth, i, 7 - i, GROUP, TRUE);

		/* Clear remaining bandwidth */
		nm_setting_dcb_set_priority_group_bandwidth (s_dcb, other, 0);
	}

	SET_VALID_PRIORITY_GROUP_BANDWIDTH
	for (i = 0; i < 8; i++) {
		TEST_PRIORITY_VALID (bandwidth, i, i, GROUP, TRUE);
		TEST_PRIORITY_VALID (bandwidth, i, 7 - i, GROUP, TRUE);
	}

	SET_VALID_PRIORITY_GROUP_BANDWIDTH
	for (i = 0; i < 8; i++)
		TEST_PRIORITY_VALID (strict_bandwidth, i, TRUE, GROUP, TRUE);

	SET_VALID_PRIORITY_GROUP_BANDWIDTH
	for (i = 0; i < 8; i++) {
		TEST_PRIORITY_VALID (traffic_class, i, i, GROUP, TRUE);
		TEST_PRIORITY_VALID (traffic_class, i, 7 - i, GROUP, TRUE);
	}
}

static void
test_dcb_bandwidth_sums (void)
{
	gs_unref_object NMSettingDcb *s_dcb = NULL;
	GError *error = NULL;
	gboolean success;

	s_dcb = (NMSettingDcb *) nm_setting_dcb_new ();
	g_assert (s_dcb);

	/* Assert that setting the value gets the same value back out */
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 0, 9);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 1, 10);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 2, 11);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 3, 12);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 4, 13);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 5, 14);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 6, 15);
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 7, 16);

	/* Assert verify success when sums total 100% */
	g_object_set (G_OBJECT (s_dcb), NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, NM_SETTING_DCB_FLAG_ENABLE, NULL);
	success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error);
	g_assert_no_error (error);
	g_assert (success);

	/* Assert verify fails when sums do not total 100% */
	nm_setting_dcb_set_priority_group_bandwidth (s_dcb, 4, 20);
	success = nm_setting_verify (NM_SETTING (s_dcb), NULL, &error);
	g_assert_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY);
	g_assert (success == FALSE);
	g_clear_error (&error);
}

#define TPATH "/libnm/settings/dcb/"

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func (TPATH "flags-valid", test_dcb_flags_valid);
	g_test_add_func (TPATH "flags-invalid", test_dcb_flags_invalid);
	g_test_add_func (TPATH "app-priorities", test_dcb_app_priorities);
	g_test_add_func (TPATH "priorities", test_dcb_priorities_valid);
	g_test_add_func (TPATH "bandwidth-sums", test_dcb_bandwidth_sums);

	return g_test_run ();
}

