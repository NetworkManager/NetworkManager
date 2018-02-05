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
 * Copyright 2008 - 2017 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <linux/pkt_sched.h>
#include <string.h>

#include "nm-utils.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bond.h"
#include "nm-setting-dcb.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-dummy.h"
#include "nm-connection.h"
#include "nm-simple-connection.h"
#include "nm-setting-connection.h"
#include "nm-errors.h"

#include "nm-utils/nm-test-utils.h"

/*****************************************************************************/

static void
compare_blob_data (const char *test,
                   const char *key_path,
                   GBytes *key)
{
	char *contents = NULL;
	gsize len = 0;
	GError *error = NULL;
	gboolean success;

	g_assert (key && g_bytes_get_size (key) > 0);

	success = g_file_get_contents (key_path, &contents, &len, &error);
	nmtst_assert_success (success, error);

	g_assert_cmpmem (contents, len, g_bytes_get_data (key, NULL), g_bytes_get_size (key));

	g_free (contents);
}

static void
check_scheme_path (GBytes *value, const char *path)
{
	const guint8 *p;

	g_assert (value);

	p = g_bytes_get_data (value, NULL);
	g_assert (memcmp (p, NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH, strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH)) == 0);
	p += strlen (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH);
	g_assert (memcmp (p, path, strlen (path)) == 0);
	p += strlen (path);
	g_assert (*p == '\0');
}

static void
test_private_key_import (const char *path,
                         const char *password,
                         NMSetting8021xCKScheme scheme)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021xCKFormat tmp_fmt;
	GError *error = NULL;
	GBytes *tmp_key = NULL, *client_cert = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             scheme,
	                                             &format,
	                                             &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	tmp_fmt = nm_setting_802_1x_get_private_key_format (s_8021x);
	g_assert (tmp_fmt == format);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (pw != NULL);
	g_assert_cmpstr (pw, ==, password);

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		tmp_key = nm_setting_802_1x_get_private_key_blob (s_8021x);
		compare_blob_data ("private-key-import", path, tmp_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
		check_scheme_path (tmp_key, path);
		g_bytes_unref (tmp_key);
	} else
		g_assert_not_reached ();

	/* If it's PKCS#12 ensure the client cert is the same value */
	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PRIVATE_KEY, &tmp_key, NULL);
		g_assert (tmp_key);

		g_object_get (s_8021x, NM_SETTING_802_1X_CLIENT_CERT, &client_cert, NULL);
		g_assert (client_cert);

		/* make sure they are the same */
		g_assert (g_bytes_equal (tmp_key, client_cert));

		g_bytes_unref (tmp_key);
		g_bytes_unref (client_cert);
	}

	g_object_unref (s_8021x);
}

static void
test_phase2_private_key_import (const char *path,
                                const char *password,
                                NMSetting8021xCKScheme scheme)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	NMSetting8021xCKFormat tmp_fmt;
	GError *error = NULL;
	GBytes *tmp_key = NULL, *client_cert = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    scheme,
	                                                    &format,
	                                                    &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	tmp_fmt = nm_setting_802_1x_get_phase2_private_key_format (s_8021x);
	g_assert (tmp_fmt == format);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	if (scheme == NM_SETTING_802_1X_CK_SCHEME_BLOB) {
		tmp_key = nm_setting_802_1x_get_phase2_private_key_blob (s_8021x);
		compare_blob_data ("phase2-private-key-import", path, tmp_key);
	} else if (scheme == NM_SETTING_802_1X_CK_SCHEME_PATH) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
		check_scheme_path (tmp_key, path);
		g_bytes_unref (tmp_key);
	} else
		g_assert_not_reached ();

	/* If it's PKCS#12 ensure the client cert is the same value */
	if (format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_PRIVATE_KEY, &tmp_key, NULL);
		g_assert (tmp_key);

		g_object_get (s_8021x, NM_SETTING_802_1X_PHASE2_CLIENT_CERT, &client_cert, NULL);
		g_assert (client_cert);

		/* make sure they are the same */
		g_assert (g_bytes_equal (tmp_key, client_cert));

		g_bytes_unref (tmp_key);
		g_bytes_unref (client_cert);
	}

	g_object_unref (s_8021x);
}

static void
test_wrong_password_keeps_data (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Now try to set it to something that's not a certificate */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             "Makefile.am",
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	nmtst_assert_no_success (success, error);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	g_clear_error (&error);

	/* Make sure the password hasn't changed */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	g_object_unref (s_8021x);
}

static void
test_clear_private_key (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             path,
	                                             password,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             &format,
	                                             &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	/* Now clear it */
	success = nm_setting_802_1x_set_private_key (s_8021x,
	                                             NULL,
	                                             NULL,
	                                             NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                             NULL,
	                                             &error);
	nmtst_assert_success (success, error);

	/* Ensure the password is also now clear */
	g_assert (!nm_setting_802_1x_get_private_key_password (s_8021x));

	g_object_unref (s_8021x);
}

static void
test_wrong_phase2_password_keeps_data (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Now try to set it to something that's not a certificate */
	format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    "Makefile.am",
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	nmtst_assert_no_success (success, error);
	g_assert (format == NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);
	g_clear_error (&error);

	/* Make sure the password hasn't changed */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	g_object_unref (s_8021x);
}

static void
test_clear_phase2_private_key (const char *path, const char *password)
{
	NMSetting8021x *s_8021x;
	gboolean success;
	NMSetting8021xCKFormat format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
	GError *error = NULL;
	const char *pw;

	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
	g_assert (s_8021x);

	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    path,
	                                                    password,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    &format,
	                                                    &error);
	nmtst_assert_success (success, error);
	g_assert (format != NM_SETTING_802_1X_CK_FORMAT_UNKNOWN);

	/* Make sure the password is what we expect */
	pw = nm_setting_802_1x_get_phase2_private_key_password (s_8021x);
	g_assert (pw);
	g_assert_cmpstr (pw, ==, password);

	/* Now clear it */
	success = nm_setting_802_1x_set_phase2_private_key (s_8021x,
	                                                    NULL,
	                                                    NULL,
	                                                    NM_SETTING_802_1X_CK_SCHEME_BLOB,
	                                                    NULL,
	                                                    &error);
	nmtst_assert_success (success, error);

	/* Ensure the password is also now clear */
	g_assert (!nm_setting_802_1x_get_phase2_private_key_password (s_8021x));

	g_object_unref (s_8021x);
}

static void
test_8021x (gconstpointer test_data)
{
	char **parts, *path, *password;

	parts = g_strsplit ((const char *) test_data, ", ", -1);
	g_assert_cmpint (g_strv_length (parts), ==, 2);

	path = g_build_filename (TEST_CERT_DIR, parts[0], NULL);
	password = parts[1];

	/* Test phase1 and phase2 path scheme */
	test_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_PATH);
	test_phase2_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_PATH);

	/* Test phase1 and phase2 blob scheme */
	test_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_BLOB);
	test_phase2_private_key_import (path, password, NM_SETTING_802_1X_CK_SCHEME_BLOB);

	/* Test that using a wrong password does not change existing data */
	test_wrong_password_keeps_data (path, password);
	test_wrong_phase2_password_keeps_data (path, password);

	/* Test clearing the private key */
	test_clear_private_key (path, password);
	test_clear_phase2_private_key (path, password);

	g_free (path);
	g_strfreev (parts);
}

/*****************************************************************************/

static void
create_bond_connection (NMConnection **con, NMSettingBond **s_bond)
{
	NMSettingConnection *s_con;

	g_assert (con);
	g_assert (s_bond);

	*con = nmtst_create_minimal_connection ("bond",
	                                        NULL,
	                                        NM_SETTING_BOND_SETTING_NAME,
	                                        &s_con);
	g_assert (*con);
	g_assert (s_con);

	g_object_set (s_con, NM_SETTING_CONNECTION_INTERFACE_NAME, "bond0", NULL);

	*s_bond = (NMSettingBond *) nm_setting_bond_new ();
	g_assert (*s_bond);

	nm_connection_add_setting (*con, NM_SETTING (*s_bond));
}

#define test_verify_options(exp, ...) \
	G_STMT_START { \
		const char *__opts[] = { __VA_ARGS__ , NULL }; \
		\
		_test_verify_options (__opts, exp); \
	} G_STMT_END

static void
_test_verify_options (const char **options, gboolean expected_result)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingBond *s_bond;
	GError *error = NULL;
	gboolean success;
	const char **option;

	create_bond_connection (&con, &s_bond);

	for (option = options; option[0] && option[1]; option += 2)
		g_assert (nm_setting_bond_add_option (s_bond, option[0], option[1]));

	if (expected_result) {
		nmtst_assert_connection_verifies_and_normalizable (con);
		nmtst_connection_normalize (con);
		success = nm_setting_verify ((NMSetting *) s_bond, con, &error);
		nmtst_assert_success (success, error);
	} else {
		nmtst_assert_connection_unnormalizable (con,
		                                        NM_CONNECTION_ERROR,
		                                        NM_CONNECTION_ERROR_INVALID_PROPERTY);
	}
}

static void
test_bond_verify (void)
{
	test_verify_options (TRUE,
	                     "mode", "3",
	                     "arp_interval", "0");
	test_verify_options (FALSE,
	                     /* arp_interval not supported in balance-alb mode */
	                     "mode", "balance-alb",
	                     "arp_interval", "1",
	                     "arp_ip_target", "1.2.3.4");
	test_verify_options (FALSE,
	                     /* arp_ip_target requires arp_interval */
	                     "mode", "balance-rr",
	                     "arp_ip_target", "1.2.3.4");
	test_verify_options (TRUE,
	                     "mode", "balance-rr",
	                     "arp_interval", "1",
	                     "arp_ip_target", "1.2.3.4");
	test_verify_options (FALSE,
	                     /* num_grat_arp, num_unsol_na cannot be different */
	                     "mode", "balance-rr",
	                     "num_grat_arp", "3",
	                     "num_unsol_na", "4");
	test_verify_options (TRUE,
	                     "mode", "balance-rr",
	                     "num_grat_arp", "5",
	                     "num_unsol_na", "5");
	test_verify_options (TRUE,
	                     "mode", "active-backup",
	                     "primary", "eth0");
	test_verify_options (FALSE,
	                     /* primary requires mode=active-backup */
	                     "mode", "802.3ad",
	                     "primary", "eth0");
	test_verify_options (TRUE,
	                     "mode", "802.3ad",
	                     "lacp_rate", "fast");
	test_verify_options (FALSE,
	                     /* lacp_rate=fast requires mode=802.3ad */
	                     "mode", "balance-rr",
	                     "lacp_rate", "fast");
	test_verify_options (TRUE,
	                     "mode", "802.3ad",
	                     "ad_actor_system", "ae:00:11:33:44:55");
}

static void
test_bond_compare_options (gboolean exp_res, const char **opts1, const char **opts2)
{
	gs_unref_object NMSettingBond *s_bond1 = NULL, *s_bond2 = NULL;
	const char **p;

	s_bond1 = (NMSettingBond *) nm_setting_bond_new ();
	g_assert (s_bond1);
	s_bond2 = (NMSettingBond *) nm_setting_bond_new ();
	g_assert (s_bond2);

	for (p = opts1; p[0] && p[1]; p += 2)
		g_assert (nm_setting_bond_add_option (s_bond1, p[0], p[1]));

	for (p = opts2; p[0] && p[1]; p += 2)
		g_assert (nm_setting_bond_add_option (s_bond2, p[0], p[1]));

	g_assert_cmpint (nm_setting_compare ((NMSetting *) s_bond1,
	                                     (NMSetting *) s_bond2,
	                                     NM_SETTING_COMPARE_FLAG_EXACT),
	                 ==,
	                 exp_res);
}

static void
test_bond_compare (void)
{
	test_bond_compare_options (TRUE,
	                           ((const char *[]){ "mode", "balance-rr", "miimon", "1", NULL }),
	                           ((const char *[]){ "mode", "balance-rr", "miimon", "1", NULL }));
	test_bond_compare_options (FALSE,
	                           ((const char *[]){ "mode", "balance-rr", "miimon", "1", NULL }),
	                           ((const char *[]){ "mode", "balance-rr", "miimon", "2", NULL }));

	/* ignore default values */
	test_bond_compare_options (TRUE,
	                           ((const char *[]){ "miimon", "1", NULL }),
	                           ((const char *[]){ "miimon", "1", "updelay", "0", NULL }));

	/* special handling of num_grat_arp, num_unsol_na */
	test_bond_compare_options (FALSE,
	                           ((const char *[]){ "num_grat_arp", "2", NULL }),
	                           ((const char *[]){ "num_grat_arp", "1", NULL }));
	test_bond_compare_options (TRUE,
	                           ((const char *[]){ "num_grat_arp", "3", NULL }),
	                           ((const char *[]){ "num_unsol_na", "3", NULL }));
	test_bond_compare_options (TRUE,
	                           ((const char *[]){ "num_grat_arp", "4", NULL }),
	                           ((const char *[]){ "num_unsol_na", "4", "num_grat_arp", "4", NULL }));
}

static void
test_bond_normalize_options (const char **opts1, const char **opts2)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingBond *s_bond;
	GError *error = NULL;
	gboolean success;
	const char **p;
	int num = 0;

	create_bond_connection (&con, &s_bond);

	for (p = opts1; p[0] && p[1]; p += 2)
		g_assert (nm_setting_bond_add_option (s_bond, p[0], p[1]));

	nmtst_assert_connection_verifies_and_normalizable (con);
	nmtst_connection_normalize (con);
	success = nm_setting_verify ((NMSetting *) s_bond, con, &error);
	nmtst_assert_success (success, error);

	for (p = opts2; p[0] && p[1]; p += 2) {
		g_assert_cmpstr (nm_setting_bond_get_option_by_name (s_bond, p[0]), ==, p[1]);
		num++;
	}

	g_assert_cmpint (num, ==, nm_setting_bond_get_num_options (s_bond));
}

static void
test_bond_normalize (void)
{
	test_bond_normalize_options (
		((const char *[]){ "mode", "802.3ad", "ad_actor_system", "00:02:03:04:05:06", NULL }),
		((const char *[]){ "mode", "802.3ad", "ad_actor_system", "00:02:03:04:05:06", NULL }));
	test_bond_normalize_options (
		((const char *[]){ "mode", "1", "miimon", "1", NULL }),
		((const char *[]){ "mode", "active-backup", "miimon", "1", NULL }));
	test_bond_normalize_options (
		((const char *[]){ "mode", "balance-alb", "tlb_dynamic_lb", "1", NULL }),
		((const char *[]){ "mode", "balance-alb", NULL }));
	test_bond_normalize_options (
		((const char *[]){ "mode", "balance-tlb", "tlb_dynamic_lb", "1", NULL }),
		((const char *[]){ "mode", "balance-tlb", "tlb_dynamic_lb", "1", NULL }));
	test_bond_normalize_options (
		((const char *[]){ "mode", "balance-rr", "ad_actor_sys_prio", "4", "packets_per_slave", "3", NULL }),
		((const char *[]){ "mode", "balance-rr", "packets_per_slave", "3", NULL }));
}

/*****************************************************************************/

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

/*****************************************************************************/

static void
_test_team_config_sync (const char *team_config,
                        int notify_peer_count,
                        int notify_peers_interval,
                        int mcast_rejoin_count,
                        int mcast_rejoin_interval,
                        char *runner,
                        char *runner_hwaddr_policy,      /* activebackup */
                        GPtrArray *runner_tx_hash,       /* lacp, loadbalance */
                        char *runner_tx_balancer,        /* lacp, loadbalance */
                        int runner_tx_balancer_interval, /* lacp, loadbalance */
                        gboolean runner_active,          /* lacp */
                        gboolean runner_fast_rate,       /* lacp */
                        int runner_sys_prio,             /* lacp */
                        int runner_min_ports,            /* lacp */
                        char *runner_agg_select_policy,  /* lacp */
                        GPtrArray *link_watchers)
{
	gs_unref_object NMSettingTeam *s_team = NULL;
	guint i, j;
	gboolean found;

	s_team = (NMSettingTeam *) nm_setting_team_new ();
	g_assert (s_team);

	g_object_set (s_team, NM_SETTING_TEAM_CONFIG, team_config, NULL);
	g_assert (nm_setting_team_get_notify_peers_count (s_team) == notify_peer_count);
	g_assert (nm_setting_team_get_notify_peers_interval (s_team) == notify_peers_interval);
	g_assert (nm_setting_team_get_mcast_rejoin_count (s_team) == mcast_rejoin_count);
	g_assert (nm_setting_team_get_mcast_rejoin_interval (s_team) == mcast_rejoin_interval);
	g_assert (nm_setting_team_get_runner_tx_balancer_interval (s_team) == runner_tx_balancer_interval);
	g_assert (nm_setting_team_get_runner_active (s_team) == runner_active);
	g_assert (nm_setting_team_get_runner_fast_rate (s_team) == runner_fast_rate);
	g_assert (nm_setting_team_get_runner_sys_prio (s_team) == runner_sys_prio);
	g_assert (nm_setting_team_get_runner_min_ports (s_team) == runner_min_ports);
	g_assert (nm_streq0 (nm_setting_team_get_runner (s_team), runner));
	g_assert (nm_streq0 (nm_setting_team_get_runner_hwaddr_policy (s_team), runner_hwaddr_policy));
	g_assert (nm_streq0 (nm_setting_team_get_runner_tx_balancer (s_team), runner_tx_balancer));
	g_assert (nm_streq0 (nm_setting_team_get_runner_agg_select_policy (s_team), runner_agg_select_policy));

	if (runner_tx_hash) {
		g_assert (runner_tx_hash->len == nm_setting_team_get_num_runner_tx_hash (s_team));
		for (i = 0; i < runner_tx_hash->len; i++) {
			found = FALSE;
			for (j = 0; j < nm_setting_team_get_num_runner_tx_hash (s_team); j++) {
				if (nm_streq0 (nm_setting_team_get_runner_tx_hash (s_team, j),
				               runner_tx_hash->pdata[i])) {
					found = TRUE;
					break;
				}
			}
			g_assert (found);
		}
	}

	if (link_watchers) {
		g_assert (link_watchers->len == nm_setting_team_get_num_link_watchers (s_team));
		for (i = 0; i < link_watchers->len; i++) {
			found = FALSE;
			for (j = 0; j < nm_setting_team_get_num_link_watchers (s_team); j++) {
				if (nm_team_link_watcher_equal (link_watchers->pdata[i],
				                                nm_setting_team_get_link_watcher (s_team, j))) {
					found = TRUE;
					break;
				}
			}
			g_assert (found);
		}
	}

	g_assert (nm_setting_verify ((NMSetting *) s_team, NULL, NULL));
}


static void
test_runner_roundrobin_sync_from_config (void)
{
	_test_team_config_sync ("",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_ROUNDROBIN,
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_broadcast_sync_from_config (void)
{
	_test_team_config_sync ("{\"runner\": {\"name\": \"broadcast\"}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_BROADCAST,
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_random_sync_from_config (void)
{
	_test_team_config_sync ("{\"runner\": {\"name\": \"random\"}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_RANDOM,
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_activebackup_sync_from_config (void)
{
	_test_team_config_sync ("{\"runner\": {\"name\": \"activebackup\"}}",
	                        NM_SETTING_TEAM_NOTIFY_PEERS_COUNT_ACTIVEBACKUP_DEFAULT, 0,
	                        NM_SETTING_TEAM_NOTIFY_MCAST_COUNT_ACTIVEBACKUP_DEFAULT, 0,
	                        NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP,
	                        NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_DEFAULT,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_loadbalance_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *tx_hash = NULL;

	tx_hash = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);
	g_ptr_array_add (tx_hash, g_strdup ("eth"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv4"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv6"));

	_test_team_config_sync ("{\"runner\": {\"name\": \"loadbalance\"}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                        NULL,
	                        tx_hash, NULL, NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);

	_test_team_config_sync ("{\"runner\": {\"name\": \"loadbalance\", "
	                        "\"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"]}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                        NULL,
	                        tx_hash, NULL, NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);

	_test_team_config_sync ("{\"runner\": {\"name\": \"loadbalance\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"], "
	                        "\"tx_balancer\": {\"name\": \"basic\", \"balancing_interval\": 30}}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                        NULL,
	                        tx_hash, "basic", 30,
	                        FALSE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_lacp_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *tx_hash = NULL;

	tx_hash = g_ptr_array_new_with_free_func ((GDestroyNotify) g_free);
	g_ptr_array_add (tx_hash, g_strdup ("eth"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv4"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv6"));

	_test_team_config_sync ("{\"runner\": {\"name\": \"lacp\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"]}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_LACP,
	                        NULL,
	                        tx_hash, NULL, NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT,
	                        TRUE, FALSE, NM_SETTING_TEAM_RUNNER_SYS_PRIO_DEFAULT, 0,
	                        NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_DEFAULT,
	                        NULL);

	_test_team_config_sync ("{\"runner\": {\"name\": \"lacp\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"], "
	                        "\"active\": false, \"fast_rate\": true, \"sys_prio\": 10, \"min_ports\": 5, "
	                        "\"agg_select_policy\": \"port_config\"}}",
	                        0, 0, 0, 0,
	                        NM_SETTING_TEAM_RUNNER_LACP,
	                        NULL,
	                        tx_hash, NULL, NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT,
	                        FALSE, TRUE, 10, 5, "port_config",
	                        NULL);
}

static void
test_watcher_ethtool_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
	g_ptr_array_add (link_watchers, nm_team_link_watcher_new_ethtool (0, 0, NULL));
	_test_team_config_sync ("{\"link_watch\": {\"name\": \"ethtool\"}}",
	                        0, 0, 0, 0,
	                        "roundrobin",
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        link_watchers);
}

static void
test_watcher_nsna_ping_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
	g_ptr_array_add (link_watchers, nm_team_link_watcher_new_nsna_ping (0, 0, 3, "target.host", NULL));
	_test_team_config_sync ("{\"link_watch\": {\"name\": \"nsna_ping\", \"target_host\": \"target.host\"}}",
	                        0, 0, 0, 0,
	                        "roundrobin",
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        link_watchers);
}

static void
test_watcher_arp_ping_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
	g_ptr_array_add (link_watchers,
	                 nm_team_link_watcher_new_arp_ping (0, 0, 3, "target.host", "source.host", 0, NULL));
	_test_team_config_sync ("{\"link_watch\": {\"name\": \"arp_ping\", \"target_host\": \"target.host\", "
	                        "\"source_host\": \"source.host\"}}",
	                        0, 0, 0, 0,
	                        "roundrobin",
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        link_watchers);
}

static void
test_multiple_watchers_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
	g_ptr_array_add (link_watchers, nm_team_link_watcher_new_ethtool (2, 4, NULL));
	g_ptr_array_add (link_watchers, nm_team_link_watcher_new_nsna_ping (3, 6, 9, "target.host", NULL));
	g_ptr_array_add (link_watchers,
	                 nm_team_link_watcher_new_arp_ping (5, 10, 15, "target.host", "source.host",
	                                                      NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE
	                                                    | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE
	                                                    | NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS,
	                                                    NULL));
	_test_team_config_sync ("{\"link_watch\": ["
	                        "{\"name\": \"ethtool\", \"delay_up\": 2, \"delay_down\": 4}, "
	                        "{\"name\": \"arp_ping\", \"init_wait\": 5, \"interval\": 10, \"missed_max\": 15, "
	                        "\"target_host\": \"target.host\", \"source_host\": \"source.host\", "
	                        "\"validate_active\": true, \"validate_inactive\": true, \"send_always\": true}, "
	                        "{\"name\": \"nsna_ping\", \"init_wait\": 3, \"interval\": 6, \"missed_max\": 9, "
	                        "\"target_host\": \"target.host\"}]}",
	                        0, 0, 0, 0,
	                        "roundrobin",
	                        NULL,
	                        NULL, NULL, -1,
	                        FALSE, FALSE, -1, -1, NULL,
	                        link_watchers);
}

/*****************************************************************************/

static void
_test_team_port_config_sync (const char *team_port_config,
                             int queue_id,
                             int prio,
                             gboolean sticky,
                             int lacp_prio,
                             int lacp_key,
                             GPtrArray *link_watchers)
{
	gs_unref_object NMSettingTeamPort *s_team_port = NULL;
	guint i, j;
	gboolean found;

	s_team_port = (NMSettingTeamPort *) nm_setting_team_port_new ();
	g_assert (s_team_port);

	g_object_set (s_team_port, NM_SETTING_TEAM_CONFIG, team_port_config, NULL);
	g_assert (nm_setting_team_port_get_queue_id (s_team_port) == queue_id);
	g_assert (nm_setting_team_port_get_prio (s_team_port) == prio);
	g_assert (nm_setting_team_port_get_sticky (s_team_port) == sticky);
	g_assert (nm_setting_team_port_get_lacp_prio (s_team_port) == lacp_prio);
	g_assert (nm_setting_team_port_get_lacp_key (s_team_port) == lacp_key);

	if (link_watchers) {
		g_assert (link_watchers->len == nm_setting_team_port_get_num_link_watchers (s_team_port));
		for (i = 0; i < link_watchers->len; i++) {
			found = FALSE;
			for (j = 0; j < nm_setting_team_port_get_num_link_watchers (s_team_port); j++) {
				if (nm_team_link_watcher_equal (link_watchers->pdata[i],
				                                nm_setting_team_port_get_link_watcher (s_team_port,
				                                                                       j))) {
					found = TRUE;
					break;
				}
			}
			g_assert (found);
		}
	}

	g_assert (nm_setting_verify ((NMSetting *) s_team_port, NULL, NULL));
}


static void
test_team_port_default (void)
{
	_test_team_port_config_sync ("", -1, 0, FALSE, 255, 0, NULL);
}

static void
test_team_port_queue_id (void)
{
	_test_team_port_config_sync ("{\"queue_id\": 3}",
	                             3, 0, FALSE, 255, 0, NULL);
	_test_team_port_config_sync ("{\"queue_id\": 0}",
	                             0, 0, FALSE, 255, 0, NULL);
}

static void
test_team_port_prio (void)
{
	_test_team_port_config_sync ("{\"prio\": 6}",
	                             -1, 6, FALSE, 255, 0, NULL);
	_test_team_port_config_sync ("{\"prio\": 0}",
	                             -1, 0, FALSE, 255, 0, NULL);
}

static void
test_team_port_sticky (void)
{
	_test_team_port_config_sync ("{\"sticky\": true}",
	                             -1, 0, TRUE, 255, 0, NULL);
	_test_team_port_config_sync ("{\"sticky\": false}",
	                             -1, 0, FALSE, 255, 0, NULL);
}

static void
test_team_port_lacp_prio (void)
{
	_test_team_port_config_sync ("{\"lacp_prio\": 9}",
	                             -1, 0, FALSE, 9, 0, NULL);
	_test_team_port_config_sync ("{\"lacp_prio\": 0}",
	                             -1, 0, FALSE, 0, 0, NULL);
}

static void
test_team_port_lacp_key (void)
{
	_test_team_port_config_sync ("{\"lacp_key\": 12}",
	                             -1, 0, FALSE, 255, 12, NULL);
	_test_team_port_config_sync ("{\"lacp_key\": 0}",
	                             -1, 0, FALSE, 255, 0, NULL);
}

static void
test_team_port_full_config (void)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
	g_ptr_array_add (link_watchers,
	                 nm_team_link_watcher_new_arp_ping (0, 3, 3, "1.2.3.2", "1.2.3.1",
	                                                    NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE,
	                                                    NULL));
	g_ptr_array_add (link_watchers,
	                 nm_team_link_watcher_new_arp_ping (1, 1, 0, "1.2.3.4", "1.2.3.1",
	                                                     NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS,
	                                                     NULL));

	_test_team_port_config_sync ("{\"queue_id\": 10, \"prio\": 20, \"sticky\": true, \"lacp_prio\": 30, "
	                             "\"lacp_key\": 40, \"link_watch\": ["
	                             "{\"name\": \"arp_ping\", \"interval\": 3, \"target_host\": \"1.2.3.2\", "
	                             "\"source_host\": \"1.2.3.1\", \"validate_inactive\": true}, "
	                             "{\"name\": \"arp_ping\", \"init_wait\": 1, \"interval\": 1, "
	                             "\"target_host\": \"1.2.3.4\", \"source_host\": \"1.2.3.1\", "
	                             "\"send_always\": true}]}",
	                             10, 20, true, 30, 40, NULL);
}

/*****************************************************************************/

static void
test_tc_config_qdisc (void)
{
	NMTCQdisc *qdisc1, *qdisc2;
	char *str;
	GError *error = NULL;

	qdisc1 = nm_tc_qdisc_new ("fq_codel", TC_H_ROOT, &error);
	nmtst_assert_success (qdisc1, error);

	qdisc2 = nm_tc_qdisc_new ("fq_codel", TC_H_ROOT, &error);
	nmtst_assert_success (qdisc2, error);

	g_assert (nm_tc_qdisc_equal (qdisc1, qdisc2));

	nm_tc_qdisc_unref (qdisc2);
	qdisc2 = nm_tc_qdisc_dup (qdisc1);

	g_assert (nm_tc_qdisc_equal (qdisc1, qdisc2));

	g_assert_cmpstr (nm_tc_qdisc_get_kind (qdisc1), ==, "fq_codel");
	g_assert (nm_tc_qdisc_get_handle (qdisc1) == TC_H_UNSPEC);
	g_assert (nm_tc_qdisc_get_parent (qdisc1) == TC_H_ROOT);

	str = nm_utils_tc_qdisc_to_str (qdisc1, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "root fq_codel");
	g_free (str);

	nm_tc_qdisc_unref (qdisc1);
	qdisc1 = nm_tc_qdisc_new ("ingress", TC_H_INGRESS, &error);
	nmtst_assert_success (qdisc1, error);

	g_assert (!nm_tc_qdisc_equal (qdisc1, qdisc2));

	str = nm_utils_tc_qdisc_to_str (qdisc1, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "ingress");
	g_free (str);

	nm_tc_qdisc_unref (qdisc1);
	qdisc1 = nm_utils_tc_qdisc_from_str ("narodil sa kristus pan",  &error);
	nmtst_assert_no_success (qdisc1, error);
	g_clear_error (&error);

	qdisc1 = nm_utils_tc_qdisc_from_str ("handle 1234 parent fff1:1 pfifo_fast",  &error);
	nmtst_assert_success (qdisc1, error);

	g_assert_cmpstr (nm_tc_qdisc_get_kind (qdisc1), ==, "pfifo_fast");
	g_assert (nm_tc_qdisc_get_handle (qdisc1) == TC_H_MAKE (0x1234 << 16, 0x0000));
	g_assert (nm_tc_qdisc_get_parent (qdisc1) == TC_H_MAKE (0xfff1 << 16, 0x0001));

	str = nm_utils_tc_qdisc_to_str (qdisc1, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "parent fff1:1 handle 1234: pfifo_fast");
	g_free (str);

	nm_tc_qdisc_unref (qdisc2);
	str = nm_utils_tc_qdisc_to_str (qdisc1, &error);
	nmtst_assert_success (str, error);
	qdisc2 = nm_utils_tc_qdisc_from_str (str, &error);
	nmtst_assert_success (qdisc2, error);
	g_free (str);

	g_assert (nm_tc_qdisc_equal (qdisc1, qdisc2));

	nm_tc_qdisc_unref (qdisc1);
	nm_tc_qdisc_unref (qdisc2);
}

static void
test_tc_config_action (void)
{
	NMTCAction *action1, *action2;
	char *str;
	GError *error = NULL;

	action1 = nm_tc_action_new ("drop", &error);
	nmtst_assert_success (action1, error);
	action2 = nm_tc_action_new ("drop", &error);
	nmtst_assert_success (action2, error);

	g_assert (nm_tc_action_equal (action1, action2));
	g_assert_cmpstr (nm_tc_action_get_kind (action1), ==, "drop");

	nm_tc_action_unref (action1);
	action1 = nm_tc_action_new ("simple", &error);
	nmtst_assert_success (action1, error);
	nm_tc_action_set_attribute (action1, "sdata", g_variant_new_bytestring ("Hello"));

	g_assert (!nm_tc_action_equal (action1, action2));

	str = nm_utils_tc_action_to_str (action1, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "simple sdata Hello");
	g_free (str);

	str = nm_utils_tc_action_to_str (action2, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "drop");
	g_free (str);

	nm_tc_action_unref (action2);
	action2 = nm_tc_action_dup (action1);

	g_assert (nm_tc_action_equal (action1, action2));

	nm_tc_action_unref (action1);
	action1 = nm_utils_tc_action_from_str ("narodil sa kristus pan",  &error);
	nmtst_assert_no_success (action1, error);
	g_clear_error (&error);

	action1 = nm_utils_tc_action_from_str ("simple sdata Hello",  &error);
	nmtst_assert_success (action1, error);

	g_assert_cmpstr (nm_tc_action_get_kind (action1), ==, "simple");
	g_assert_cmpstr (g_variant_get_bytestring (nm_tc_action_get_attribute (action1, "sdata")), ==, "Hello");

	nm_tc_action_unref (action1);
	nm_tc_action_unref (action2);
}

static void
test_tc_config_tfilter (void)
{
	NMTCAction *action1;
	NMTCTfilter *tfilter1, *tfilter2;
	char *str;
	GError *error = NULL;

	tfilter1 = nm_tc_tfilter_new ("matchall",
	                              TC_H_MAKE (0x1234 << 16, 0x0000),
	                              &error);
	nmtst_assert_success (tfilter1, error);

	tfilter2 = nm_tc_tfilter_new ("matchall",
	                              TC_H_MAKE (0x1234 << 16, 0x0000),
	                              &error);
	nmtst_assert_success (tfilter2, error);

	g_assert (nm_tc_tfilter_equal (tfilter1, tfilter2));

	action1 = nm_tc_action_new ("simple", &error);
	nmtst_assert_success (action1, error);
	nm_tc_action_set_attribute (action1, "sdata", g_variant_new_bytestring ("Hello"));
	nm_tc_tfilter_set_action (tfilter1, action1);
	nm_tc_action_unref (action1);

	g_assert (!nm_tc_tfilter_equal (tfilter1, tfilter2));

	str = nm_utils_tc_tfilter_to_str (tfilter1, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "parent 1234: matchall action simple sdata Hello");
	g_free (str);

	nm_tc_tfilter_unref (tfilter2);
	tfilter2 = nm_tc_tfilter_dup (tfilter1);

	g_assert (nm_tc_tfilter_equal (tfilter1, tfilter2));

	nm_tc_tfilter_unref (tfilter1);
	tfilter1 = nm_utils_tc_tfilter_from_str ("narodil sa kristus pan",  &error);
	nmtst_assert_no_success (tfilter1, error);
	g_clear_error (&error);

	str = nm_utils_tc_tfilter_to_str (tfilter2, &error);
	nmtst_assert_success (str, error);
	tfilter1 = nm_utils_tc_tfilter_from_str (str, &error);
	nmtst_assert_success (tfilter1, error);
	g_free (str);

	g_assert (nm_tc_tfilter_equal (tfilter1, tfilter2));

	nm_tc_tfilter_unref (tfilter1);
	nm_tc_tfilter_unref (tfilter2);
}

static void
test_tc_config_setting (void)
{
	gs_unref_object NMSettingTCConfig *s_tc = NULL;
	NMTCQdisc *qdisc1, *qdisc2;
	GError *error = NULL;

	s_tc = (NMSettingTCConfig *) nm_setting_tc_config_new ();

	qdisc1 = nm_tc_qdisc_new ("fq_codel", TC_H_ROOT, &error);
	nmtst_assert_success (qdisc1, error);

	qdisc2 = nm_tc_qdisc_new ("pfifo_fast",
	                          TC_H_MAKE (0xfff1 << 16, 0x0001),
	                          &error);
	nmtst_assert_success (qdisc2, error);
	nm_tc_qdisc_set_handle (qdisc2, TC_H_MAKE (0x1234 << 16, 0x0000));

	g_assert (nm_setting_tc_config_get_num_qdiscs (s_tc) == 0);
	g_assert (nm_setting_tc_config_add_qdisc (s_tc, qdisc1) == TRUE);
	g_assert (nm_setting_tc_config_get_num_qdiscs (s_tc) == 1);
	g_assert (nm_setting_tc_config_get_qdisc (s_tc, 0) != NULL);
	g_assert (nm_setting_tc_config_remove_qdisc_by_value (s_tc, qdisc2) == FALSE);
	g_assert (nm_setting_tc_config_add_qdisc (s_tc, qdisc2) == TRUE);
	g_assert (nm_setting_tc_config_get_num_qdiscs (s_tc) == 2);
	g_assert (nm_setting_tc_config_remove_qdisc_by_value (s_tc, qdisc1) == TRUE);
	g_assert (nm_setting_tc_config_get_num_qdiscs (s_tc) == 1);
	nm_setting_tc_config_clear_qdiscs (s_tc);
	g_assert (nm_setting_tc_config_get_num_qdiscs (s_tc) == 0);

	nm_tc_qdisc_unref (qdisc1);
	nm_tc_qdisc_unref (qdisc2);
}

static void
test_tc_config_dbus (void)
{
	NMConnection *connection1, *connection2;
	NMSetting *s_tc;
	NMTCQdisc *qdisc1, *qdisc2;
	NMTCTfilter *tfilter1, *tfilter2;
	NMTCAction *action;
	GVariant *dbus, *tc_dbus, *var1, *var2;
	GError *error = NULL;
	gboolean success;

	connection1 = nmtst_create_minimal_connection ("dummy",
	                                               NULL,
	                                               NM_SETTING_DUMMY_SETTING_NAME,
	                                               NULL);

	s_tc = nm_setting_tc_config_new ();

	qdisc1 = nm_tc_qdisc_new ("fq_codel", TC_H_ROOT, &error);
	nmtst_assert_success (qdisc1, error);
	nm_tc_qdisc_set_handle (qdisc1, TC_H_MAKE (0x1234 << 16, 0x0000));
	nm_setting_tc_config_add_qdisc (NM_SETTING_TC_CONFIG (s_tc), qdisc1);

	qdisc2 = nm_tc_qdisc_new ("ingress", TC_H_INGRESS, &error);
	nmtst_assert_success (qdisc2, error);
	nm_tc_qdisc_set_handle (qdisc2, TC_H_MAKE (TC_H_INGRESS, 0));
	nm_setting_tc_config_add_qdisc (NM_SETTING_TC_CONFIG (s_tc), qdisc2);

	tfilter1 = nm_tc_tfilter_new ("matchall",
	                              TC_H_MAKE (0x1234 << 16, 0x0000),
	                              &error);
	nmtst_assert_success (tfilter1, error);
	action = nm_tc_action_new ("drop", &error);
	nmtst_assert_success (action, error);
	nm_tc_tfilter_set_action (tfilter1, action);
	nm_tc_action_unref (action);
	nm_setting_tc_config_add_tfilter (NM_SETTING_TC_CONFIG (s_tc), tfilter1);
	nm_tc_tfilter_unref (tfilter1);

	tfilter2 = nm_tc_tfilter_new ("matchall",
	                              TC_H_MAKE (TC_H_INGRESS, 0),
	                              &error);
	nmtst_assert_success (tfilter2, error);
	action = nm_tc_action_new ("simple", &error);
	nmtst_assert_success (action, error);
	nm_tc_action_set_attribute (action, "sdata", g_variant_new_bytestring ("Hello"));
	nm_tc_tfilter_set_action (tfilter2, action);
	nm_tc_action_unref (action);
	nm_setting_tc_config_add_tfilter (NM_SETTING_TC_CONFIG (s_tc), tfilter2);
	nm_tc_tfilter_unref (tfilter2);

	nm_connection_add_setting (connection1, s_tc);

	dbus = nm_connection_to_dbus (connection1, NM_CONNECTION_SERIALIZE_ALL);

	tc_dbus = g_variant_lookup_value (dbus, "tc", G_VARIANT_TYPE_VARDICT);
	g_assert (tc_dbus);

	var1 = g_variant_lookup_value (tc_dbus, "qdiscs", G_VARIANT_TYPE ("aa{sv}"));
	var2 = g_variant_new_parsed ("[{'kind':   <'fq_codel'>,"
	                             "  'handle': <uint32 0x12340000>,"
	                             "  'parent': <uint32 0xffffffff>},"
	                             " {'kind':   <'ingress'>,"
	                             "  'handle': <uint32 0xffff0000>,"
	                             "  'parent': <uint32 0xfffffff1>}]");
	g_assert (g_variant_equal (var1, var2));
	g_variant_unref (var1);
	g_variant_unref (var2);

	var1 = g_variant_lookup_value (tc_dbus, "tfilters", G_VARIANT_TYPE ("aa{sv}"));
	var2 = g_variant_new_parsed ("[{'kind':   <'matchall'>,"
	                             "  'handle': <uint32 0>,"
	                             "  'parent': <uint32 0x12340000>,"
	                             "  'action': <{'kind': <'drop'>}>},"
	                             " {'kind':   <'matchall'>,"
	                             "  'handle': <uint32 0>,"
	                             "  'parent': <uint32 0xffff0000>,"
	                             "  'action': <{'kind':  <'simple'>,"
	                             "              'sdata': <b'Hello'>}>}]");
	g_variant_unref (var1);
	g_variant_unref (var2);

	g_variant_unref (tc_dbus);

	connection2 = nm_simple_connection_new ();
	success = nm_connection_replace_settings (connection2, dbus, &error);
	nmtst_assert_success (success, error);

	g_assert (nm_connection_diff (connection1, connection2, NM_SETTING_COMPARE_FLAG_EXACT, NULL));

	g_variant_unref (dbus);

	nm_tc_qdisc_unref (qdisc1);
	nm_tc_qdisc_unref (qdisc2);

	g_object_unref (connection1);
	g_object_unref (connection2);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_data_func ("/libnm/setting-8021x/key-and-cert",
	                      "test_key_and_cert.pem, test",
	                      test_8021x);
	g_test_add_data_func ("/libnm/setting-8021x/key-only",
	                      "test-key-only.pem, test",
	                      test_8021x);
	g_test_add_data_func ("/libnm/setting-8021x/pkcs8-enc-key",
	                      "pkcs8-enc-key.pem, 1234567890",
	                      test_8021x);
	g_test_add_data_func ("/libnm/setting-8021x/pkcs12",
	                      "test-cert.p12, test",
	                      test_8021x);

	g_test_add_func ("/libnm/settings/bond/verify", test_bond_verify);
	g_test_add_func ("/libnm/settings/bond/compare", test_bond_compare);
	g_test_add_func ("/libnm/settings/bond/normalize", test_bond_normalize);

	g_test_add_func ("/libnm/settings/dcb/flags-valid", test_dcb_flags_valid);
	g_test_add_func ("/libnm/settings/dcb/flags-invalid", test_dcb_flags_invalid);
	g_test_add_func ("/libnm/settings/dcb/app-priorities", test_dcb_app_priorities);
	g_test_add_func ("/libnm/settings/dcb/priorities", test_dcb_priorities_valid);
	g_test_add_func ("/libnm/settings/dcb/bandwidth-sums", test_dcb_bandwidth_sums);

	g_test_add_func ("/libnm/settings/tc_config/qdisc", test_tc_config_qdisc);
	g_test_add_func ("/libnm/settings/tc_config/action", test_tc_config_action);
	g_test_add_func ("/libnm/settings/tc_config/tfilter", test_tc_config_tfilter);
	g_test_add_func ("/libnm/settings/tc_config/setting", test_tc_config_setting);
	g_test_add_func ("/libnm/settings/tc_config/dbus", test_tc_config_dbus);

#if WITH_JANSSON
	g_test_add_func ("/libnm/settings/team/sync_runner_from_config_roundrobin",
	                 test_runner_roundrobin_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_runner_from_config_broadcast",
	                 test_runner_broadcast_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_runner_from_config_random",
	                 test_runner_random_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_runner_from_config_activebackup",
	                 test_runner_activebackup_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_runner_from_config_loadbalance",
	                 test_runner_loadbalance_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_runner_from_config_lacp",
	                 test_runner_lacp_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_watcher_from_config_ethtool",
	                 test_watcher_ethtool_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_watcher_from_config_nsna_ping",
	                 test_watcher_nsna_ping_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_watcher_from_config_arp_ping",
	                 test_watcher_arp_ping_sync_from_config);
	g_test_add_func ("/libnm/settings/team/sync_watcher_from_config_all",
	                 test_multiple_watchers_sync_from_config);

	g_test_add_func ("/libnm/settings/team-port/sync_from_config_defaults", test_team_port_default);
	g_test_add_func ("/libnm/settings/team-port/sync_from_config_queue_id", test_team_port_queue_id);
	g_test_add_func ("/libnm/settings/team-port/sync_from_config_prio", test_team_port_prio);
	g_test_add_func ("/libnm/settings/team-port/sync_from_config_sticky", test_team_port_sticky);
	g_test_add_func ("/libnm/settings/team-port/sync_from_config_lacp_prio", test_team_port_lacp_prio);
	g_test_add_func ("/libnm/settings/team-port/sync_from_config_lacp_key", test_team_port_lacp_key);
	g_test_add_func ("/libnm/settings/team-port/sycn_from_config_full", test_team_port_full_config);

#endif

	return g_test_run ();
}
