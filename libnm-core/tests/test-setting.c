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

#include <string.h>

#include "nm-utils.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bond.h"
#include "nm-setting-dcb.h"
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

	return g_test_run ();
}
