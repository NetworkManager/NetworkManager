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
#include <net/if.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-core-internal.h"
#include "nm-setting-8021x.h"
#include "nm-setting-bond.h"
#include "nm-setting-dcb.h"
#include "nm-setting-ethtool.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"
#include "nm-setting-tc-config.h"
#include "nm-setting-dummy.h"
#include "nm-connection.h"
#include "nm-simple-connection.h"
#include "nm-setting-connection.h"
#include "nm-errors.h"
#include "nm-keyfile-internal.h"

#include "nm-utils/nm-test-utils.h"

#define TEST_CERT_DIR NM_BUILD_SRCDIR"/libnm-core/tests/certs"

/*****************************************************************************/

/* assert that the define is just a plain integer (boolean). */

G_STATIC_ASSERT (   (WITH_JSON_VALIDATION) == 1
                 || (WITH_JSON_VALIDATION) == 0);

_nm_unused static const int _with_json_validation = WITH_JSON_VALIDATION;

/*****************************************************************************/

/* converts @dict to a connection. In this case, @dict must be good, without warnings, so that
 * NM_SETTING_PARSE_FLAGS_STRICT and NM_SETTING_PARSE_FLAGS_BEST_EFFORT yield the exact same results. */
static NMConnection *
_connection_new_from_dbus_strict (GVariant *dict,
                                  gboolean normalize)
{
	gs_unref_object NMConnection *con_x_0 = NULL;
	gs_unref_object NMConnection *con_x_s = NULL;
	gs_unref_object NMConnection *con_x_e = NULL;
	gs_unref_object NMConnection *con_n_0 = NULL;
	gs_unref_object NMConnection *con_n_s = NULL;
	gs_unref_object NMConnection *con_n_e = NULL;
	gs_free_error GError *error = NULL;
	guint i;

	g_assert (g_variant_is_of_type (dict, NM_VARIANT_TYPE_CONNECTION));

	con_x_0 = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_NONE, &error);
	nmtst_assert_success (NM_IS_CONNECTION (con_x_0), error);

	con_x_s = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_STRICT, &error);
	nmtst_assert_success (NM_IS_CONNECTION (con_x_s), error);

	con_x_e = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, &error);
	nmtst_assert_success (NM_IS_CONNECTION (con_x_e), error);

	con_n_0 = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_NORMALIZE, &error);
	nmtst_assert_success (NM_IS_CONNECTION (con_n_0), error);

	con_n_s = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_STRICT | NM_SETTING_PARSE_FLAGS_NORMALIZE, &error);
	nmtst_assert_success (NM_IS_CONNECTION (con_n_s), error);

	con_n_e = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT | NM_SETTING_PARSE_FLAGS_NORMALIZE, &error);
	nmtst_assert_success (NM_IS_CONNECTION (con_n_e), error);

	nmtst_assert_connection_verifies (con_x_0);
	nmtst_assert_connection_verifies (con_x_e);
	nmtst_assert_connection_verifies (con_x_s);

	nmtst_assert_connection_verifies_without_normalization (con_n_0);
	nmtst_assert_connection_verifies_without_normalization (con_n_e);
	nmtst_assert_connection_verifies_without_normalization (con_n_s);

	/* randomly compare some pairs that we created. They must all be equal,
	 * after accounting for normalization. */
	for (i = 0; i < 10; i++) {
		NMConnection *cons[] = { con_x_0, con_x_s, con_x_e, con_n_0, con_n_s, con_n_e };
		guint idx_a = (nmtst_get_rand_uint32 () % G_N_ELEMENTS (cons));
		guint idx_b = (nmtst_get_rand_uint32 () % G_N_ELEMENTS (cons));
		gboolean normalize_a, normalize_b;

		if (idx_a <= 2 && idx_b <= 2) {
			normalize_a = nmtst_get_rand_bool ();
			normalize_b = normalize_a;
		} else if (idx_a > 2 && idx_b > 2) {
			normalize_a = nmtst_get_rand_bool ();
			normalize_b = nmtst_get_rand_bool ();
		} else {
			normalize_a = (idx_a <= 2) ? TRUE : nmtst_get_rand_bool ();
			normalize_b = (idx_b <= 2) ? TRUE : nmtst_get_rand_bool ();
		}
		nmtst_assert_connection_equals (cons[idx_a], normalize_a, cons[idx_b], normalize_b);
	}

	return (normalize)
	       ? g_steal_pointer (&con_x_0)
	       : g_steal_pointer (&con_n_0);
}

/*****************************************************************************/

static char *
_create_random_ipaddr (int addr_family, gboolean as_service)
{
	char delimiter = as_service ? ':' : '/';
	int num;

	if (addr_family == AF_UNSPEC)
		addr_family = nmtst_rand_select (AF_INET, AF_INET6);

	g_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	if (as_service)
		num = (nmtst_get_rand_uint32 () % 1000) + 30000;
	else
		num = addr_family == AF_INET ? 32 : 128;

	if (addr_family == AF_INET)
		return g_strdup_printf ("192.168.%u.%u%c%d", nmtst_get_rand_uint32 () % 256, nmtst_get_rand_uint32 () % 256, delimiter, num);
	else
		return g_strdup_printf ("a:b:c::%02x:%02x%c%d", nmtst_get_rand_uint32 () % 256, nmtst_get_rand_uint32 () % 256, delimiter, num);
}

/*****************************************************************************/

static void
compare_blob_data (const char *test,
                   const char *key_path,
                   GBytes *key)
{
	gs_free char *contents = NULL;
	gsize len = 0;
	GError *error = NULL;
	gboolean success;

	g_assert (key && g_bytes_get_size (key) > 0);

	success = g_file_get_contents (key_path, &contents, &len, &error);
	nmtst_assert_success (success, error);

	g_assert_cmpmem (contents, len, g_bytes_get_data (key, NULL), g_bytes_get_size (key));
}

static void
check_scheme_path (GBytes *value, const char *path)
{
	const guint8 *p;
	gsize l;

	g_assert (value);

	p = g_bytes_get_data (value, &l);
	g_assert_cmpint (l, ==, strlen (path) + NM_STRLEN (NM_SETTING_802_1X_CERT_SCHEME_PREFIX_PATH) + 1);
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
	_test_verify_options (NM_MAKE_STRV (__VA_ARGS__), exp)

static void
_test_verify_options (const char *const *options,
                      gboolean expected_result)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingBond *s_bond;
	GError *error = NULL;
	gboolean success;
	const char *const *option;

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

	NMTST_EXPECT ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_APP_FCOE_FLAGS, nm_setting_dcb_get_app_fcoe_flags, 0x332523);
	g_test_assert_expected_messages ();

	NMTST_EXPECT ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_APP_ISCSI_FLAGS, nm_setting_dcb_get_app_iscsi_flags, 0xFF);
	g_test_assert_expected_messages ();

	NMTST_EXPECT ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_APP_FIP_FLAGS, nm_setting_dcb_get_app_fip_flags, 0x1111);
	g_test_assert_expected_messages ();

	NMTST_EXPECT ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
	TEST_FLAG (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, nm_setting_dcb_get_priority_flow_control_flags, G_MAXUINT32);
	g_test_assert_expected_messages ();

	NMTST_EXPECT ("GLib-GObject", G_LOG_LEVEL_WARNING, "*invalid or out of range*");
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

	if (!WITH_JSON_VALIDATION) {
		g_test_skip ("team test requires JSON validation");
		return;
	}

	s_team = (NMSettingTeam *) nm_setting_team_new ();
	g_assert (s_team);

	g_object_set (s_team, NM_SETTING_TEAM_CONFIG, team_config, NULL);
	g_assert_cmpint (nm_setting_team_get_notify_peers_count (s_team), ==, notify_peer_count);
	g_assert_cmpint (nm_setting_team_get_notify_peers_interval (s_team), ==, notify_peers_interval);
	g_assert_cmpint (nm_setting_team_get_mcast_rejoin_count (s_team), ==, mcast_rejoin_count);
	g_assert_cmpint (nm_setting_team_get_mcast_rejoin_interval (s_team), ==, mcast_rejoin_interval);
	g_assert_cmpint (nm_setting_team_get_runner_tx_balancer_interval (s_team), ==, runner_tx_balancer_interval);
	g_assert_cmpint (nm_setting_team_get_runner_active (s_team), ==, runner_active);
	g_assert_cmpint (nm_setting_team_get_runner_fast_rate (s_team), ==, runner_fast_rate);
	g_assert_cmpint (nm_setting_team_get_runner_sys_prio (s_team), ==, runner_sys_prio);
	g_assert_cmpint (nm_setting_team_get_runner_min_ports (s_team), ==, runner_min_ports);
	g_assert_cmpstr (nm_setting_team_get_runner (s_team), ==, runner);
	g_assert_cmpstr (nm_setting_team_get_runner_hwaddr_policy (s_team), ==, runner_hwaddr_policy);
	g_assert_cmpstr (nm_setting_team_get_runner_tx_balancer (s_team), ==, runner_tx_balancer);
	g_assert_cmpstr (nm_setting_team_get_runner_agg_select_policy (s_team), ==, runner_agg_select_policy);

	if (runner_tx_hash) {
		g_assert_cmpint (runner_tx_hash->len, ==, nm_setting_team_get_num_runner_tx_hash (s_team));
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
		g_assert_cmpint (link_watchers->len, ==, nm_setting_team_get_num_link_watchers (s_team));
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
	                        -1, -1, -1, -1,
	                        NULL,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_broadcast_sync_from_config (void)
{
	_test_team_config_sync ("{\"runner\": {\"name\": \"broadcast\"}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_BROADCAST,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_random_sync_from_config (void)
{
	_test_team_config_sync ("{\"runner\": {\"name\": \"random\"}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_RANDOM,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_activebackup_sync_from_config (void)
{
	_test_team_config_sync ("{\"runner\": {\"name\": \"activebackup\"}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_loadbalance_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *tx_hash = NULL;

	tx_hash = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (tx_hash, g_strdup ("eth"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv4"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv6"));

	_test_team_config_sync ("{\"runner\": {\"name\": \"loadbalance\"}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);

	_test_team_config_sync ("{\"runner\": {\"name\": \"loadbalance\", "
	                        "\"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"]}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                        NULL,
	                        tx_hash, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);

	_test_team_config_sync ("{\"runner\": {\"name\": \"loadbalance\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"], "
	                        "\"tx_balancer\": {\"name\": \"basic\", \"balancing_interval\": 30}}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                        NULL,
	                        tx_hash, "basic", 30,
	                        TRUE, FALSE, -1, -1, NULL,
	                        NULL);
}

static void
test_runner_lacp_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *tx_hash = NULL;

	tx_hash = g_ptr_array_new_with_free_func (g_free);
	g_ptr_array_add (tx_hash, g_strdup ("eth"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv4"));
	g_ptr_array_add (tx_hash, g_strdup ("ipv6"));

	_test_team_config_sync ("{\"runner\": {\"name\": \"lacp\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"]}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_LACP,
	                        NULL,
	                        tx_hash, NULL, -1,
	                        TRUE, FALSE, -1, -1,
	                        NULL,
	                        NULL);

	_test_team_config_sync ("{\"runner\": {\"name\": \"lacp\", \"tx_hash\": [\"eth\", \"ipv4\", \"ipv6\"], "
	                        "\"active\": false, \"fast_rate\": true, \"sys_prio\": 10, \"min_ports\": 5, "
	                        "\"agg_select_policy\": \"port_config\"}}",
	                        -1, -1, -1, -1,
	                        NM_SETTING_TEAM_RUNNER_LACP,
	                        NULL,
	                        tx_hash, NULL, -1,
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
	                        -1, -1, -1, -1,
	                        NULL,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
	                        link_watchers);
}

static void
test_watcher_nsna_ping_sync_from_config (void)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
	g_ptr_array_add (link_watchers, nm_team_link_watcher_new_nsna_ping (0, 0, 3, "target.host", NULL));
	_test_team_config_sync ("{\"link_watch\": {\"name\": \"nsna_ping\", \"target_host\": \"target.host\"}}",
	                        -1, -1, -1, -1,
	                        NULL,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
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
	                        -1, -1, -1, -1,
	                        NULL,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
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
	                        -1, -1, -1, -1,
	                        NULL,
	                        NULL,
	                        NULL, NULL, -1,
	                        TRUE, FALSE, -1, -1, NULL,
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

	if (!WITH_JSON_VALIDATION) {
		g_test_skip ("team test requires JSON validation");
		return;
	}

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
	_test_team_port_config_sync ("", -1, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_queue_id (void)
{
	_test_team_port_config_sync ("{\"queue_id\": 3}",
	                             3, 0, FALSE, -1, -1, NULL);
	_test_team_port_config_sync ("{\"queue_id\": 0}",
	                             0, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_prio (void)
{
	_test_team_port_config_sync ("{\"prio\": 6}",
	                             -1, 6, FALSE, -1, -1, NULL);
	_test_team_port_config_sync ("{\"prio\": 0}",
	                             -1, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_sticky (void)
{
	_test_team_port_config_sync ("{\"sticky\": true}",
	                             -1, 0, TRUE, -1, -1, NULL);
	_test_team_port_config_sync ("{\"sticky\": false}",
	                             -1, 0, FALSE, -1, -1, NULL);
}

static void
test_team_port_lacp_prio (void)
{
	_test_team_port_config_sync ("{\"lacp_prio\": 9}",
	                             -1, 0, FALSE, 9, -1, NULL);
	_test_team_port_config_sync ("{\"lacp_prio\": 0}",
	                             -1, 0, FALSE, 0, -1, NULL);
}

static void
test_team_port_lacp_key (void)
{
	_test_team_port_config_sync ("{\"lacp_key\": 12}",
	                             -1, 0, FALSE, -1, 12, NULL);
	_test_team_port_config_sync ("{\"lacp_key\": 0}",
	                             -1, 0, FALSE, -1, 0, NULL);
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
_check_team_setting (NMSetting *setting)
{
	gs_unref_object NMSetting *setting2 = NULL;
	gs_unref_object NMSetting *setting_clone = NULL;
	gboolean is_port = NM_IS_SETTING_TEAM_PORT (setting);
	gs_unref_variant GVariant *variant2 = NULL;
	gs_unref_variant GVariant *variant3 = NULL;

	g_assert (NM_IS_SETTING_TEAM (setting) || is_port);

	setting2 = g_object_new (G_OBJECT_TYPE (setting),
	                           is_port
	                         ? NM_SETTING_TEAM_PORT_CONFIG
	                         : NM_SETTING_TEAM_CONFIG,
	                           is_port
	                         ? nm_setting_team_port_get_config (NM_SETTING_TEAM_PORT (setting))
	                         : nm_setting_team_get_config (NM_SETTING_TEAM (setting)),
	                         NULL);

	if (WITH_JSON_VALIDATION)
		nmtst_assert_setting_is_equal (setting, setting2, NM_SETTING_COMPARE_FLAG_EXACT);

	g_clear_object (&setting2);

	nmtst_assert_setting_dbus_roundtrip (setting);

	/* OK, now parse the setting only from the D-Bus variant, but removing the JSON config.
	 * For that, we have to "drop" the JSON and we do that by resetting the property.
	 * This causes JSON to be regenerated and it's in a normalized form that will compare
	 * equal. */
	setting_clone = nm_setting_duplicate (setting);
	setting = setting_clone;
	if (is_port) {
		g_object_set (setting,
		              NM_SETTING_TEAM_PORT_STICKY,
		              nm_setting_team_port_get_sticky (NM_SETTING_TEAM_PORT (setting)),
		              NULL);
	} else {
		g_object_set (setting,
		              NM_SETTING_TEAM_RUNNER_SYS_PRIO,
		              nm_setting_team_get_runner_sys_prio (NM_SETTING_TEAM (setting)),
		              NULL);
	}
	variant2 = _nm_setting_to_dbus (setting, NULL, NM_CONNECTION_SERIALIZE_ALL, NULL);
	variant3 = nm_utils_gvariant_vardict_filter_drop_one (variant2, "config");
	setting2 = nmtst_assert_setting_dbus_new (G_OBJECT_TYPE (setting), variant3);
	nmtst_assert_setting_is_equal (setting, setting2, NM_SETTING_COMPARE_FLAG_EXACT);
}

static void
test_team_setting (void)
{
	gs_unref_variant GVariant *variant = nmtst_variant_from_string (G_VARIANT_TYPE_VARDICT,
	                                                                "{'config': <'{\"link_watch\": {\"name\": \"ethtool\"}}'>, 'interface-name': <'nm-team'>, 'link-watchers': <[{'name': <'ethtool'>}]>}");
	gs_free_error GError *error = NULL;
	gs_unref_object NMSetting *setting = NULL;
	nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher1 = nm_team_link_watcher_new_nsna_ping (1, 3, 4, "bbb", NULL);
	nm_auto_unref_team_link_watcher NMTeamLinkWatcher *watcher2 = nm_team_link_watcher_new_arp_ping2 (1, 3, 4, -1, "ccc", "ddd", 0, NULL);

	g_assert (watcher1);
	g_assert (watcher2);

	setting = _nm_setting_new_from_dbus (NM_TYPE_SETTING_TEAM,
	                                     variant,
	                                     NULL,
	                                     NM_SETTING_PARSE_FLAGS_STRICT,
	                                     &error);
	nmtst_assert_success (setting, error);
	_check_team_setting (setting);

	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{\"link_watch\": {\"name\": \"ethtool\"}}");
	g_assert_cmpint (nm_setting_team_get_num_link_watchers (NM_SETTING_TEAM (setting)), ==, 1);

	g_object_set (setting,
	              NM_SETTING_TEAM_RUNNER_SYS_PRIO,
	              (int) 10,
	              NULL);

	_check_team_setting (setting);
	g_assert_cmpint (nm_setting_team_get_num_link_watchers (NM_SETTING_TEAM (setting)), ==, 1);
	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{ \"runner\": { \"sys_prio\": 10 }, \"link_watch\": { \"name\": \"ethtool\" } }");

	nm_setting_team_remove_link_watcher (NM_SETTING_TEAM (setting), 0);

	_check_team_setting (setting);
	g_assert_cmpint (nm_setting_team_get_num_link_watchers (NM_SETTING_TEAM (setting)), ==, 0);
	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{ \"runner\": { \"sys_prio\": 10 } }");

	nm_setting_team_add_link_watcher (NM_SETTING_TEAM (setting), watcher1);
	_check_team_setting (setting);
	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{ \"runner\": { \"sys_prio\": 10 }, \"link_watch\": { \"name\": \"nsna_ping\", \"interval\": 3, \"init_wait\": 1, \"missed_max\": 4, \"target_host\": \"bbb\" } }");

	nm_setting_team_add_link_watcher (NM_SETTING_TEAM (setting), watcher2);
	_check_team_setting (setting);
	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{ \"runner\": { \"sys_prio\": 10 }, \"link_watch\": [ { \"name\": \"nsna_ping\", \"interval\": 3, \"init_wait\": 1, \"missed_max\": 4, \"target_host\": \"bbb\" }, { \"name\": \"arp_ping\", \"interval\": 3, \"init_wait\": 1, \"missed_max\": 4, \"source_host\": \"ddd\", \"target_host\": \"ccc\" } ] }");

	nm_setting_team_remove_link_watcher (NM_SETTING_TEAM (setting), 0);
	nm_setting_team_remove_link_watcher (NM_SETTING_TEAM (setting), 0);
	g_object_set (setting,
	              NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL,
	              (int) 5,
	              NULL);
	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{ \"runner\": { \"tx_balancer\": { \"balancing_interval\": 5 }, \"sys_prio\": 10 } }");

	g_object_set (setting,
	              NM_SETTING_TEAM_RUNNER,
	              NULL,
	              NULL);
	_check_team_setting (setting);
	g_assert_cmpstr (nm_setting_team_get_config (NM_SETTING_TEAM (setting)), ==, "{ \"runner\": { \"tx_balancer\": { \"balancing_interval\": 5 }, \"sys_prio\": 10 } }");

	g_object_set (setting,
	              NM_SETTING_TEAM_CONFIG,
	              "{ \"runner\": { \"tx_hash\": [ \"eth\", \"l3\" ] } }",
	              NULL);
	_check_team_setting (setting);
}

/*****************************************************************************/

static void
test_ethtool_1 (void)
{
	gs_unref_object NMConnection *con = NULL;
	gs_unref_object NMConnection *con2 = NULL;
	gs_unref_object NMConnection *con3 = NULL;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	NMSettingConnection *s_con;
	NMSettingEthtool *s_ethtool;
	NMSettingEthtool *s_ethtool2;
	NMSettingEthtool *s_ethtool3;

	con = nmtst_create_minimal_connection ("ethtool-1",
	                                        NULL,
	                                        NM_SETTING_WIRED_SETTING_NAME,
	                                        &s_con);
	s_ethtool = NM_SETTING_ETHTOOL (nm_setting_ethtool_new ());
	nm_connection_add_setting (con, NM_SETTING (s_ethtool));

	nm_setting_ethtool_set_feature (s_ethtool,
	                                NM_ETHTOOL_OPTNAME_FEATURE_RX,
	                                NM_TERNARY_TRUE);
	nm_setting_ethtool_set_feature (s_ethtool,
	                                NM_ETHTOOL_OPTNAME_FEATURE_LRO,
	                                NM_TERNARY_FALSE);

	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_RX), ==, NM_TERNARY_TRUE);
	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_LRO), ==, NM_TERNARY_FALSE);
	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool, NM_ETHTOOL_OPTNAME_FEATURE_SG),  ==, NM_TERNARY_DEFAULT);

	nmtst_connection_normalize (con);

	variant = nm_connection_to_dbus (con, NM_CONNECTION_SERIALIZE_ALL);

	con2 = nm_simple_connection_new_from_dbus (variant, &error);
	nmtst_assert_success (con2, error);

	s_ethtool2 = NM_SETTING_ETHTOOL (nm_connection_get_setting (con2, NM_TYPE_SETTING_ETHTOOL));

	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool2, NM_ETHTOOL_OPTNAME_FEATURE_RX),  ==, NM_TERNARY_TRUE);
	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool2, NM_ETHTOOL_OPTNAME_FEATURE_LRO), ==, NM_TERNARY_FALSE);
	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool2, NM_ETHTOOL_OPTNAME_FEATURE_SG),  ==, NM_TERNARY_DEFAULT);

	nmtst_assert_connection_verifies_without_normalization (con2);

	nmtst_assert_connection_equals (con, FALSE, con2, FALSE);

	keyfile = nm_keyfile_write (con, NULL, NULL, &error);
	nmtst_assert_success (keyfile, error);

	con3 = nm_keyfile_read (keyfile,
	                        "/ignored/current/working/directory/for/loading/relative/paths",
	                        NULL,
	                        NULL,
	                        &error);
	nmtst_assert_success (con3, error);

	nm_keyfile_read_ensure_id (con3, "unused-because-already-has-id");
	nm_keyfile_read_ensure_uuid (con3, "unused-because-already-has-uuid");

	nmtst_connection_normalize (con3);

	nmtst_assert_connection_equals (con, FALSE, con3, FALSE);

	s_ethtool3 = NM_SETTING_ETHTOOL (nm_connection_get_setting (con3, NM_TYPE_SETTING_ETHTOOL));

	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool3, NM_ETHTOOL_OPTNAME_FEATURE_RX),  ==, NM_TERNARY_TRUE);
	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool3, NM_ETHTOOL_OPTNAME_FEATURE_LRO), ==, NM_TERNARY_FALSE);
	g_assert_cmpint (nm_setting_ethtool_get_feature (s_ethtool3, NM_ETHTOOL_OPTNAME_FEATURE_SG),  ==, NM_TERNARY_DEFAULT);
}

/*****************************************************************************/

static void
test_sriov_vf (void)
{
	NMSriovVF *vf1, *vf2;
	GError *error = NULL;
	char *str;

	vf1 = nm_sriov_vf_new (1);
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_MAC, g_variant_new_string ("00:11:22:33:44:55"));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK, g_variant_new_boolean (TRUE));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean (FALSE));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE, g_variant_new_uint32 (100));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE, g_variant_new_uint32 (500));

	str = nm_utils_sriov_vf_to_str (vf1, FALSE, &error);
	g_assert_no_error (error);
	g_assert_cmpstr (str, ==, "1 mac=00:11:22:33:44:55 max-tx-rate=500 min-tx-rate=100 spoof-check=true trust=false");
	g_free (str);

	vf2 = nm_utils_sriov_vf_from_str (" 1  mac=00:11:22:33:44:55  max-tx-rate=500 min-tx-rate=100", &error);
	nmtst_assert_success (vf2, error);
	nm_sriov_vf_set_attribute (vf2, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK, g_variant_new_boolean (FALSE));
	nm_sriov_vf_set_attribute (vf2, NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK, g_variant_new_boolean (TRUE));
	nm_sriov_vf_set_attribute (vf2, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean (TRUE));
	nm_sriov_vf_set_attribute (vf2, NM_SRIOV_VF_ATTRIBUTE_TRUST, NULL);
	nm_sriov_vf_set_attribute (vf2, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean (FALSE));

	g_assert (nm_sriov_vf_equal (vf1, vf2));

	nm_sriov_vf_unref (vf1);
	nm_sriov_vf_unref (vf2);
}

static void
test_sriov_vf_dup (void)
{
	NMSriovVF *vf1, *vf2;

	vf1 = nm_sriov_vf_new (1);
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_MAC, g_variant_new_string ("foobar"));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_TRUST, g_variant_new_boolean (FALSE));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE, g_variant_new_uint32 (10));
	nm_sriov_vf_set_attribute (vf1, NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE, g_variant_new_uint32 (1000));
	nm_sriov_vf_add_vlan (vf1, 80);
	nm_sriov_vf_set_vlan_qos (vf1, 80, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

	vf2 = nm_sriov_vf_dup (vf1);
	g_assert (nm_sriov_vf_equal (vf1, vf2));

	nm_sriov_vf_unref (vf1);
	nm_sriov_vf_unref (vf2);
}

static void
test_sriov_vf_vlan (void)
{
	NMSriovVF *vf;
	const guint *vlan_ids;
	guint num;
	GError *error = NULL;
	gs_free char *str = NULL;

	vf = nm_sriov_vf_new (19);
	nm_sriov_vf_set_attribute (vf, NM_SRIOV_VF_ATTRIBUTE_MAC, g_variant_new_string ("00:11:22"));
	g_assert (nm_sriov_vf_add_vlan (vf, 80));
	g_assert (!nm_sriov_vf_add_vlan (vf, 80));
	g_assert (nm_sriov_vf_add_vlan (vf, 82));
	g_assert (nm_sriov_vf_add_vlan (vf, 83));
	g_assert (nm_sriov_vf_add_vlan (vf, 81));
	g_assert (!nm_sriov_vf_remove_vlan (vf, 100));
	g_assert (nm_sriov_vf_remove_vlan (vf, 82));
	nm_sriov_vf_set_vlan_qos (vf, 81, 0xabba);
	nm_sriov_vf_set_vlan_protocol (vf, 81, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

	vlan_ids = nm_sriov_vf_get_vlan_ids (vf, &num);
	g_assert (vlan_ids);
	g_assert_cmpint (num, ==, 3);
	g_assert_cmpint (vlan_ids[0], ==, 80);
	g_assert_cmpint (vlan_ids[1], ==, 81);
	g_assert_cmpint (vlan_ids[2], ==, 83);
	g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, 80), ==, 0x0);
	g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, 80), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
	g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, 81), ==, 0xabba);
	g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, 81), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

	nm_sriov_vf_unref (vf);

	vf = nm_utils_sriov_vf_from_str ("20 spoof-check=false vlans=85.0.q;4000.0x20.ad;81.10;83", &error);
	nmtst_assert_success (vf, error);
	vlan_ids = nm_sriov_vf_get_vlan_ids (vf, &num);
	g_assert (vlan_ids);
	g_assert_cmpint (num, ==, 4);
	g_assert_cmpint (vlan_ids[0], ==, 81);
	g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, 81), ==, 10);
	g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, 81), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
	g_assert_cmpint (vlan_ids[1], ==, 83);
	g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, 83), ==, 0);
	g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, 83), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
	g_assert_cmpint (vlan_ids[2], ==, 85);
	g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, 85), ==, 0);
	g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, 85), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
	g_assert_cmpint (vlan_ids[3], ==, 4000);
	g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, 4000), ==, 0x20);
	g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, 4000), ==, NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD);

	str = nm_utils_sriov_vf_to_str (vf, FALSE, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "20 spoof-check=false vlans=81.10;83;85;4000.32.ad");

	nm_sriov_vf_unref (vf);
}

static void
test_sriov_setting (void)
{
	gs_unref_object NMConnection *con = NULL;
	NMSettingConnection *s_con;
	NMSettingSriov *s_sriov = NULL;
	NMSriovVF *vf1, *vf2, *vf3;
	GError *error = NULL;
	gboolean success;

	con = nm_simple_connection_new ();

	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	nm_connection_add_setting (con, NM_SETTING (s_con));

	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, "Test SR-IOV connection",
	              NM_SETTING_CONNECTION_UUID, nm_utils_uuid_generate_a (),
	              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "eth0",
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
	              NULL);

	nm_connection_add_setting (con, nm_setting_wired_new ());

	s_sriov = (NMSettingSriov *) nm_setting_sriov_new ();
	nm_connection_add_setting (con, NM_SETTING (s_sriov));

	g_object_set (s_sriov, NM_SETTING_SRIOV_TOTAL_VFS, 16, NULL);
	nm_setting_sriov_add_vf (s_sriov, (vf1 = nm_sriov_vf_new (0)));
	nm_setting_sriov_add_vf (s_sriov, (vf2 = nm_sriov_vf_new (4)));
	nm_setting_sriov_add_vf (s_sriov, (vf3 = nm_sriov_vf_new (10)));
	g_assert (nm_setting_sriov_remove_vf_by_index (s_sriov, 4));
	nm_sriov_vf_unref (vf2);
	nm_setting_sriov_add_vf (s_sriov, (vf2 = nm_sriov_vf_new (2)));

	nmtst_assert_connection_verifies_and_normalizable (con);
	nmtst_connection_normalize (con);
	success = nm_setting_verify ((NMSetting *) s_sriov, con, &error);
	nmtst_assert_success (success, error);

	g_assert_cmpint (nm_setting_sriov_get_num_vfs (s_sriov), ==, 3);
	g_assert_cmpint (nm_sriov_vf_get_index (nm_setting_sriov_get_vf (s_sriov, 0)), ==, 0);
	g_assert_cmpint (nm_sriov_vf_get_index (nm_setting_sriov_get_vf (s_sriov, 1)), ==, 2);
	g_assert_cmpint (nm_sriov_vf_get_index (nm_setting_sriov_get_vf (s_sriov, 2)), ==, 10);

	nm_sriov_vf_unref (vf1);
	nm_sriov_vf_unref (vf2);
	nm_sriov_vf_unref (vf3);
}

typedef struct {
	guint id;
	guint qos;
	bool  proto_ad;
} VlanData;

static void
_test_sriov_parse_vlan_one (const char *string, gboolean exp_res, VlanData *data, guint data_length)
{
	NMSriovVF *vf;
	gboolean res;
	guint i, num_vlans;
	const guint *vlan_ids;

	vf = nm_sriov_vf_new (1);
	g_assert (vf);

	res = _nm_sriov_vf_parse_vlans (vf, string, NULL);
	g_assert_cmpint (res, ==, exp_res);

	if (exp_res) {
		vlan_ids = nm_sriov_vf_get_vlan_ids (vf, &num_vlans);
		g_assert_cmpint (num_vlans, ==, data_length);
		for (i = 0; i < num_vlans; i++) {
			g_assert_cmpint (vlan_ids[i], ==, data[i].id);
			g_assert_cmpint (nm_sriov_vf_get_vlan_qos (vf, vlan_ids[i]), ==, data[i].qos);
			g_assert_cmpint (nm_sriov_vf_get_vlan_protocol (vf, vlan_ids[i]),
			                 ==,
			                 data[i].proto_ad ? NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD: NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q);
		}
	}

	nm_sriov_vf_unref (vf);
}

#define test_sriov_parse_vlan_one(string, result, ...) \
	{ \
		VlanData _data[] = { __VA_ARGS__ }; \
		guint _length = G_N_ELEMENTS (_data); \
		\
		_test_sriov_parse_vlan_one (string, result, _data, _length); \
	}

static void
test_sriov_parse_vlans (void)
{
	test_sriov_parse_vlan_one ("",  FALSE, {});
	test_sriov_parse_vlan_one ("1", TRUE, {1, 0, 0});
	test_sriov_parse_vlan_one ("1;2", TRUE, {1, 0, 0}, {2, 0, 0});
	test_sriov_parse_vlan_one ("4095;;2", TRUE, {2, 0, 0}, {4095, 0, 0});
	test_sriov_parse_vlan_one ("1 2", FALSE, {});
	test_sriov_parse_vlan_one ("4096", FALSE, {});
	test_sriov_parse_vlan_one ("1.10", TRUE, {1, 10, 0});
	test_sriov_parse_vlan_one ("1.20.ad", TRUE, {1, 20, 1});
	test_sriov_parse_vlan_one ("1.21.q", TRUE, {1, 21, 0});
	test_sriov_parse_vlan_one ("9.20.foo", FALSE, {});
	test_sriov_parse_vlan_one ("1.20.ad.12", FALSE, {});
	test_sriov_parse_vlan_one ("1;1.10", FALSE, {});
	test_sriov_parse_vlan_one ("1..1;2", FALSE, {});
	test_sriov_parse_vlan_one ("1..ad;2", FALSE, {});
	test_sriov_parse_vlan_one ("1.2.ad;2.0.q;5;3", TRUE, {1, 2, 1}, {2, 0, 0}, {3, 0, 0}, {5, 0, 0});
}

static void
test_bridge_vlans (void)
{
	NMBridgeVlan *v1, *v2;
	GError *error = NULL;
	guint16 vid_start, vid_end;
	char *str;

	v1 = nm_bridge_vlan_from_str ("1 foobar", &error);
	nmtst_assert_no_success (v1, error);
	g_clear_error (&error);

	v1 = nm_bridge_vlan_from_str ("4095", &error);
	nmtst_assert_no_success (v1, error);
	g_clear_error (&error);

	/* test ranges */
	v1 = nm_bridge_vlan_from_str ("2-1000 untagged", &error);
	nmtst_assert_success (v1, error);
	g_assert_cmpint (nm_bridge_vlan_get_vid_range (v1, &vid_start, &vid_end), ==, TRUE);
	g_assert_cmpuint (vid_start, ==, 2);
	g_assert_cmpuint (vid_end, ==, 1000);
	g_assert_cmpint (nm_bridge_vlan_is_pvid (v1), ==, FALSE);
	g_assert_cmpint (nm_bridge_vlan_is_untagged (v1), ==, TRUE);
	nm_bridge_vlan_unref (v1);

	/* test comparison (1) */
	v1 = nm_bridge_vlan_from_str ("10 untagged", &error);
	nmtst_assert_success (v1, error);

	g_assert_cmpint (nm_bridge_vlan_get_vid_range (v1, &vid_start, &vid_end), ==, FALSE);
	g_assert_cmpuint (vid_start, ==, 10);
	g_assert_cmpuint (vid_end, ==, 10);
	g_assert_cmpint (nm_bridge_vlan_is_sealed (v1), ==, FALSE);
	g_assert_cmpint (nm_bridge_vlan_is_pvid (v1), ==, FALSE);
	g_assert_cmpint (nm_bridge_vlan_is_untagged (v1), ==, TRUE);

	nm_bridge_vlan_set_pvid (v1, TRUE);
	nm_bridge_vlan_set_untagged (v1, FALSE);
	nm_bridge_vlan_seal (v1);

	g_assert_cmpint (nm_bridge_vlan_is_sealed (v1), ==, TRUE);
	g_assert_cmpint (nm_bridge_vlan_is_pvid (v1), ==, TRUE);
	g_assert_cmpint (nm_bridge_vlan_is_untagged (v1), ==, FALSE);

	str = nm_bridge_vlan_to_str (v1, &error);
	nmtst_assert_success (str, error);
	g_assert_cmpstr (str, ==, "10 pvid");
	g_clear_pointer (&str, g_free);

	v2 = nm_bridge_vlan_from_str ("  10  pvid  ", &error);
	nmtst_assert_success (v2, error);

	g_assert_cmpint (nm_bridge_vlan_cmp (v1, v2), ==, 0);

	nm_bridge_vlan_unref (v1);
	nm_bridge_vlan_unref (v2);

	/* test comparison (2) */
	v1 = nm_bridge_vlan_from_str ("10", &error);
	nmtst_assert_success (v1, error);
	v2 = nm_bridge_vlan_from_str ("20", &error);
	nmtst_assert_success (v2, error);

	g_assert_cmpint (nm_bridge_vlan_cmp (v1, v2), <, 0);

	nm_bridge_vlan_unref (v1);
	nm_bridge_vlan_unref (v2);
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
test_tc_config_setting_valid (void)
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
test_tc_config_setting_duplicates (void)
{
	gs_unref_ptrarray GPtrArray *qdiscs = NULL;
	gs_unref_ptrarray GPtrArray *tfilters = NULL;
	NMSettingConnection *s_con;
	NMConnection *con;
	NMSetting *s_tc;
	NMTCQdisc *qdisc;
	NMTCTfilter *tfilter;
	GError *error = NULL;

	con = nmtst_create_minimal_connection ("dummy",
	                                       NULL,
	                                       NM_SETTING_DUMMY_SETTING_NAME,
	                                       &s_con);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_INTERFACE_NAME, "dummy1",
	              NULL);

	s_tc = nm_setting_tc_config_new ();
	nm_connection_add_setting (con, s_tc);
	qdiscs = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_qdisc_unref);
	tfilters = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_tc_tfilter_unref);

	/* 1. add duplicate qdiscs */
	qdisc = nm_utils_tc_qdisc_from_str ("handle 1234 parent fff1:1 pfifo_fast", &error);
	nmtst_assert_success (qdisc, error);
	g_ptr_array_add (qdiscs, qdisc);

	qdisc = nm_utils_tc_qdisc_from_str ("handle 1234 parent fff1:1 pfifo_fast", &error);
	nmtst_assert_success (qdisc, error);
	g_ptr_array_add (qdiscs, qdisc);

	g_object_set (s_tc, NM_SETTING_TC_CONFIG_QDISCS, qdiscs, NULL);
	nmtst_assert_connection_unnormalizable (con,
	                                        NM_CONNECTION_ERROR,
	                                        NM_CONNECTION_ERROR_INVALID_PROPERTY);

	/* 2. make qdiscs unique */
	g_ptr_array_remove_index (qdiscs, 0);
	g_object_set (s_tc, NM_SETTING_TC_CONFIG_QDISCS, qdiscs, NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);

	/* 3. add duplicate filters */
	tfilter = nm_utils_tc_tfilter_from_str ("parent 1234: matchall action simple sdata Hello", &error);
	nmtst_assert_success (tfilter, error);
	g_ptr_array_add (tfilters, tfilter);

	tfilter = nm_utils_tc_tfilter_from_str ("parent 1234: matchall action simple sdata Hello", &error);
	nmtst_assert_success (tfilter, error);
	g_ptr_array_add (tfilters, tfilter);

	g_object_set (s_tc, NM_SETTING_TC_CONFIG_TFILTERS, tfilters, NULL);
	nmtst_assert_connection_unnormalizable (con,
	                                        NM_CONNECTION_ERROR,
	                                        NM_CONNECTION_ERROR_INVALID_PROPERTY);

	/* 4. make filters unique */
	g_ptr_array_remove_index (tfilters, 0);
	g_object_set (s_tc, NM_SETTING_TC_CONFIG_TFILTERS, tfilters, NULL);
	nmtst_assert_connection_verifies_and_normalizable (con);
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

static void
_rndt_wired_add_s390_options (NMSettingWired *s_wired,
                              char **out_keyfile_entries)
{
	gsize n_opts;
	gsize i, j;
	const char *const*option_names;
	gs_free const char **opt_keys = NULL;
	gs_strfreev char **opt_vals = NULL;
	gs_free bool *opt_found = NULL;
	GString *keyfile_entries;
	nm_auto_free_gstring GString *str_tmp = NULL;

	option_names = nm_setting_wired_get_valid_s390_options (nmtst_get_rand_bool () ? NULL : s_wired);

	n_opts = NM_PTRARRAY_LEN (option_names);
	opt_keys = g_new (const char *, (n_opts + 1));
	nmtst_rand_perm (NULL, opt_keys, option_names, sizeof (const char *), n_opts);
	n_opts = nmtst_get_rand_uint32 () % (n_opts + 1);
	opt_keys[n_opts] = NULL;

	opt_vals = g_new0 (char *, n_opts + 1);
	opt_found = g_new0 (bool, n_opts + 1);
	for (i = 0; i < n_opts; i++) {
		guint p = nmtst_get_rand_uint32 () % 1000;

		if (p < 200)
			opt_vals[i] = nm_strdup_int (i);
		else {
			opt_vals[i] = g_strdup_printf ("%s%s%s%s-%zu",
			                               ((p % 5)  % 2) ? "\n" : "",
			                               ((p % 7)  % 2) ? "\t" : "",
			                               ((p % 11) % 2) ? "x" : "",
			                               ((p % 13) % 2) ? "=" : "",
			                               i);
		}
	}

	if (nmtst_get_rand_bool ()) {
		gs_unref_hashtable GHashTable *hash = NULL;

		hash = g_hash_table_new (nm_str_hash, g_str_equal);
		for (i = 0; i < n_opts; i++)
			g_hash_table_insert (hash, (char *) opt_keys[i], opt_vals[i]);
		g_object_set (s_wired,
		              NM_SETTING_WIRED_S390_OPTIONS,
		              hash,
		              NULL);
	} else {
		_nm_setting_wired_clear_s390_options (s_wired);
		for (i = 0; i < n_opts; i++) {
			if (!nm_setting_wired_add_s390_option (s_wired, opt_keys[i], opt_vals[i]))
				g_assert_not_reached ();
		}
	}

	g_assert_cmpint (nm_setting_wired_get_num_s390_options (s_wired), ==, n_opts);

	keyfile_entries = g_string_new (NULL);
	str_tmp = g_string_new (NULL);
	if (n_opts > 0)
		g_string_append_printf (keyfile_entries, "[ethernet-s390-options]\n");
	for (i = 0; i < n_opts; i++) {
		gssize idx;
		const char *k, *v;

		nm_setting_wired_get_s390_option (s_wired, i, &k, &v);
		g_assert (k);
		g_assert (v);

		idx = nm_utils_strv_find_first ((char **) opt_keys, n_opts, k);
		g_assert (idx >= 0);
		g_assert (!opt_found[idx]);
		opt_found[idx] = TRUE;
		g_assert_cmpstr (opt_keys[idx], ==, k);
		g_assert_cmpstr (opt_vals[idx], ==, v);

		g_string_truncate (str_tmp, 0);
		for (j = 0; v[j] != '\0'; j++) {
			if (v[j] == '\n')
				g_string_append (str_tmp, "\\n");
			else if (v[j] == '\t')
				g_string_append (str_tmp, "\\t");
			else
				g_string_append_c (str_tmp, v[j]);
		}

		g_string_append_printf (keyfile_entries,
		                        "%s=%s\n",
		                        k,
		                        str_tmp->str);
	}
	for (i = 0; i < n_opts; i++)
		g_assert (opt_found[i]);
	if (n_opts > 0)
		g_string_append_printf (keyfile_entries, "\n");
	*out_keyfile_entries = g_string_free (keyfile_entries, FALSE);
}

static GPtrArray *
_rndt_wg_peers_create (void)
{
	GPtrArray *wg_peers;
	guint i, n;

	wg_peers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_wireguard_peer_unref);

	n = nmtst_get_rand_uint32 () % 10;
	for (i = 0; i < n; i++) {
		NMWireGuardPeer *peer;
		guint8 public_key_buf[NM_WIREGUARD_PUBLIC_KEY_LEN];
		guint8 preshared_key_buf[NM_WIREGUARD_SYMMETRIC_KEY_LEN];
		gs_free char *public_key = NULL;
		gs_free char *preshared_key = NULL;
		gs_free char *s_endpoint = NULL;
		guint i_aip, n_aip;

		/* we don't bother to create a valid curve25519 public key. Of course, libnm cannot
		 * check whether the public key is bogus or not. Hence, for our purpose a random
		 * bogus key is good enough. */
		public_key = g_base64_encode (nmtst_rand_buf (NULL, public_key_buf, sizeof (public_key_buf)), sizeof (public_key_buf));

		preshared_key = g_base64_encode (nmtst_rand_buf (NULL, preshared_key_buf, sizeof (preshared_key_buf)), sizeof (preshared_key_buf));

		s_endpoint = _create_random_ipaddr (AF_UNSPEC, TRUE);

		peer = nm_wireguard_peer_new ();
		if (!nm_wireguard_peer_set_public_key (peer, public_key, TRUE))
			g_assert_not_reached ();

		if (!nm_wireguard_peer_set_preshared_key (peer, nmtst_rand_select (NULL, preshared_key), TRUE))
			g_assert_not_reached ();

		nm_wireguard_peer_set_preshared_key_flags (peer, nmtst_rand_select (NM_SETTING_SECRET_FLAG_NONE,
		                                                                    NM_SETTING_SECRET_FLAG_NOT_SAVED,
		                                                                    NM_SETTING_SECRET_FLAG_AGENT_OWNED));

		nm_wireguard_peer_set_persistent_keepalive (peer,
		                                            nmtst_rand_select ((guint32) 0, nmtst_get_rand_uint32 ()));

		if (!nm_wireguard_peer_set_endpoint (peer, nmtst_rand_select (s_endpoint, NULL), TRUE))
			g_assert_not_reached ();

		n_aip = nmtst_rand_select (0, nmtst_get_rand_uint32 () % 10);
		for (i_aip = 0; i_aip < n_aip; i_aip++) {
			gs_free char *aip = NULL;

			aip = _create_random_ipaddr (AF_UNSPEC, FALSE);
			if (!nm_wireguard_peer_append_allowed_ip (peer, aip, FALSE))
				g_assert_not_reached ();
		}

		g_assert (nm_wireguard_peer_is_valid (peer, TRUE, TRUE, NULL));

		nm_wireguard_peer_seal (peer);
		g_ptr_array_add (wg_peers, peer);
	}

	return wg_peers;
}

static const char *
_rndt_wg_peers_to_keyfile (GPtrArray *wg_peers,
                           gboolean strict,
                           char **out_str)
{
	nm_auto_free_gstring GString *gstr = NULL;
	nm_auto_free_gstring GString *gstr_aip = NULL;
	guint i, j;

	g_assert (wg_peers);
	g_assert (out_str && !*out_str);

	nm_gstring_prepare (&gstr);
	for (i = 0; i < wg_peers->len; i++) {
		const NMWireGuardPeer *peer = wg_peers->pdata[i];
		gs_free char *s_endpoint = NULL;
		gs_free char *s_preshared_key = NULL;
		gs_free char *s_preshared_key_flags = NULL;
		gs_free char *s_persistent_keepalive = NULL;
		gs_free char *s_allowed_ips = NULL;

		if (nm_wireguard_peer_get_endpoint (peer))
			s_endpoint = g_strdup_printf ("endpoint=%s\n", nm_wireguard_peer_get_endpoint (peer));
		else if (!strict)
			s_endpoint = g_strdup_printf ("endpoint=\n");

		if (   nm_wireguard_peer_get_preshared_key (peer)
		    || !strict) {
			if (nm_wireguard_peer_get_preshared_key_flags (peer) == NM_SETTING_SECRET_FLAG_NONE)
				s_preshared_key = g_strdup_printf ("preshared-key=%s\n", nm_wireguard_peer_get_preshared_key (peer) ?: "");
		}

		if (   nm_wireguard_peer_get_preshared_key_flags (peer) != NM_SETTING_SECRET_FLAG_NOT_REQUIRED
		    || !strict)
			s_preshared_key_flags = g_strdup_printf ("preshared-key-flags=%d\n", (int) nm_wireguard_peer_get_preshared_key_flags (peer));

		if (   nm_wireguard_peer_get_persistent_keepalive (peer) != 0
		    || !strict)
			s_persistent_keepalive = g_strdup_printf ("persistent-keepalive=%u\n", nm_wireguard_peer_get_persistent_keepalive (peer));

		if (   nm_wireguard_peer_get_allowed_ips_len (peer) > 0
		    || !strict) {
			nm_gstring_prepare (&gstr_aip);
			for (j = 0; j < nm_wireguard_peer_get_allowed_ips_len (peer); j++)
				g_string_append_printf (gstr_aip, "%s;", nm_wireguard_peer_get_allowed_ip (peer, j, NULL));
			s_allowed_ips = g_strdup_printf ("allowed-ips=%s\n", gstr_aip->str);
		}

		if (   !s_endpoint
		    && !s_preshared_key
		    && !s_preshared_key_flags
		    && !s_persistent_keepalive
		    && !s_allowed_ips)
			s_endpoint = g_strdup_printf ("endpoint=\n");

		g_string_append_printf (gstr,
		                        "\n"
		                        "[wireguard-peer.%s]\n"
		                        "%s" /* endpoint */
		                        "%s" /* preshared-key */
		                        "%s" /* preshared-key-flags */
		                        "%s" /* persistent-keepalive */
		                        "%s" /* allowed-ips */
		                        "",
		                        nm_wireguard_peer_get_public_key (peer),
		                        s_endpoint ?: "",
		                        s_preshared_key ?: "",
		                        s_preshared_key_flags ?: "",
		                        s_persistent_keepalive ?: "",
		                        s_allowed_ips ?: "");
	}

	return (*out_str = g_string_free (g_steal_pointer (&gstr), FALSE));
}

static void
_rndt_wg_peers_assert_equal (NMSettingWireGuard *s_wg,
                             GPtrArray *peers,
                             gboolean consider_persistent_secrets,
                             gboolean consider_all_secrets,
                             gboolean expect_no_secrets)
{
	guint i;

	g_assert (NM_IS_SETTING_WIREGUARD (s_wg));
	g_assert (peers);

	g_assert_cmpint (peers->len, ==, nm_setting_wireguard_get_peers_len (s_wg));

	for (i = 0; i < peers->len; i++) {
		const NMWireGuardPeer *a = peers->pdata[i];
		const NMWireGuardPeer *b = nm_setting_wireguard_get_peer (s_wg, i);
		gboolean consider_secrets;

		g_assert (a);
		g_assert (b);

		g_assert_cmpint (nm_wireguard_peer_cmp (a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS), ==, 0);

		if (   consider_all_secrets
		    || !nm_wireguard_peer_get_preshared_key (a))
			consider_secrets = TRUE;
		else if (nm_wireguard_peer_get_preshared_key (b))
			consider_secrets = TRUE;
		else if (   consider_persistent_secrets
		         && nm_wireguard_peer_get_preshared_key_flags (b) == NM_SETTING_SECRET_FLAG_NONE)
			consider_secrets = TRUE;
		else
			consider_secrets = FALSE;

		if (consider_secrets) {
			g_assert_cmpstr (nm_wireguard_peer_get_preshared_key (a), ==, nm_wireguard_peer_get_preshared_key (b));
			g_assert_cmpint (nm_wireguard_peer_cmp (a, b, NM_SETTING_COMPARE_FLAG_EXACT), ==, 0);
		}

		if (expect_no_secrets)
			g_assert_cmpstr (nm_wireguard_peer_get_preshared_key (b), ==, NULL);
	}
}

static void
_rndt_wg_peers_fix_secrets (NMSettingWireGuard *s_wg,
                            GPtrArray *peers)
{
	guint i;

	g_assert (NM_IS_SETTING_WIREGUARD (s_wg));
	g_assert (peers);

	g_assert_cmpint (peers->len, ==, nm_setting_wireguard_get_peers_len (s_wg));

	for (i = 0; i < peers->len; i++) {
		const NMWireGuardPeer *a = peers->pdata[i];
		const NMWireGuardPeer *b = nm_setting_wireguard_get_peer (s_wg, i);
		nm_auto_unref_wgpeer NMWireGuardPeer *b_clone = NULL;

		g_assert (a);
		g_assert (b);

		g_assert_cmpint (nm_wireguard_peer_get_preshared_key_flags (a), ==, nm_wireguard_peer_get_preshared_key_flags (b));
		g_assert_cmpint (nm_wireguard_peer_cmp (a, b, NM_SETTING_COMPARE_FLAG_IGNORE_SECRETS), ==, 0);

		if (!nm_streq0 (nm_wireguard_peer_get_preshared_key (a),
		                nm_wireguard_peer_get_preshared_key (b))) {
			g_assert_cmpstr (nm_wireguard_peer_get_preshared_key (a), !=, NULL);
			g_assert_cmpstr (nm_wireguard_peer_get_preshared_key (b), ==, NULL);
			g_assert (NM_IN_SET (nm_wireguard_peer_get_preshared_key_flags (a), NM_SETTING_SECRET_FLAG_AGENT_OWNED,
			                                                                    NM_SETTING_SECRET_FLAG_NOT_SAVED));
			b_clone = nm_wireguard_peer_new_clone (b, TRUE);
			if (!nm_wireguard_peer_set_preshared_key (b_clone, nm_wireguard_peer_get_preshared_key (a), TRUE))
				g_assert_not_reached ();
			nm_setting_wireguard_set_peer (s_wg, b_clone, i);
			b = nm_setting_wireguard_get_peer (s_wg, i);
			g_assert (b == b_clone);
		} else {
			if (nm_wireguard_peer_get_preshared_key (a)) {
				g_assert (NM_IN_SET (nm_wireguard_peer_get_preshared_key_flags (a), NM_SETTING_SECRET_FLAG_NONE,
				                                                                    NM_SETTING_SECRET_FLAG_NOT_REQUIRED));
			} else {
				g_assert (NM_IN_SET (nm_wireguard_peer_get_preshared_key_flags (a), NM_SETTING_SECRET_FLAG_AGENT_OWNED,
				                                                                    NM_SETTING_SECRET_FLAG_NONE,
				                                                                    NM_SETTING_SECRET_FLAG_NOT_SAVED,
				                                                                    NM_SETTING_SECRET_FLAG_NOT_REQUIRED));
			}
		}

		g_assert_cmpstr (nm_wireguard_peer_get_preshared_key (a), ==, nm_wireguard_peer_get_preshared_key (b));
		g_assert_cmpint (nm_wireguard_peer_cmp (a, b, NM_SETTING_COMPARE_FLAG_EXACT), ==, 0);
	}
}

static void
test_roundtrip_conversion (gconstpointer test_data)
{
	const int MODE = GPOINTER_TO_INT (test_data);
	const char *ID= nm_sprintf_bufa (100, "roundtip-conversion-%d", MODE);
	const char *UUID= "63376701-b61e-4318-bf7e-664a1c1eeaab";
	const char *INTERFACE_NAME = nm_sprintf_bufa (100, "ifname%d", MODE);
	guint32 ETH_MTU = nmtst_rand_select ((guint32) 0u,
	                                     nmtst_get_rand_uint32 ());
	const char *WG_PRIVATE_KEY = nmtst_get_rand_bool ()
	                             ? "yGXGK+5bVnxSJUejH4vbpXbq+ZtaG4NB8IHRK/aVtE0="
	                             : NULL;
	const NMSettingSecretFlags WG_PRIVATE_KEY_FLAGS = nmtst_rand_select (NM_SETTING_SECRET_FLAG_NONE,
	                                                                     NM_SETTING_SECRET_FLAG_NOT_SAVED,
	                                                                     NM_SETTING_SECRET_FLAG_AGENT_OWNED);
	const guint WG_LISTEN_PORT = nmtst_rand_select (0u,
	                                                nmtst_get_rand_uint32 () % 0x10000);
	const guint WG_FWMARK = nmtst_rand_select (0u,
	                                           nmtst_get_rand_uint32 ());
	gs_unref_ptrarray GPtrArray *kf_data_arr = g_ptr_array_new_with_free_func (g_free);
	gs_unref_ptrarray GPtrArray *wg_peers = NULL;
	const NMConnectionSerializationFlags dbus_serialization_flags[] = {
		NM_CONNECTION_SERIALIZE_ALL,
		NM_CONNECTION_SERIALIZE_NO_SECRETS,
		NM_CONNECTION_SERIALIZE_ONLY_SECRETS,
	};
	guint dbus_serialization_flags_idx;
	gs_unref_object NMConnection *con = NULL;
	gs_free_error GError *error = NULL;
	gs_free char *tmp_str = NULL;
	guint kf_data_idx;
	NMSettingConnection *s_con = NULL;
	NMSettingWired *s_eth = NULL;
	NMSettingWireGuard *s_wg = NULL;
	union {
		struct {
			NMSettingIPConfig  *s_6;
			NMSettingIPConfig  *s_4;
		};
		NMSettingIPConfig *s_x[2];
	} s_ip;
	int is_ipv4;
	guint i;
	gboolean success;
	gs_free char *s390_keyfile_entries = NULL;

	switch (MODE) {
	case 0:
		con = nmtst_create_minimal_connection (ID, UUID, NM_SETTING_WIRED_SETTING_NAME, &s_con);
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_INTERFACE_NAME,
		              INTERFACE_NAME,
		              NULL);
		nmtst_connection_normalize (con);

		s_eth = NM_SETTING_WIRED (nm_connection_get_setting (con, NM_TYPE_SETTING_WIRED));
		g_assert (NM_IS_SETTING_WIRED (s_eth));

		g_object_set (s_eth,
		              NM_SETTING_WIRED_MTU,
		              ETH_MTU,
		              NULL);

		_rndt_wired_add_s390_options (s_eth, &s390_keyfile_entries);

		g_ptr_array_add (kf_data_arr,
		    g_strdup_printf ("[connection]\n"
		                     "id=%s\n"
		                     "uuid=%s\n"
		                     "type=ethernet\n"
		                     "interface-name=%s\n"
		                     "permissions=\n"
		                     "\n"
		                     "[ethernet]\n"
		                     "mac-address-blacklist=\n"
		                     "%s" /* mtu */
		                     "\n"
		                     "%s" /* [ethernet-s390-options] */
		                     "[ipv4]\n"
		                     "dns-search=\n"
		                     "method=auto\n"
		                     "\n"
		                     "[ipv6]\n"
		                     "addr-gen-mode=stable-privacy\n"
		                     "dns-search=\n"
		                     "method=auto\n"
		                     "",
		                     ID,
		                     UUID,
		                     INTERFACE_NAME,
		                       (ETH_MTU != 0)
		                     ? nm_sprintf_bufa (100, "mtu=%u\n", ETH_MTU)
		                     : "",
		                     s390_keyfile_entries));

		g_ptr_array_add (kf_data_arr,
		    g_strdup_printf ("[connection]\n"
		                     "id=%s\n"
		                     "uuid=%s\n"
		                     "type=ethernet\n"
		                     "interface-name=%s\n"
		                     "permissions=\n"
		                     "\n"
		                     "[ethernet]\n"
		                     "mac-address-blacklist=\n"
		                     "%s" /* mtu */
		                     "\n"
		                     "%s" /* [ethernet-s390-options] */
		                     "[ipv4]\n"
		                     "dns-search=\n"
		                     "method=auto\n"
		                     "\n"
		                     "[ipv6]\n"
		                     "addr-gen-mode=stable-privacy\n"
		                     "dns-search=\n"
		                     "method=auto\n"
		                     "",
		                     ID,
		                     UUID,
		                     INTERFACE_NAME,
		                       (ETH_MTU != 0)
		                     ? nm_sprintf_bufa (100, "mtu=%d\n", (int) ETH_MTU)
		                     : "",
		                     s390_keyfile_entries));

		break;

	case 1:
		con = nmtst_create_minimal_connection (ID, UUID, "wireguard", &s_con);
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_INTERFACE_NAME,
		              INTERFACE_NAME,
		              NULL);
		nmtst_connection_normalize (con);

		s_wg = NM_SETTING_WIREGUARD (nm_connection_get_setting (con, NM_TYPE_SETTING_WIREGUARD));

		g_ptr_array_add (kf_data_arr,
		    g_strdup_printf ("[connection]\n"
		                     "id=%s\n"
		                     "uuid=%s\n"
		                     "type=wireguard\n"
		                     "interface-name=%s\n"
		                     "permissions=\n"
		                     "\n"
		                     "[ipv4]\n"
		                     "dns-search=\n"
		                     "method=disabled\n"
		                     "\n"
		                     "[ipv6]\n"
		                     "addr-gen-mode=stable-privacy\n"
		                     "dns-search=\n"
		                     "method=ignore\n"
		                     "",
		                     ID,
		                     UUID,
		                     INTERFACE_NAME));
		break;

	case 2:
		con = nmtst_create_minimal_connection (ID, UUID, "wireguard", &s_con);
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_INTERFACE_NAME,
		              INTERFACE_NAME,
		              NULL);
		nmtst_connection_normalize (con);

		s_wg = NM_SETTING_WIREGUARD (nm_connection_get_setting (con, NM_TYPE_SETTING_WIREGUARD));
		g_object_set (s_wg,
		              NM_SETTING_WIREGUARD_PRIVATE_KEY,
		              WG_PRIVATE_KEY,
		              NM_SETTING_WIREGUARD_PRIVATE_KEY_FLAGS,
		              WG_PRIVATE_KEY_FLAGS,
		              NM_SETTING_WIREGUARD_LISTEN_PORT,
		              WG_LISTEN_PORT,
		              NM_SETTING_WIREGUARD_FWMARK,
		              WG_FWMARK,
		              NULL);

		wg_peers = _rndt_wg_peers_create ();

		for (i = 0; i < wg_peers->len; i++)
			nm_setting_wireguard_append_peer (s_wg, wg_peers->pdata[i]);

		nm_clear_g_free (&tmp_str);

		g_ptr_array_add (kf_data_arr,
		    g_strdup_printf ("[connection]\n"
		                     "id=%s\n"
		                     "uuid=%s\n"
		                     "type=wireguard\n"
		                     "interface-name=%s\n"
		                     "permissions=\n"
		                     "%s" /* [wireguard] */
		                     "%s" /* fwmark */
		                     "%s" /* listen-port */
		                     "%s" /* private-key-flags */
		                     "%s" /* private-key */
		                     "%s" /* [wireguard-peers*] */
		                     "\n"
		                     "[ipv4]\n"
		                     "dns-search=\n"
		                     "method=disabled\n"
		                     "\n"
		                     "[ipv6]\n"
		                     "addr-gen-mode=stable-privacy\n"
		                     "dns-search=\n"
		                     "method=ignore\n"
		                     "",
		                     ID,
		                     UUID,
		                     INTERFACE_NAME,
		                     (  (   (WG_FWMARK != 0)
		                         || (WG_LISTEN_PORT != 0)
		                         || (WG_PRIVATE_KEY_FLAGS != NM_SETTING_SECRET_FLAG_NONE)
		                         || (   WG_PRIVATE_KEY
		                             && WG_PRIVATE_KEY_FLAGS == NM_SETTING_SECRET_FLAG_NONE))
		                      ? "\n[wireguard]\n"
		                      : ""),
		                     (  (WG_FWMARK != 0)
		                      ? nm_sprintf_bufa (100, "fwmark=%u\n", WG_FWMARK)
		                      : ""),
		                     (  (WG_LISTEN_PORT != 0)
		                      ? nm_sprintf_bufa (100, "listen-port=%u\n", WG_LISTEN_PORT)
		                      : ""),
		                     (  (WG_PRIVATE_KEY_FLAGS != NM_SETTING_SECRET_FLAG_NONE)
		                      ? nm_sprintf_bufa (100, "private-key-flags=%u\n", (guint) WG_PRIVATE_KEY_FLAGS)
		                      : ""),
		                     (  (   WG_PRIVATE_KEY
		                         && WG_PRIVATE_KEY_FLAGS == NM_SETTING_SECRET_FLAG_NONE)
		                      ? nm_sprintf_bufa (100, "private-key=%s\n", WG_PRIVATE_KEY)
		                      : ""),
		                     _rndt_wg_peers_to_keyfile (wg_peers, TRUE, &tmp_str)));

		_rndt_wg_peers_assert_equal (s_wg, wg_peers, TRUE, TRUE, FALSE);
		break;

	case 3:
		con = nmtst_create_minimal_connection (ID, UUID, NM_SETTING_WIRED_SETTING_NAME, &s_con);
		g_object_set (s_con,
		              NM_SETTING_CONNECTION_INTERFACE_NAME,
		              INTERFACE_NAME,
		              NULL);
		nmtst_connection_normalize (con);

		s_eth = NM_SETTING_WIRED (nm_connection_get_setting (con, NM_TYPE_SETTING_WIRED));
		g_assert (NM_IS_SETTING_WIRED (s_eth));

		g_object_set (s_eth,
		              NM_SETTING_WIRED_MTU,
		              ETH_MTU,
		              NULL);

		s_ip.s_4 = NM_SETTING_IP_CONFIG (nm_connection_get_setting (con, NM_TYPE_SETTING_IP4_CONFIG));
		g_assert (NM_IS_SETTING_IP4_CONFIG (s_ip.s_4));

		s_ip.s_6 = NM_SETTING_IP_CONFIG (nm_connection_get_setting (con, NM_TYPE_SETTING_IP6_CONFIG));
		g_assert (NM_IS_SETTING_IP6_CONFIG (s_ip.s_6));

		for (is_ipv4 = 0; is_ipv4 < 2; is_ipv4++) {
			g_assert (NM_IS_SETTING_IP_CONFIG (s_ip.s_x[is_ipv4]));
			for (i = 0; i < 3; i++) {
				char addrstr[NM_UTILS_INET_ADDRSTRLEN];

				nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr = NULL;

				rr = nm_ip_routing_rule_new (is_ipv4 ? AF_INET : AF_INET6);
				nm_ip_routing_rule_set_priority (rr, i + 1);
				if (i > 0) {
					if (is_ipv4)
						nm_sprintf_buf (addrstr, "192.168.%u.0", i);
					else
						nm_sprintf_buf (addrstr, "1:2:3:%x::", 10 + i);
					nm_ip_routing_rule_set_from (rr, addrstr, is_ipv4 ? 24 + i : 64 + i);
				}
				nm_ip_routing_rule_set_table (rr, 1000 + i);

				success = nm_ip_routing_rule_validate (rr, &error);
				nmtst_assert_success (success, error);

				nm_setting_ip_config_add_routing_rule (s_ip.s_x[is_ipv4], rr);
			}
		}

		g_ptr_array_add (kf_data_arr,
		    g_strdup_printf ("[connection]\n"
		                     "id=%s\n"
		                     "uuid=%s\n"
		                     "type=ethernet\n"
		                     "interface-name=%s\n"
		                     "permissions=\n"
		                     "\n"
		                     "[ethernet]\n"
		                     "mac-address-blacklist=\n"
		                     "%s" /* mtu */
		                     "\n"
		                     "[ipv4]\n"
		                     "dns-search=\n"
		                     "method=auto\n"
		                     "routing-rule1=priority 1 from 0.0.0.0/0 table 1000\n"
		                     "routing-rule2=priority 2 from 192.168.1.0/25 table 1001\n"
		                     "routing-rule3=priority 3 from 192.168.2.0/26 table 1002\n"
		                     "\n"
		                     "[ipv6]\n"
		                     "addr-gen-mode=stable-privacy\n"
		                     "dns-search=\n"
		                     "method=auto\n"
		                     "routing-rule1=priority 1 from ::/0 table 1000\n"
		                     "routing-rule2=priority 2 from 1:2:3:b::/65 table 1001\n"
		                     "routing-rule3=priority 3 from 1:2:3:c::/66 table 1002\n"
		                     "",
		                     ID,
		                     UUID,
		                     INTERFACE_NAME,
		                       (ETH_MTU != 0)
		                     ? nm_sprintf_bufa (100, "mtu=%u\n", ETH_MTU)
		                     : ""));

		break;

	default:
		g_assert_not_reached ();
	}

	/* the first kf_data_arr entry is special: it is the exact result of what we expect
	 * when converting @con to keyfile. Write @con to keyfile and compare the expected result
	 * literally. */
	{
		gs_unref_keyfile GKeyFile *kf = NULL;

		kf = nm_keyfile_write (con, NULL, NULL, &error);
		nmtst_assert_success (kf, error);

		/* the first kf_data_arr entry is special: it must be what the writer would
		 * produce again. */
		nmtst_keyfile_assert_data (kf, kf_data_arr->pdata[0], -1);
	}

	/* check that reading any of kf_data_arr yields the same result that we expect. */
	for (kf_data_idx = 0; kf_data_idx < kf_data_arr->len; kf_data_idx++) {
		gs_unref_object NMConnection *con2 = NULL;
		NMSettingWireGuard *s_wg2 = NULL;
		NMSettingWired *s_eth2 = NULL;

		con2 = nmtst_create_connection_from_keyfile (kf_data_arr->pdata[kf_data_idx], "/no/where/file.nmconnection");

		switch (MODE) {
		case 0:
			s_eth2 = NM_SETTING_WIRED (nm_connection_get_setting (con2, NM_TYPE_SETTING_WIRED));
			g_assert (NM_IS_SETTING_WIRED (s_eth2));

			if (   ETH_MTU > (guint32) G_MAXINT
			    && kf_data_idx == 1) {
				/* older versions wrote values > 2^21 as signed integers, but the reader would
				 * always reject such negative values for G_TYPE_UINT.
				 *
				 * The test case kf_data_idx #1 still writes the values in the old style.
				 * The behavior was fixed, but such values are still rejected as invalid.
				 *
				 * Patch the setting so that the comparison below succeeds are usual. */
				g_assert_cmpint (nm_setting_wired_get_mtu (s_eth2), ==, 0);
				g_object_set (s_eth2,
				              NM_SETTING_WIRED_MTU,
				              ETH_MTU,
				              NULL);
			}

			g_assert_cmpint (nm_setting_wired_get_mtu (s_eth), ==, ETH_MTU);
			g_assert_cmpint (nm_setting_wired_get_mtu (s_eth2), ==, ETH_MTU);

			g_assert_cmpint (nm_setting_wired_get_num_s390_options (s_eth2), ==, nm_setting_wired_get_num_s390_options (s_eth));

			break;

		case 1:
			s_wg2 = NM_SETTING_WIREGUARD (nm_connection_get_setting (con2, NM_TYPE_SETTING_WIREGUARD));
			g_assert (NM_IS_SETTING_WIREGUARD (s_wg2));

			g_assert_cmpstr (nm_setting_wireguard_get_private_key (s_wg), ==, NULL);
			g_assert_cmpstr (nm_setting_wireguard_get_private_key (s_wg2), ==, NULL);
			break;

		case 2:
			s_wg2 = NM_SETTING_WIREGUARD (nm_connection_get_setting (con2, NM_TYPE_SETTING_WIREGUARD));
			g_assert (NM_IS_SETTING_WIREGUARD (s_wg2));

			/* the private key was lost due to the secret-flags. Patch it. */
			if (WG_PRIVATE_KEY_FLAGS != NM_SETTING_SECRET_FLAG_NONE) {
				g_assert_cmpstr (nm_setting_wireguard_get_private_key (s_wg2), ==, NULL);
				g_object_set (s_wg2,
				              NM_SETTING_WIREGUARD_PRIVATE_KEY,
				              WG_PRIVATE_KEY,
				              NULL);
			}

			g_assert_cmpstr (nm_setting_wireguard_get_private_key (s_wg), ==, WG_PRIVATE_KEY);
			g_assert_cmpstr (nm_setting_wireguard_get_private_key (s_wg2), ==, WG_PRIVATE_KEY);

			_rndt_wg_peers_assert_equal (s_wg2, wg_peers, TRUE, FALSE, FALSE);
			_rndt_wg_peers_fix_secrets (s_wg2, wg_peers);
			_rndt_wg_peers_assert_equal (s_wg2, wg_peers, TRUE, TRUE, FALSE);
			break;
		}

		nmtst_assert_connection_equals (con, nmtst_get_rand_bool (), con2, nmtst_get_rand_bool ());
	}

	for (dbus_serialization_flags_idx = 0; dbus_serialization_flags_idx < G_N_ELEMENTS (dbus_serialization_flags); dbus_serialization_flags_idx++) {
		NMConnectionSerializationFlags flag = dbus_serialization_flags[dbus_serialization_flags_idx];
		gs_unref_variant GVariant *con_var = NULL;
		gs_unref_object NMConnection *con2 = NULL;
		NMSettingWireGuard *s_wg2 = NULL;

		con_var = nm_connection_to_dbus (con, flag);
		g_assert (g_variant_is_of_type (con_var, NM_VARIANT_TYPE_CONNECTION));
		g_assert (g_variant_is_floating (con_var));
		g_variant_ref_sink (con_var);

		if (flag == NM_CONNECTION_SERIALIZE_ALL) {
			con2 = _connection_new_from_dbus_strict (con_var, TRUE);
			nmtst_assert_connection_equals (con, nmtst_get_rand_bool (), con2, nmtst_get_rand_bool ());

			{
				gs_unref_keyfile GKeyFile *kf = NULL;

				kf = nm_keyfile_write (con2, NULL, NULL, &error);
				nmtst_assert_success (kf, error);
				nmtst_keyfile_assert_data (kf, kf_data_arr->pdata[0], -1);
			}
		}

		switch (MODE) {
		case 2:
			if (flag == NM_CONNECTION_SERIALIZE_ALL) {
				s_wg2 = NM_SETTING_WIREGUARD (nm_connection_get_setting (con2, NM_TYPE_SETTING_WIREGUARD));

				if (flag == NM_CONNECTION_SERIALIZE_ALL)
					_rndt_wg_peers_assert_equal (s_wg2, wg_peers, TRUE, TRUE, FALSE);
				else if (flag == NM_CONNECTION_SERIALIZE_NO_SECRETS)
					_rndt_wg_peers_assert_equal (s_wg2, wg_peers, FALSE, FALSE, TRUE);
				else
					g_assert_not_reached ();
			}
			break;
		}
	}
}

/*****************************************************************************/

static NMIPRoutingRule *
_rr_from_str_get_impl (const char *str, const char *const*aliases)
{
	nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr = NULL;
	gs_free_error GError *error = NULL;
	gboolean vbool;
	int addr_family;
	int i;
	NMIPRoutingRuleAsStringFlags to_string_flags;

	rr = nm_ip_routing_rule_from_string (str,
	                                     NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE,
	                                     NULL,
	                                     &error);
	nmtst_assert_success (rr, error);

	addr_family = nm_ip_routing_rule_get_addr_family (rr);
	g_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));

	if (addr_family == AF_INET)
		to_string_flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET;
	else
		to_string_flags = NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6;

	for (i = 0; TRUE; i++) {
		nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr2 = NULL;
		gs_free char *str1 = NULL;
		gs_unref_variant GVariant *variant1 = NULL;
		const char *cstr1;

		switch (i) {
		case 0:
			rr2 = nm_ip_routing_rule_ref (rr);
			break;

		case 1:
			rr2 = nm_ip_routing_rule_from_string (str,
			                                        NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
			                                      | (nmtst_get_rand_bool () ? to_string_flags : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
			                                      NULL,
			                                      &error);
			nmtst_assert_success (rr, error);
			break;

		case 2:
			str1 = nm_ip_routing_rule_to_string (rr,
			                                       NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
			                                      | (nmtst_get_rand_bool () ? to_string_flags : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
			                                     NULL,
			                                     &error);
			nmtst_assert_success (str1 && str1[0], error);

			g_assert_cmpstr (str, ==, str1);

			rr2 = nm_ip_routing_rule_from_string (str1,
			                                        NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
			                                      | (nmtst_get_rand_bool () ? to_string_flags : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
			                                      NULL,
			                                      &error);
			nmtst_assert_success (rr, error);
			break;

		case 3:
			variant1 = nm_ip_routing_rule_to_dbus (rr);
			g_assert (variant1);
			g_assert (g_variant_is_floating (variant1));
			g_assert (g_variant_is_of_type (variant1, G_VARIANT_TYPE_VARDICT));

			rr2 = nm_ip_routing_rule_from_dbus (variant1,
			                                    TRUE,
			                                    &error);
			nmtst_assert_success (rr, error);
			break;

		default:
			if (!aliases || !aliases[0])
				goto done;
			cstr1 = (aliases++)[0];
			rr2 = nm_ip_routing_rule_from_string (cstr1,
			                                        NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE
			                                      | (nmtst_get_rand_bool () ? to_string_flags : NM_IP_ROUTING_RULE_AS_STRING_FLAGS_NONE),
			                                      NULL,
			                                      &error);
			nmtst_assert_success (rr, error);
			break;
		}

		g_assert (rr2);
		vbool = nm_ip_routing_rule_validate (rr, &error);
		nmtst_assert_success (vbool, error);
		vbool = nm_ip_routing_rule_validate (rr2, &error);
		nmtst_assert_success (vbool, error);

		g_assert_cmpint (nm_ip_routing_rule_cmp (rr, rr2), ==, 0);
		g_assert_cmpint (nm_ip_routing_rule_cmp (rr2, rr), ==, 0);
	}

done:
	return g_steal_pointer (&rr);
}
#define _rr_from_str_get(a, ...) _rr_from_str_get_impl (a, &(NM_MAKE_STRV (NULL, ##__VA_ARGS__))[1])

#define _rr_from_str(...) \
	G_STMT_START { \
		nm_auto_unref_ip_routing_rule NMIPRoutingRule *_rr = NULL; \
		\
		_rr = _rr_from_str_get (__VA_ARGS__); \
		g_assert (_rr); \
	} G_STMT_END

static void
test_routing_rule (gconstpointer test_data)
{
	nm_auto_unref_ip_routing_rule NMIPRoutingRule *rr1 = NULL;
	gboolean success;
	char ifname_buf[16];

	_rr_from_str ("priority 5 from 0.0.0.0 table 1",
	              "  from 0.0.0.0  priority  5 lookup 1 ");
	_rr_from_str ("priority 5 from 0.0.0.0/0 table 4");
	_rr_from_str ("priority 5 to 0.0.0.0 table 6");
	_rr_from_str ("priority 5 to 0.0.0.0 table 254",
	              "priority 5 to 0.0.0.0/32");
	_rr_from_str ("priority 5 from 1.2.3.4 table 15",
	              "priority 5 from 1.2.3.4/32 table  0xF ",
	              "priority 5 from 1.2.3.4/32 to 0.0.0.0/0 lookup 15 ");
	_rr_from_str ("priority 5 from 1.2.3.4 to 0.0.0.0 table 8");
	_rr_from_str ("priority 5 to a:b:c:: tos 0x16 table 25",
	              "priority 5 to a:b:c::/128 table 0x19 tos 16",
	              "priority 5 to a:b:c::/128 lookup 0x19 dsfield 16",
	              "priority 5 to a:b:c::/128 lookup 0x19 dsfield 16 fwmark 0/0x00",
	              "priority 5 to a:b:c:: from all lookup 0x19 dsfield 16 fwmark 0x0/0");
	_rr_from_str ("priority 5 from :: fwmark 0 table 25",
	              "priority 5 from ::/128 to all table 0x19 fwmark 0/0xFFFFFFFF",
	              "priority 5 from :: to ::/0 table 0x19 fwmark 0x00/4294967295");
	_rr_from_str ("priority 5 from :: iif aab table 25");
	_rr_from_str ("priority 5 from :: iif aab oif er table 25",
	              "priority 5 from :: table 0x19 dev aab oif er");
	_rr_from_str ("priority 5 from :: iif a\\\\303b table 25");
	_rr_from_str ("priority 5 to 0.0.0.0 sport 10 table 6",
	              "priority 5 to 0.0.0.0 sport 10-10 table 6");
	_rr_from_str ("not priority 5 to 0.0.0.0 dport 10-133 table 6",
	              "priority 5 to 0.0.0.0 not dport 10-133 not table 6",
	              "priority 5 to 0.0.0.0 not dport 10-\\ 133 not table 6");
	_rr_from_str ("priority 5 to 0.0.0.0 ipproto 10 sport 10 table 6");

	rr1 = _rr_from_str_get ("priority 5 from :: iif aab table 25");
	g_assert_cmpstr (nm_ip_routing_rule_get_iifname (rr1), ==, "aab");
	success = nm_ip_routing_rule_get_xifname_bin (rr1, FALSE, ifname_buf);
	g_assert (!success);
	success = nm_ip_routing_rule_get_xifname_bin (rr1, TRUE, ifname_buf);
	g_assert_cmpstr (ifname_buf, ==, "aab");
	g_assert (success);
	nm_clear_pointer (&rr1, nm_ip_routing_rule_unref);

	rr1 = _rr_from_str_get ("priority 5 from :: iif a\\\\303\\\\261xb table 254");
	g_assert_cmpstr (nm_ip_routing_rule_get_iifname (rr1), ==, "a\\303\\261xb");
	success = nm_ip_routing_rule_get_xifname_bin (rr1, FALSE, ifname_buf);
	g_assert (!success);
	success = nm_ip_routing_rule_get_xifname_bin (rr1, TRUE, ifname_buf);
	g_assert_cmpstr (ifname_buf, ==, "a\303\261xb");
	g_assert (success);
	nm_clear_pointer (&rr1, nm_ip_routing_rule_unref);

	rr1 = _rr_from_str_get ("priority 5 from :: oif \\\\101=\\\\303\\\\261xb table 7");
	g_assert_cmpstr (nm_ip_routing_rule_get_oifname (rr1), ==, "\\101=\\303\\261xb");
	success = nm_ip_routing_rule_get_xifname_bin (rr1, FALSE, ifname_buf);
	g_assert_cmpstr (ifname_buf, ==, "A=\303\261xb");
	g_assert (success);
	success = nm_ip_routing_rule_get_xifname_bin (rr1, TRUE, ifname_buf);
	g_assert (!success);
	nm_clear_pointer (&rr1, nm_ip_routing_rule_unref);

	rr1 = _rr_from_str_get ("priority 5 to 0.0.0.0 tos 0x10 table 7");
	g_assert_cmpstr (NULL, ==, nm_ip_routing_rule_get_from (rr1));
	g_assert (!nm_ip_routing_rule_get_from_bin (rr1));
	g_assert_cmpint (0, ==, nm_ip_routing_rule_get_from_len (rr1));
	g_assert_cmpstr ("0.0.0.0", ==, nm_ip_routing_rule_get_to (rr1));
	g_assert (nm_ip_addr_is_null (AF_INET, nm_ip_routing_rule_get_to_bin (rr1)));
	g_assert_cmpint (32, ==, nm_ip_routing_rule_get_to_len (rr1));
	g_assert_cmpint (7, ==, nm_ip_routing_rule_get_table (rr1));
	g_assert_cmpint (0x10, ==, nm_ip_routing_rule_get_tos (rr1));
	nm_clear_pointer (&rr1, nm_ip_routing_rule_unref);

	rr1 = _rr_from_str_get ("priority 5 from :: iif a\\\\303\\\\261,x;b table 254",
	                        "priority 5 from :: iif a\\\\303\\\\261,x;b table 254");
	g_assert_cmpstr (nm_ip_routing_rule_get_iifname (rr1), ==, "a\\303\\261,x;b");
	success = nm_ip_routing_rule_get_xifname_bin (rr1, FALSE, ifname_buf);
	g_assert (!success);
	success = nm_ip_routing_rule_get_xifname_bin (rr1, TRUE, ifname_buf);
	g_assert_cmpstr (ifname_buf, ==, "a\303\261,x;b");
	g_assert (success);
	nm_clear_pointer (&rr1, nm_ip_routing_rule_unref);

}

/*****************************************************************************/

static void
test_parse_tc_handle (void)
{
#define _parse_tc_handle(str, exp) \
	G_STMT_START { \
		gs_free_error GError *_error = NULL; \
		GError **_perror = nmtst_get_rand_bool () ? &_error : NULL; \
		guint32 _v; \
		const guint32 _v_exp = (exp); \
		\
		_v = _nm_utils_parse_tc_handle (""str"", _perror); \
		\
		if (_v != _v_exp) \
			g_error ("%s:%d: \"%s\" gave %08x but %08x expected.", __FILE__, __LINE__, ""str"", _v, _v_exp); \
		\
		if (_v == TC_H_UNSPEC) \
			g_assert (!_perror || *_perror); \
		else \
			g_assert (!_perror || !*_perror); \
		\
	} G_STMT_END

#define _parse_tc_handle_inval(str)           _parse_tc_handle (str, TC_H_UNSPEC)
#define _parse_tc_handle_valid(str, maj, min) _parse_tc_handle (str, TC_H_MAKE (((guint32) (maj)) << 16, ((guint16) (min))))

	_parse_tc_handle_inval ("");
	_parse_tc_handle_inval (" ");
	_parse_tc_handle_inval (" \n");
	_parse_tc_handle_valid ("1", 1, 0);
	_parse_tc_handle_valid(" 1 ", 1, 0);
	_parse_tc_handle_valid ("1:", 1, 0);
	_parse_tc_handle_valid ("1:  ", 1, 0);
	_parse_tc_handle_valid ("1:0", 1, 0);
	_parse_tc_handle_valid ("1   :0", 1, 0);
	_parse_tc_handle_valid ("1   \t\n\f\r:0", 1, 0);
	_parse_tc_handle_inval ("1   \t\n\f\r\v:0");
	_parse_tc_handle_valid (" 1 : 0  ", 1, 0);
	_parse_tc_handle_inval (" \t\v\n1: 0");
	_parse_tc_handle_valid ("1:2", 1, 2);
	_parse_tc_handle_valid ("01:02", 1, 2);
	_parse_tc_handle_inval ("0x01:0x02");
	_parse_tc_handle_valid ("  01:   02", 1, 2);
	_parse_tc_handle_valid ("019:   020", 0x19, 0x20);
	_parse_tc_handle_valid ("FFFF:   020", 0xFFFF, 0x20);
	_parse_tc_handle_valid ("FfFF:   ffff", 0xFFFF, 0xFFFF);
	_parse_tc_handle_valid ("FFFF", 0xFFFF, 0);
	_parse_tc_handle_inval ("0xFFFF");
	_parse_tc_handle_inval ("10000");
	_parse_tc_handle_valid ("\t\n\f\r FFFF", 0xFFFF, 0);
	_parse_tc_handle_inval ("\t\n\f\r \vFFFF");
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

	g_test_add_func ("/libnm/settings/ethtool/1", test_ethtool_1);

	g_test_add_func ("/libnm/settings/sriov/vf", test_sriov_vf);
	g_test_add_func ("/libnm/settings/sriov/vf-dup", test_sriov_vf_dup);
	g_test_add_func ("/libnm/settings/sriov/vf-vlan", test_sriov_vf_vlan);
	g_test_add_func ("/libnm/settings/sriov/setting", test_sriov_setting);
	g_test_add_func ("/libnm/settings/sriov/vlans", test_sriov_parse_vlans);

	g_test_add_func ("/libnm/settings/tc_config/qdisc", test_tc_config_qdisc);
	g_test_add_func ("/libnm/settings/tc_config/action", test_tc_config_action);
	g_test_add_func ("/libnm/settings/tc_config/tfilter", test_tc_config_tfilter);
	g_test_add_func ("/libnm/settings/tc_config/setting/valid", test_tc_config_setting_valid);
	g_test_add_func ("/libnm/settings/tc_config/setting/duplicates", test_tc_config_setting_duplicates);
	g_test_add_func ("/libnm/settings/tc_config/dbus", test_tc_config_dbus);

	g_test_add_func ("/libnm/settings/bridge/vlans", test_bridge_vlans);

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

	g_test_add_data_func ("/libnm/settings/roundtrip-conversion/general/0",   GINT_TO_POINTER (0), test_roundtrip_conversion);
	g_test_add_data_func ("/libnm/settings/roundtrip-conversion/wireguard/1", GINT_TO_POINTER (1), test_roundtrip_conversion);
	g_test_add_data_func ("/libnm/settings/roundtrip-conversion/wireguard/2", GINT_TO_POINTER (2), test_roundtrip_conversion);
	g_test_add_data_func ("/libnm/settings/roundtrip-conversion/general/3",   GINT_TO_POINTER (3), test_roundtrip_conversion);

	g_test_add_data_func ("/libnm/settings/routing-rule/1", GINT_TO_POINTER (0), test_routing_rule);

	g_test_add_func ("/libnm/parse-tc-handle", test_parse_tc_handle);

	g_test_add_func ("/libnm/test_team_setting", test_team_setting);

	return g_test_run ();
}
