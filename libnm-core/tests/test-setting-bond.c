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
 * Copyright 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-utils.h"
#include "nm-setting-bond.h"
#include "nm-connection.h"
#include "nm-simple-connection.h"
#include "nm-setting-connection.h"
#include "nm-errors.h"

#include "nm-test-utils.h"

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
test_verify (void)
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
test_compare_options (gboolean exp_res, const char **opts1, const char **opts2)
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
test_compare (void)
{
	test_compare_options (TRUE,
	                      ((const char *[]){ "mode", "balance-rr", "miimon", "1", NULL }),
	                      ((const char *[]){ "mode", "balance-rr", "miimon", "1", NULL }));
	test_compare_options (FALSE,
	                      ((const char *[]){ "mode", "balance-rr", "miimon", "1", NULL }),
	                      ((const char *[]){ "mode", "balance-rr", "miimon", "2", NULL }));

	/* ignore default values */
	test_compare_options (TRUE,
	                      ((const char *[]){ "miimon", "1", NULL }),
	                      ((const char *[]){ "miimon", "1", "updelay", "0", NULL }));

	/* special handling of num_grat_arp, num_unsol_na */
	test_compare_options (FALSE,
	                      ((const char *[]){ "num_grat_arp", "2", NULL }),
	                      ((const char *[]){ "num_grat_arp", "1", NULL }));
	test_compare_options (TRUE,
	                      ((const char *[]){ "num_grat_arp", "3", NULL }),
	                      ((const char *[]){ "num_unsol_na", "3", NULL }));
	test_compare_options (TRUE,
	                      ((const char *[]){ "num_grat_arp", "4", NULL }),
	                      ((const char *[]){ "num_unsol_na", "4", "num_grat_arp", "4", NULL }));
}

#define TPATH "/libnm/settings/bond/"

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init (&argc, &argv, TRUE);

	g_test_add_func (TPATH "verify", test_verify);
	g_test_add_func (TPATH "compare", test_compare);

	return g_test_run ();
}
