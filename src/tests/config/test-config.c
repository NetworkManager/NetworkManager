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
 * Copyright 2013 Red Hat, Inc.
 *
 */

#include "nm-default.h"

#include <unistd.h>

#include "nm-config.h"
#include "nm-test-device.h"
#include "platform/nm-fake-platform.h"
#include "nm-dbus-manager.h"
#include "nm-connectivity.h"

#include "nm-test-utils-core.h"

#define TEST_DIR              NM_BUILD_SRCDIR"/src/tests/config"
#define BUILD_DIR             NM_BUILD_BUILDDIR"/src/tests/config"

/*****************************************************************************/

static void
_assert_config_value (const NMConfigData *config_data, const char *group, const char *key, const char *expected_value, const char *file, int line)
{
	gs_free char *value = NULL;

	value = nm_config_data_get_value (config_data, group, key, NM_CONFIG_GET_VALUE_NONE);
	if (g_strcmp0 (value, expected_value)) {
		g_error ("(%s:%d) invalid value in config-data %s.%s = %s%s%s (instead of %s%s%s)",
		         file, line, group, key,
		         NM_PRINT_FMT_QUOTED (value, "\"", value, "\"", "(null)"),
		         NM_PRINT_FMT_QUOTED (expected_value, "\"", expected_value, "\"", "(null)"));
	}
}
#define assert_config_value(config_data, group, key, expected_value) _assert_config_value (config_data, group, key, expected_value, __FILE__, __LINE__)

#define _config_get_dhcp_client_a(config) \
	({ \
		gs_free char *_s = NULL; \
		\
		_s = nm_config_data_get_value (nm_config_get_data_orig (config), \
		                               NM_CONFIG_KEYFILE_GROUP_MAIN, \
		                               NM_CONFIG_KEYFILE_KEY_MAIN_DHCP, \
		                               NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY); \
		_s ? nm_sprintf_bufa (100, "%s", _s) : NULL; \
	})

/*****************************************************************************/

static NMConfig *
setup_config (GError **error, const char *config_file, const char *intern_config, const char *const* atomic_section_prefixes, const char *config_dir, const char *system_config_dir, ...)
{
	va_list ap;
	GPtrArray *args;
	char **argv, *arg;
	int argc;
	GOptionContext *context;
	gboolean success;
	NMConfig *config;
	GError *local_error = NULL;
	NMConfigCmdLineOptions *cli;

	g_assert (!error || !*error);

	args = g_ptr_array_new ();
	g_ptr_array_add (args, "test-config");
	g_ptr_array_add (args, "--config");
	g_ptr_array_add (args, (char *)config_file);
	if (intern_config) {
		g_ptr_array_add (args, "--intern-config");
		g_ptr_array_add (args, (char *)intern_config);
	}
	g_ptr_array_add (args, "--config-dir");
	g_ptr_array_add (args, (char *)config_dir);
	if (system_config_dir) {
		g_ptr_array_add (args, "--system-config-dir");
		g_ptr_array_add (args, (char *) system_config_dir);
	}

	va_start (ap, system_config_dir);
	while ((arg = va_arg (ap, char *)))
		g_ptr_array_add (args, arg);
	va_end (ap);

	argv = (char **)args->pdata;
	argc = args->len;

	cli = nm_config_cmd_line_options_new (FALSE);

	context = g_option_context_new (NULL);
	nm_config_cmd_line_options_add_to_entries (cli, context);
	success = g_option_context_parse (context, &argc, &argv, NULL);
	g_option_context_free (context);

	if (!success)
		g_printerr ("Invalid options.\n");

	g_ptr_array_free (args, TRUE);

	config = nm_config_setup (cli, (char **) atomic_section_prefixes, &local_error);
	if (error) {
		g_assert (!config);
		g_assert (local_error);
		g_propagate_error (error, local_error);
	} else {
		g_assert (config);
		g_assert_no_error (local_error);
	}
	nm_config_cmd_line_options_free (cli);
	return config;
}

static void
test_config_simple (void)
{
	gs_unref_object NMConfig *config = NULL;
	gs_strfreev char **plugins = NULL;
	char *value;
	gs_unref_object NMDevice *dev50 = nm_test_device_new ("00:00:00:00:00:50");
	gs_unref_object NMDevice *dev51 = nm_test_device_new ("00:00:00:00:00:51");
	gs_unref_object NMDevice *dev52 = nm_test_device_new ("00:00:00:00:00:52");

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, "/no/such/dir", "", NULL);

	g_assert_cmpstr (nm_config_data_get_config_main_file (nm_config_get_data_orig (config)), ==, TEST_DIR "/NetworkManager.conf");
	g_assert_cmpstr (_config_get_dhcp_client_a (config), ==, "dhclient");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpint (nm_config_data_get_connectivity_interval (nm_config_get_data_orig (config)), ==, 100);

	plugins = nm_config_data_get_plugins (nm_config_get_data_orig (config), FALSE);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 3);
	g_assert_cmpstr (plugins[0], ==, "foo");
	g_assert_cmpstr (plugins[1], ==, "bar");
	g_assert_cmpstr (plugins[2], ==, "baz");

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "extra-section", "extra-key", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "some value");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "extra-section", "no-key", NM_CONFIG_GET_VALUE_NONE);
	g_assert (!value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "no-section", "no-key", NM_CONFIG_GET_VALUE_NONE);
	g_assert (!value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "connection", "ipv6.ip6_privacy", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "0");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "connection.dev51", "ipv4.route-metric", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "51");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv6.route-metric", NULL);
	g_assert_cmpstr (value, ==, NULL);
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", NULL);
	g_assert_cmpstr (value, ==, "50");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", dev50);
	g_assert_cmpstr (value, ==, "50");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", dev51);
	g_assert_cmpstr (value, ==, "51");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "ipv4.route-metric", dev52);
	g_assert_cmpstr (value, ==, "52");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test1", dev51);
	g_assert_cmpstr (value, ==, "yes");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test1", dev50);
	g_assert_cmpstr (value, ==, "no");
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test2", dev51);
	g_assert_cmpstr (value, ==, NULL);
	g_free (value);

	value = nm_config_data_get_connection_default (nm_config_get_data_orig (config), "dummy.test2", dev50);
	g_assert_cmpstr (value, ==, "no");
	g_free (value);
}

static void
test_config_non_existent (void)
{
	GError *error = NULL;

	setup_config (&error, TEST_DIR "/no-such-file", "", NULL, "/no/such/dir", "", NULL);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND);
	g_clear_error (&error);
}

static void
test_config_parse_error (void)
{
	GError *error = NULL;

	setup_config (&error, TEST_DIR "/bad.conf", "", NULL, "/no/such/dir", "", NULL);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error (&error);
}

static void
test_config_override (void)
{
	gs_unref_object NMConfig *config = NULL;
	gs_strfreev char **plugins = NULL;

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, "/no/such/dir", "",
	                       "--plugins", "alpha,beta,gamma,delta",
	                       "--connectivity-interval", "12",
	                       NULL);

	g_assert_cmpstr (nm_config_data_get_config_main_file (nm_config_get_data_orig (config)), ==, TEST_DIR "/NetworkManager.conf");
	g_assert_cmpstr (_config_get_dhcp_client_a (config), ==, "dhclient");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpint (nm_config_data_get_connectivity_interval (nm_config_get_data_orig (config)), ==, 12);

	plugins = nm_config_data_get_plugins (nm_config_get_data_orig (config), FALSE);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 4);
	g_assert_cmpstr (plugins[0], ==, "alpha");
	g_assert_cmpstr (plugins[1], ==, "beta");
	g_assert_cmpstr (plugins[2], ==, "gamma");
	g_assert_cmpstr (plugins[3], ==, "delta");
}

static void
test_config_global_dns (void)
{
	NMConfig *config;
	const NMGlobalDnsConfig *dns;
	NMGlobalDnsDomain *domain;
	const char *const*strv;

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL,
	                       "/no/such/dir", "", NULL);

	dns = nm_config_data_get_global_dns_config (nm_config_get_data_orig (config));
	g_assert (dns);

	strv = nm_global_dns_config_get_searches (dns);
	g_assert (strv);
	g_assert_cmpuint (g_strv_length ((char **) strv), ==, 2);
	g_assert_cmpstr (strv[0], ==, "foo.com");
	g_assert_cmpstr (strv[1], ==, "bar.org");

	strv = nm_global_dns_config_get_options (dns);
	g_assert (strv);
	g_assert_cmpuint (g_strv_length ((char **) strv), ==, 2);
	g_assert_cmpstr (strv[0], ==, "debug");
	g_assert_cmpstr (strv[1], ==, "edns0");

	g_assert_cmpuint (nm_global_dns_config_get_num_domains (dns), ==, 2);

	/* Default domain */
	domain = nm_global_dns_config_lookup_domain (dns, "*");
	g_assert (domain);

	strv = nm_global_dns_domain_get_servers (domain);
	g_assert (strv);
	g_assert_cmpuint (g_strv_length ((char **) strv), ==, 2);
	g_assert_cmpstr (strv[0], ==, "1.1.1.1");
	g_assert_cmpstr (strv[1], ==, "1::128");

	strv = nm_global_dns_domain_get_options (domain);
	g_assert (strv);
	g_assert_cmpuint (g_strv_length ((char **) strv), ==, 2);
	g_assert_cmpstr (strv[0], ==, "opt1");
	g_assert_cmpstr (strv[1], ==, "opt2");

	/* 'example.com' domain */
	domain = nm_global_dns_config_lookup_domain (dns, "example.com");
	g_assert (domain);

	strv = nm_global_dns_domain_get_servers (domain);
	g_assert (strv);
	g_assert_cmpuint (g_strv_length ((char **) strv), ==, 1);
	g_assert_cmpstr (strv[0], ==, "2.2.2.2");

	strv = nm_global_dns_domain_get_options (domain);
	g_assert (!strv || g_strv_length ((char **) strv) == 0);

	/* Non-existent domain 'test.com' */
	domain = nm_global_dns_config_lookup_domain (dns, "test.com");
	g_assert (!domain);

	g_object_unref (config);

	/* Check that a file without a default domain section gives a NULL configuration */
	config = setup_config (NULL, TEST_DIR "/global-dns-invalid.conf", "", NULL,
	                       "/no/such/dir", "", NULL);
	dns = nm_config_data_get_global_dns_config (nm_config_get_data_orig (config));
	g_assert (!dns);
	g_object_unref (config);
}

static void
test_config_connectivity_check (void)
{
#if WITH_CONCHECK
	const char *CONFIG_INTERN = BUILD_DIR"/test-connectivity-check-intern.conf";
	NMConfig *config;
	NMConnectivity *connectivity;

	g_assert (g_file_set_contents (CONFIG_INTERN, "", 0, NULL));
	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", CONFIG_INTERN, NULL,
	                       "/no/such/dir", "", NULL);
	connectivity = nm_connectivity_get();

	g_assert (nm_connectivity_check_enabled (connectivity));

	/* disable connectivity checking */
	NMTST_EXPECT_NM_INFO ("config: signal: *");
	nm_config_set_connectivity_check_enabled (config, FALSE);
	g_test_assert_expected_messages ();

	g_assert (!nm_connectivity_check_enabled (connectivity));

	/* re-enable connectivity checking */
	NMTST_EXPECT_NM_INFO ("config: signal: *");
	nm_config_set_connectivity_check_enabled (config, TRUE);
	g_test_assert_expected_messages ();

	g_assert (nm_connectivity_check_enabled (connectivity));

	g_object_unref (connectivity);
	g_object_unref (config);

	g_assert (remove (CONFIG_INTERN) == 0);
#else
	g_test_skip ("concheck disabled");
#endif
}

static void
test_config_no_auto_default (void)
{
	NMConfig *config;
	GError *error = NULL;
	int fd, nwrote;
	char *state_file;
	NMDevice *dev1, *dev2, *dev3, *dev4;

	fd = g_file_open_tmp (NULL, &state_file, &error);
	g_assert_no_error (error);

	nwrote = write (fd, "22:22:22:22:22:22\n", 18);
	g_assert_cmpint (nwrote, ==, 18);
	nwrote = write (fd, "44:44:44:44:44:44\n", 18);
	g_assert_cmpint (nwrote, ==, 18);
	nm_close (fd);

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, "/no/such/dir", "",
	                       "--no-auto-default", state_file,
	                       NULL);

	dev1 = nm_test_device_new ("11:11:11:11:11:11");
	dev2 = nm_test_device_new ("22:22:22:22:22:22");
	dev3 = nm_test_device_new ("33:33:33:33:33:33");
	dev4 = nm_test_device_new ("44:44:44:44:44:44");

	g_assert (nm_config_get_no_auto_default_for_device (config, dev1));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev2));
	g_assert (!nm_config_get_no_auto_default_for_device (config, dev3));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev4));

	NMTST_EXPECT_NM_INFO ("config: signal: NO_AUTO_DEFAULT,no-auto-default *");
	nm_config_set_no_auto_default_for_device (config, dev3);
	g_test_assert_expected_messages ();

	g_assert (nm_config_get_no_auto_default_for_device (config, dev3));

	g_object_unref (config);

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, "/no/such/dir", "",
	                       "--no-auto-default", state_file,
	                       NULL);

	g_assert (nm_config_get_no_auto_default_for_device (config, dev1));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev2));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev3));
	g_assert (nm_config_get_no_auto_default_for_device (config, dev4));

	g_object_unref (config);

	g_object_unref (dev1);
	g_object_unref (dev2);
	g_object_unref (dev3);
	g_object_unref (dev4);

	unlink (state_file);
	g_free (state_file);
}

static void
test_config_confdir (void)
{
	gs_unref_object NMConfig *config = NULL;
	gs_strfreev char **plugins = NULL;
	char *value;
	GSList *specs;

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "", NULL);

	g_assert_cmpstr (nm_config_data_get_config_main_file (nm_config_get_data_orig (config)), ==, TEST_DIR "/NetworkManager.conf");
	g_assert_cmpstr (_config_get_dhcp_client_a (config), ==, "dhcpcd");
	g_assert_cmpstr (nm_config_get_log_level (config), ==, "INFO");
	g_assert_cmpstr (nm_config_get_log_domains (config), ==, "PLATFORM,DNS,WIFI");
	g_assert_cmpstr (nm_config_data_get_connectivity_uri (nm_config_get_data_orig (config)), ==, "http://example.net");
	g_assert_cmpint (nm_config_data_get_connectivity_interval (nm_config_get_data_orig (config)), ==, 100);

	plugins = nm_config_data_get_plugins (nm_config_get_data_orig (config), FALSE);
	g_assert_cmpint (g_strv_length ((char **)plugins), ==, 5);
	g_assert_cmpstr (plugins[0], ==, "foo");
	g_assert_cmpstr (plugins[1], ==, "bar");
	g_assert_cmpstr (plugins[2], ==, "baz");
	g_assert_cmpstr (plugins[3], ==, "one");
	g_assert_cmpstr (plugins[4], ==, "two");

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "main", "extra", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "hello");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "main", "no-auto-default", NM_CONFIG_GET_VALUE_TYPE_SPEC);
	specs = nm_match_spec_split (value);
	g_free (value);
	g_assert_cmpint (g_slist_length (specs), ==, 2);
	g_assert_cmpstr (g_slist_nth_data (specs, 0), ==, "spec2");
	g_assert_cmpstr (g_slist_nth_data (specs, 1), ==, "spec3");
	g_slist_free_full (specs, g_free);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "main", "ignore-carrier", NM_CONFIG_GET_VALUE_TYPE_SPEC);
	specs = nm_match_spec_split (value);
	g_free (value);
	g_assert_cmpint (g_slist_length (specs), ==, 2);
	g_assert_cmpstr (g_slist_nth_data (specs, 0), ==, "  space1  ");
	g_assert_cmpstr (g_slist_nth_data (specs, 1), ==, " space2\t");
	g_slist_free_full (specs, g_free);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST".0", "new", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "something"); /* not ",something" */
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), "order", "a", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "90");
	g_free (value);
	value = nm_config_data_get_value (nm_config_get_data_orig (config), "order", "b", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "10");
	g_free (value);
	value = nm_config_data_get_value (nm_config_get_data_orig (config), "order", "c", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "0");
	g_free (value);

	g_assert (!nm_config_data_has_value (nm_config_get_data_orig (config), "appendable-test", "non-appendable-key1", NM_CONFIG_GET_VALUE_RAW));
	g_assert (!nm_config_data_has_value (nm_config_get_data_orig (config), "appendable-test", "non-appendable-key1+", NM_CONFIG_GET_VALUE_RAW));
	g_assert (!nm_config_data_has_value (nm_config_get_data_orig (config), "appendable-test", "non-appendable-key1-", NM_CONFIG_GET_VALUE_RAW));
	g_assert (!nm_config_data_has_value (nm_config_get_data_orig (config), "appendable-test", "non-appendable-key2", NM_CONFIG_GET_VALUE_RAW));
	g_assert (!nm_config_data_has_value (nm_config_get_data_orig (config), "appendable-test", "non-appendable-key2+", NM_CONFIG_GET_VALUE_RAW));
	g_assert (!nm_config_data_has_value (nm_config_get_data_orig (config), "appendable-test", "non-appendable-key2-", NM_CONFIG_GET_VALUE_RAW));

#define ASSERT_GET_CONN_DEFAULT(xconfig, xname, xvalue) \
	G_STMT_START { \
		gs_free char *_value = nm_config_data_get_connection_default (nm_config_get_data_orig (xconfig), (xname), NULL); \
		g_assert_cmpstr (_value, ==, (xvalue)); \
	} G_STMT_END
	ASSERT_GET_CONN_DEFAULT (config, "ord.key00", "A-0.0.00");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key01", "A-0.3.01");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key02", "A-0.2.02");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key03", "A-0.1.03");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key04", "B-1.3.04");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key05", "B-1.2.05");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key06", "B-1.1.06");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key07", "C-2.3.07");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key08", "C-2.2.08");
	ASSERT_GET_CONN_DEFAULT (config, "ord.key09", "C-2.1.09");
	ASSERT_GET_CONN_DEFAULT (config, "ord.ovw01", "C-0.1.ovw01");

	value = nm_config_data_get_value (nm_config_get_data_orig (config), NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST".1", "val1", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "a,c");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST".1", "val2", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "VAL2");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST".1", "val3", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, NULL);
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST".1", "val4", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "vb,vb");
	g_free (value);

	value = nm_config_data_get_value (nm_config_get_data_orig (config), NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST".1", "val5", NM_CONFIG_GET_VALUE_NONE);
	g_assert_cmpstr (value, ==, "VAL5");
	g_free (value);

	nm_config_data_log (nm_config_get_data_orig (config), ">>> TEST: ", " ", NULL);
}

static void
test_config_confdir_parse_error (void)
{
	GError *error = NULL;

	/* Using TEST_DIR as the conf dir will pick up bad.conf */
	setup_config (&error, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR, "", NULL);
	g_assert_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE);
	g_clear_error (&error);
}

/*****************************************************************************/

typedef void (*TestSetValuesUserSetFcn) (NMConfig *config, gboolean is_user, GKeyFile *keyfile_user, NMConfigChangeFlags *out_expected_changes);
typedef void (*TestSetValuesCheckStateFcn) (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data);

typedef struct {
	NMConfigChangeFlags changes;
	TestSetValuesCheckStateFcn check_state_fcn;
} TestSetValuesConfigChangedData;

static void
_set_values_config_changed_cb (NMConfig *config,
                               NMConfigData *config_data,
                               NMConfigChangeFlags changes,
                               NMConfigData *old_data,
                               TestSetValuesConfigChangedData *config_changed_data)
{
	g_assert (changes != NM_CONFIG_CHANGE_NONE);
	g_assert (config_changed_data);
	g_assert (config_changed_data->changes == NM_CONFIG_CHANGE_NONE);

	if (changes == NM_CONFIG_CHANGE_CAUSE_SIGHUP)
		return;
	changes &= ~NM_CONFIG_CHANGE_CAUSE_SIGHUP;

	config_changed_data->changes = changes;

	if (config_changed_data->check_state_fcn)
		config_changed_data->check_state_fcn (config, config_data, TRUE, changes, old_data);
}

static void
_set_values_user (NMConfig *config,
                  const char *CONFIG_USER,
                  TestSetValuesUserSetFcn set_fcn,
                  TestSetValuesCheckStateFcn check_state_fcn)
{
	GKeyFile *keyfile_user;
	gboolean success;
	gs_free_error GError *error = NULL;
	TestSetValuesConfigChangedData config_changed_data = {
		.changes = NM_CONFIG_CHANGE_NONE,
		.check_state_fcn = check_state_fcn,
	};
	NMConfigChangeFlags expected_changes = NM_CONFIG_CHANGE_NONE;
	gs_unref_object NMConfigData *config_data_before = NULL;

	keyfile_user = nm_config_create_keyfile ();

	success = g_key_file_load_from_file (keyfile_user, CONFIG_USER, G_KEY_FILE_NONE, &error);
	nmtst_assert_success (success, error);

	if (set_fcn)
		set_fcn (config, TRUE, keyfile_user, &expected_changes);

	success = g_key_file_save_to_file (keyfile_user, CONFIG_USER, &error);
	nmtst_assert_success (success, error);

	g_signal_connect (G_OBJECT (config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_set_values_config_changed_cb),
	                  &config_changed_data);

	config_data_before = g_object_ref (nm_config_get_data (config));

	if (expected_changes != NM_CONFIG_CHANGE_NONE)
		NMTST_EXPECT_NM_INFO ("config: signal: *");
	else
		NMTST_EXPECT_NM_INFO ("config: signal: SIGHUP (no changes from disk)*");

	nm_config_reload (config, NM_CONFIG_CHANGE_CAUSE_SIGHUP);

	g_test_assert_expected_messages ();

	g_assert (expected_changes == config_changed_data.changes);

	if (check_state_fcn)
		check_state_fcn (config, nm_config_get_data (config), FALSE, NM_CONFIG_CHANGE_NONE, config_data_before);

	g_signal_handlers_disconnect_by_func (config, _set_values_config_changed_cb, &config_changed_data);

	g_key_file_unref (keyfile_user);
}

static void
_set_values_intern (NMConfig *config,
                    TestSetValuesUserSetFcn set_fcn,
                    TestSetValuesCheckStateFcn check_state_fcn)
{
	GKeyFile *keyfile_intern;
	TestSetValuesConfigChangedData config_changed_data = {
		.changes = NM_CONFIG_CHANGE_NONE,
		.check_state_fcn = check_state_fcn,
	};
	NMConfigChangeFlags expected_changes = NM_CONFIG_CHANGE_NONE;
	gs_unref_object NMConfigData *config_data_before = NULL;

	config_data_before = g_object_ref (nm_config_get_data (config));

	keyfile_intern = nm_config_data_clone_keyfile_intern (config_data_before);

	if (set_fcn)
		set_fcn (config, FALSE, keyfile_intern, &expected_changes);

	g_signal_connect (G_OBJECT (config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_set_values_config_changed_cb),
	                  &config_changed_data);

	if (expected_changes != NM_CONFIG_CHANGE_NONE)
		NMTST_EXPECT_NM_INFO ("config: signal: *");

	nm_config_set_values (config, keyfile_intern, TRUE, FALSE);

	g_test_assert_expected_messages ();

	g_assert (expected_changes == config_changed_data.changes);

	if (check_state_fcn)
		check_state_fcn (config, nm_config_get_data (config), FALSE, NM_CONFIG_CHANGE_NONE, config_data_before);

	g_signal_handlers_disconnect_by_func (config, _set_values_config_changed_cb, &config_changed_data);

	g_key_file_unref (keyfile_intern);
}

static void
_set_values_user_intern_section_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"section1", "key", "this-should-be-ignored");
}

static void
_set_values_user_intern_section_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	g_assert (changes == NM_CONFIG_CHANGE_NONE);
	g_assert (!nm_config_data_has_group (config_data, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"section1"));
}

static void
_set_values_user_initial_values_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	g_key_file_remove_group (keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"section1", NULL);
	g_key_file_set_string (keyfile, "section1", "key1", "value1");
	*out_expected_changes = NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER;
}

static void
_set_values_user_initial_values_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	if (is_change_event)
		g_assert (changes == (NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER));
	assert_config_value (config_data, "section1", "key1", "value1");
}

static void
_set_values_intern_internal_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"section1", "key", "internal-section");
	*out_expected_changes = NM_CONFIG_CHANGE_CAUSE_SET_VALUES | NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN;
}

static void
_set_values_intern_internal_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	if (is_change_event)
		g_assert (changes == (NM_CONFIG_CHANGE_CAUSE_SET_VALUES | NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN));
	assert_config_value (config_data, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"section1", "key", "internal-section");
}

static void
_set_values_user_atomic_section_1_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", "key1", "user-value1");
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", "key2", "user-value2");
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-b", "key1", "user-value1");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key1", "user-value1");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key2", "user-value2");
	*out_expected_changes = NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER;
}

static void
_set_values_user_atomic_section_1_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	if (is_change_event)
		g_assert (changes == (NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER));
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key1", "user-value1");
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key2", "user-value2");
	assert_config_value (config_data, "atomic-prefix-1.section-b", "key1", "user-value1");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key1", "user-value1");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key2", "user-value2");
}

static void
_set_values_intern_atomic_section_1_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", "key1", "intern-value1");
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", "key3", "intern-value3");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key1", "intern-value1");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key3", "intern-value3");
	*out_expected_changes = NM_CONFIG_CHANGE_CAUSE_SET_VALUES | NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN;
}

static void
_set_values_intern_atomic_section_1_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	if (is_change_event)
		g_assert (changes == (NM_CONFIG_CHANGE_CAUSE_SET_VALUES | NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN));
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key1", "intern-value1");
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key2", NULL);
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key3", "intern-value3");
	assert_config_value (config_data, "atomic-prefix-1.section-b", "key1", "user-value1");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key1", "intern-value1");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key2", "user-value2");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key3", "intern-value3");
	g_assert ( nm_config_data_is_intern_atomic_group (config_data, "atomic-prefix-1.section-a"));
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "atomic-prefix-1.section-b"));
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "non-atomic-prefix-1.section-a"));
}

static void
_set_values_user_atomic_section_2_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", "key1", "user-value1-x");
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", "key2", "user-value2");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key1", "user-value1-x");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key2", "user-value2-x");
	*out_expected_changes = NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER | NM_CONFIG_CHANGE_VALUES_INTERN;
}

static void
_set_values_user_atomic_section_2_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	if (is_change_event)
		g_assert (changes == (NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_USER | NM_CONFIG_CHANGE_VALUES_INTERN));
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key1", "user-value1-x");
	assert_config_value (config_data, "atomic-prefix-1.section-a", "key2", "user-value2");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key1", "user-value1-x");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key2", "user-value2-x");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key3", "intern-value3");
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "atomic-prefix-1.section-a"));
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "atomic-prefix-1.section-b"));
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "non-atomic-prefix-1.section-a"));
}

static void
_set_values_intern_atomic_section_2_set (NMConfig *config, gboolean set_user, GKeyFile *keyfile, NMConfigChangeFlags *out_expected_changes)
{
	/* let's hide an atomic section and one key. */
	g_key_file_set_string (keyfile, "atomic-prefix-1.section-a", NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, "any-value");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", NM_CONFIG_KEYFILE_KEYPREFIX_WAS"nap1-key1", "any-value");
	g_key_file_set_string (keyfile, "non-atomic-prefix-1.section-a", "nap1-key3", "intern-value3");
	g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"with-whitespace", "key1", " b c\\,  d  ");
	g_key_file_set_value  (keyfile, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"with-whitespace", "key2", " b c\\,  d  ");
	*out_expected_changes = NM_CONFIG_CHANGE_CAUSE_SET_VALUES | NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN;
}

static void
_set_values_intern_atomic_section_2_check (NMConfig *config, NMConfigData *config_data, gboolean is_change_event, NMConfigChangeFlags changes, NMConfigData *old_data)
{
	if (is_change_event)
		g_assert (changes == (NM_CONFIG_CHANGE_CAUSE_SET_VALUES | NM_CONFIG_CHANGE_VALUES | NM_CONFIG_CHANGE_VALUES_INTERN));
	g_assert (!nm_config_data_has_group (config_data, "atomic-prefix-1.section-a"));
	assert_config_value (config_data, "atomic-prefix-1.section-b", "key1", "user-value1");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key1", NULL);
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key2", "user-value2-x");
	assert_config_value (config_data, "non-atomic-prefix-1.section-a", "nap1-key3", "intern-value3");
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "atomic-prefix-1.section-a"));
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "atomic-prefix-1.section-b"));
	g_assert (!nm_config_data_is_intern_atomic_group (config_data, "non-atomic-prefix-1.section-a"));
	assert_config_value (config_data, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"with-whitespace", "key1", " b c\\,  d  ");
	assert_config_value (config_data, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN"with-whitespace", "key2", " b c\\,  d  ");
}

static void
test_config_set_values (void)
{
	gs_unref_object NMConfig *config = NULL;
	const char *CONFIG_USER = BUILD_DIR"/test-set-values-user.conf";
	const char *CONFIG_INTERN = BUILD_DIR"/test-set-values-intern.conf";
	const char *atomic_section_prefixes[] = {
		"atomic-prefix-1.",
		"atomic-prefix-2.",
		NULL,
	};

	g_assert (g_file_set_contents (CONFIG_USER, "", 0, NULL));
	g_assert (g_file_set_contents (CONFIG_INTERN, "", 0, NULL));

	config = setup_config (NULL, CONFIG_USER, CONFIG_INTERN, atomic_section_prefixes, "", "", NULL);

	_set_values_user (config, CONFIG_USER,
	                  _set_values_user_intern_section_set,
	                  _set_values_user_intern_section_check);

	_set_values_user (config, CONFIG_USER,
	                  _set_values_user_initial_values_set,
	                  _set_values_user_initial_values_check);

	_set_values_intern (config,
	                    _set_values_intern_internal_set,
	                    _set_values_intern_internal_check);

	_set_values_user (config, CONFIG_USER,
	                  _set_values_user_atomic_section_1_set,
	                  _set_values_user_atomic_section_1_check);

	_set_values_intern (config,
	                    _set_values_intern_atomic_section_1_set,
	                    _set_values_intern_atomic_section_1_check);

	_set_values_user (config, CONFIG_USER,
	                  _set_values_user_atomic_section_2_set,
	                  _set_values_user_atomic_section_2_check);

	_set_values_intern (config,
	                    _set_values_intern_atomic_section_2_set,
	                    _set_values_intern_atomic_section_2_check);

	g_assert (remove (CONFIG_USER) == 0);
	g_assert (remove (CONFIG_INTERN) == 0);
}

/*****************************************************************************/

static void
_test_signal_config_changed_cb (NMConfig *config,
                                NMConfigData *config_data,
                                NMConfigChangeFlags changes,
                                NMConfigData *old_data,
                                gpointer user_data)
{
	const NMConfigChangeFlags *expected = user_data;

	g_assert (changes);
	g_assert_cmpint (changes, ==, *expected);
	g_assert (NM_IS_CONFIG (config));
	g_assert (NM_IS_CONFIG_DATA (config_data));

	g_assert (config_data == old_data);
	g_assert (config_data == nm_config_get_data (config));
}

static void
_test_signal_config_changed_cb2 (NMConfig *config,
                                 NMConfigData *config_data,
                                 NMConfigChangeFlags changes,
                                 NMConfigData *old_data,
                                 gpointer user_data)
{
	const NMConfigChangeFlags *expected = user_data;

	g_assert (changes);
	g_assert_cmpint (changes, ==, *expected);
}

static void
test_config_signal (void)
{
	gs_unref_object NMConfig *config = NULL;
	NMConfigChangeFlags expected;
	gs_unref_object NMConfigData *config_data_orig = NULL;

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "", NULL);

	config_data_orig = g_object_ref (nm_config_get_data_orig (config));

	g_signal_connect (G_OBJECT (config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_test_signal_config_changed_cb),
	                  &expected);

	expected = NM_CONFIG_CHANGE_CAUSE_SIGUSR1;
	NMTST_EXPECT_NM_INFO ("config: signal: SIGUSR1");
	nm_config_reload (config, expected);

	expected = NM_CONFIG_CHANGE_CAUSE_SIGUSR2;
	NMTST_EXPECT_NM_INFO ("config: signal: SIGUSR2");
	nm_config_reload (config, expected);

	expected = NM_CONFIG_CHANGE_CAUSE_SIGHUP;
	NMTST_EXPECT_NM_INFO ("config: signal: SIGHUP (no changes from disk)*");
	nm_config_reload (config, expected);

	/* test with subscribing two signals...
	 *
	 * This test exposes glib bug https://bugzilla.redhat.com/show_bug.cgi?id=1260577
	 * for which we however have a workaround in 'nm-config.c' */
	g_signal_connect (G_OBJECT (config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_test_signal_config_changed_cb2),
	                  &expected);
	expected = NM_CONFIG_CHANGE_CAUSE_SIGUSR2;
	NMTST_EXPECT_NM_INFO ("config: signal: SIGUSR2");
	nm_config_reload (config, NM_CONFIG_CHANGE_CAUSE_SIGUSR2);
	g_signal_handlers_disconnect_by_func (config, _test_signal_config_changed_cb2, &expected);

	g_signal_handlers_disconnect_by_func (config, _test_signal_config_changed_cb, &expected);

	g_assert (config_data_orig == nm_config_get_data (config));
}

/*****************************************************************************/

static void
test_config_enable (void)
{
	gs_unref_object NMConfig *config = NULL;
	guint match_nm_version = _nm_config_match_nm_version;
	char *match_env = g_strdup (_nm_config_match_env);

	g_clear_pointer (&_nm_config_match_env, g_free);
	_nm_config_match_env = g_strdup ("something-else");

	_nm_config_match_nm_version = nm_encode_version (1, 3, 4);
	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "", NULL);
	assert_config_value (nm_config_get_data_orig (config), "test-group-config-enable-1", "key1", NULL);
	g_clear_object (&config);

	_nm_config_match_nm_version = nm_encode_version (1, 5, 32);
	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "", NULL);
	assert_config_value (nm_config_get_data_orig (config), "test-group-config-enable-1", "key1", "enabled");
	g_clear_object (&config);

	_nm_config_match_nm_version = nm_encode_version (1, 5, 3);
	g_clear_pointer (&_nm_config_match_env, g_free);
	_nm_config_match_env = g_strdup ("test-match-env-1");
	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "", NULL);
	assert_config_value (nm_config_get_data_orig (config), "test-group-config-enable-1", "key1", "enabled");
	g_clear_object (&config);

	_nm_config_match_nm_version = match_nm_version;
	g_clear_pointer (&_nm_config_match_env, g_free);
	_nm_config_match_env = match_env;
}

/*****************************************************************************/

static void
test_config_state_file (void)
{
	NMConfig *config;
	const NMConfigState *state;
	gs_free_error GError *error = NULL;
	gboolean ret;
	gs_free char *file_data = NULL;
	gsize file_size;
	const char *const TMP_FILE = BUILD_DIR "/tmp.state";

	ret = g_file_get_contents (TEST_DIR "/NetworkManager.state", &file_data, &file_size, &error);
	nmtst_assert_success (ret, error);
	ret = g_file_set_contents (TMP_FILE, file_data, file_size, &error);
	nmtst_assert_success (ret, error);

	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "",
	                       "--state-file", TMP_FILE, NULL);
	g_assert (config);

	state = nm_config_state_get (config);
	g_assert (state);

	g_assert_cmpint (state->net_enabled, ==, TRUE);
	g_assert_cmpint (state->wifi_enabled, ==, TRUE);
	g_assert_cmpint (state->wwan_enabled, ==, TRUE);

	nm_config_state_set (config, TRUE, TRUE,
	                     NM_CONFIG_STATE_PROPERTY_NETWORKING_ENABLED, FALSE,
	                     NM_CONFIG_STATE_PROPERTY_WIFI_ENABLED, TRUE,
	                     NM_CONFIG_STATE_PROPERTY_WWAN_ENABLED, FALSE);

	state = nm_config_state_get (config);
	g_assert (state);

	g_assert_cmpint (state->net_enabled, ==, FALSE);
	g_assert_cmpint (state->wifi_enabled, ==, TRUE);
	g_assert_cmpint (state->wwan_enabled, ==, FALSE);

	g_object_unref (config);

	/* Reload configuration */
	config = setup_config (NULL, TEST_DIR "/NetworkManager.conf", "", NULL, TEST_DIR "/conf.d", "",
	                       "--state-file", TMP_FILE, NULL);
	g_assert (config);

	state = nm_config_state_get (config);
	g_assert (state);

	g_assert_cmpint (state->net_enabled, ==, FALSE);
	g_assert_cmpint (state->wifi_enabled, ==, TRUE);
	g_assert_cmpint (state->wwan_enabled, ==, FALSE);

	g_object_unref (config);
	unlink (TMP_FILE);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "DEFAULT");

	nm_fake_platform_setup ();

	g_test_add_func ("/config/simple", test_config_simple);
	g_test_add_func ("/config/non-existent", test_config_non_existent);
	g_test_add_func ("/config/parse-error", test_config_parse_error);
	g_test_add_func ("/config/no-auto-default", test_config_no_auto_default);
	g_test_add_func ("/config/confdir", test_config_confdir);
	g_test_add_func ("/config/confdir-parse-error", test_config_confdir_parse_error);

	g_test_add_func ("/config/set-values", test_config_set_values);
	g_test_add_func ("/config/global-dns", test_config_global_dns);
	g_test_add_func ("/config/connectivity-check", test_config_connectivity_check);

	g_test_add_func ("/config/signal", test_config_signal);

	g_test_add_func ("/config/enable", test_config_enable);

	g_test_add_func ("/config/state-file", test_config_state_file);

	/* This one has to come last, because it leaves its values in
	 * nm-config.c's global variables, and there's no way to reset
	 * those to NULL.
	 */
	g_test_add_func ("/config/override", test_config_override);

	return g_test_run ();
}

