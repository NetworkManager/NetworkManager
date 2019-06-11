/* nm-platform.c - Handle runtime kernel networking configuration
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "n-acd/src/n-acd.h"

#include "devices/nm-acd-manager.h"
#include "platform/tests/test-common.h"

#define IFACE_VETH0 "nm-test-veth0"
#define IFACE_VETH1 "nm-test-veth1"

#define ADDR1 0x01010101
#define ADDR2 0x02020202
#define ADDR3 0x03030303
#define ADDR4 0x04040404

/*****************************************************************************/

static gboolean
_skip_acd_test_check (void)
{
	NAcd *acd;
	NAcdConfig *config;
	const guint8 hwaddr[ETH_ALEN] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
	int r;
	static int skip = -1;

	if (skip == -1) {
		r = n_acd_config_new (&config);
		g_assert (r == 0);

		n_acd_config_set_ifindex (config, 1);
		n_acd_config_set_transport (config, N_ACD_TRANSPORT_ETHERNET);
		n_acd_config_set_mac (config, hwaddr, sizeof (hwaddr));

		r = n_acd_new (&acd, config);
		n_acd_config_free (config);
		if (r == 0)
			n_acd_unref (acd);

		skip = (r != 0);
	}
	return skip;
}

#define _skip_acd_test() \
	({ \
		gboolean _skip = _skip_acd_test_check (); \
		\
		if (_skip) \
			g_test_skip ("Cannot create NAcd. Running under valgind?"); \
		_skip; \
	})

/*****************************************************************************/

typedef struct {
	int ifindex0;
	int ifindex1;
	const guint8 *hwaddr0;
	const guint8 *hwaddr1;
	size_t hwaddr0_len;
	size_t hwaddr1_len;
} test_fixture;

static void
fixture_setup (test_fixture *fixture, gconstpointer user_data)
{
	/* create veth pair. */
	fixture->ifindex0 = nmtstp_link_veth_add (NM_PLATFORM_GET, -1, IFACE_VETH0, IFACE_VETH1)->ifindex;
	fixture->ifindex1 = nmtstp_link_get_typed (NM_PLATFORM_GET, -1, IFACE_VETH1, NM_LINK_TYPE_VETH)->ifindex;

	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, fixture->ifindex0, NULL));
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, fixture->ifindex1, NULL));

	fixture->hwaddr0 = nm_platform_link_get_address (NM_PLATFORM_GET, fixture->ifindex0, &fixture->hwaddr0_len);
	fixture->hwaddr1 = nm_platform_link_get_address (NM_PLATFORM_GET, fixture->ifindex1, &fixture->hwaddr1_len);
}

typedef struct {
	in_addr_t addresses[8];
	in_addr_t peer_addresses[8];
	gboolean expected_result[8];
} TestInfo;

static void
acd_manager_probe_terminated (NMAcdManager *acd_manager, gpointer user_data)
{
	g_main_loop_quit (user_data);
}

static void
test_acd_common (test_fixture *fixture, TestInfo *info)
{
	nm_auto_free_acdmgr NMAcdManager *manager = NULL;
	nm_auto_unref_gmainloop GMainLoop *loop = NULL;
	int i;
	const guint WAIT_TIME_OPTIMISTIC = 50;
	guint wait_time;
	static const NMAcdCallbacks callbacks = {
		.probe_terminated_callback = acd_manager_probe_terminated,
		.user_data_destroy         = (GDestroyNotify) g_main_loop_unref,
	};
	int r;

	if (_skip_acd_test ())
		return;

	/* first, try with a short waittime. We hope that this is long enough
	 * to successfully complete the test. Only if that's not the case, we
	 * assume the computer is currently busy (high load) and we retry with
	 * a longer timeout. */
	wait_time = WAIT_TIME_OPTIMISTIC;
again:

	nm_clear_pointer (&loop, g_main_loop_unref);
	loop = g_main_loop_new (NULL, FALSE);

	nm_clear_pointer (&manager, nm_acd_manager_free);
	manager = nm_acd_manager_new (fixture->ifindex0,
	                              fixture->hwaddr0,
	                              fixture->hwaddr0_len,
	                              &callbacks,
	                              g_main_loop_ref (loop));
	g_assert (manager != NULL);

	for (i = 0; info->addresses[i]; i++)
		g_assert (nm_acd_manager_add_address (manager, info->addresses[i]));

	for (i = 0; info->peer_addresses[i]; i++) {
		nmtstp_ip4_address_add (NULL, FALSE, fixture->ifindex1, info->peer_addresses[i],
		                        24, 0, 3600, 1800, 0, NULL);
	}

	r = nm_acd_manager_start_probe (manager, wait_time);
	g_assert_cmpint (r, ==, 0);

	g_assert (nmtst_main_loop_run (loop, 2000));

	for (i = 0; info->addresses[i]; i++) {
		gboolean val;
		char sbuf[NM_UTILS_INET_ADDRSTRLEN];

		val = nm_acd_manager_check_address (manager, info->addresses[i]);
		if (val == info->expected_result[i])
			continue;

		if (wait_time == WAIT_TIME_OPTIMISTIC) {
			/* probably we just had a glitch and the system took longer than
			 * expected. Re-verify with a large timeout this time. */
			wait_time = 1000;
			goto again;
		}

		g_error ("expected check for address #%d (%s) to %s, but it didn't",
		         i, nm_utils_inet4_ntop (info->addresses[i], sbuf),
		         info->expected_result[i] ? "detect no duplicated" : "detect a duplicate");
	}
}

static void
test_acd_probe_1 (test_fixture *fixture, gconstpointer user_data)
{
	TestInfo info = { .addresses       = { ADDR1, ADDR2, ADDR3 },
	                  .peer_addresses  = { ADDR4 },
	                  .expected_result = { TRUE, TRUE, TRUE } };

	test_acd_common (fixture, &info);
}

static void
test_acd_probe_2 (test_fixture *fixture, gconstpointer user_data)
{
	TestInfo info = { .addresses       = { ADDR1, ADDR2, ADDR3, ADDR4 },
	                  .peer_addresses  = { ADDR3, ADDR2 },
	                  .expected_result = { TRUE, FALSE, FALSE, TRUE } };

	test_acd_common (fixture, &info);
}

static void
test_acd_announce (test_fixture *fixture, gconstpointer user_data)
{
	nm_auto_free_acdmgr NMAcdManager *manager = NULL;
	nm_auto_unref_gmainloop GMainLoop *loop = NULL;
	int r;

	if (_skip_acd_test ())
		return;

	manager = nm_acd_manager_new (fixture->ifindex0,
	                              fixture->hwaddr0,
	                              fixture->hwaddr0_len,
	                              NULL,
	                              NULL);
	g_assert (manager != NULL);

	g_assert (nm_acd_manager_add_address (manager, ADDR1));
	g_assert (nm_acd_manager_add_address (manager, ADDR2));

	loop = g_main_loop_new (NULL, FALSE);
	r = nm_acd_manager_announce_addresses (manager);
	g_assert_cmpint (r, ==, 0);
	g_assert (!nmtst_main_loop_run (loop, 200));
}

static void
fixture_teardown (test_fixture *fixture, gconstpointer user_data)
{
	nm_platform_link_delete (NM_PLATFORM_GET, fixture->ifindex0);
	nm_platform_link_delete (NM_PLATFORM_GET, fixture->ifindex1);
}

NMTstpSetupFunc const _nmtstp_setup_platform_func = nm_linux_platform_setup;

void
_nmtstp_init_tests (int *argc, char ***argv)
{
	nmtst_init_with_logging (argc, argv, NULL, "ALL");
}

void
_nmtstp_setup_tests (void)
{
	g_test_add ("/acd/probe/1", test_fixture, NULL, fixture_setup, test_acd_probe_1, fixture_teardown);
	g_test_add ("/acd/probe/2", test_fixture, NULL, fixture_setup, test_acd_probe_2, fixture_teardown);
	g_test_add ("/acd/announce", test_fixture, NULL, fixture_setup, test_acd_announce, fixture_teardown);
}
