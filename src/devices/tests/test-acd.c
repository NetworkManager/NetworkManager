/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include "devices/nm-acd-manager.h"
#include "platform/tests/test-common.h"

#define IFACE_VETH0 "nm-test-veth0"
#define IFACE_VETH1 "nm-test-veth1"

#define ADDR1 0x01010101
#define ADDR2 0x02020202
#define ADDR3 0x03030303
#define ADDR4 0x04040404

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
acd_manager_probe_terminated (NMAcdManager *acd_manager, GMainLoop *loop)
{
	g_main_loop_quit (loop);
}

static void
test_acd_common (test_fixture *fixture, TestInfo *info)
{
	gs_unref_object NMAcdManager *manager = NULL;
	GMainLoop *loop;
	int i;
	const guint WAIT_TIME_OPTIMISTIC = 50;
	guint wait_time;
	gulong signal_id;

	/* first, try with a short waittime. We hope that this is long enough
	 * to successfully complete the test. Only if that's not the case, we
	 * assume the computer is currently busy (high load) and we retry with
	 * a longer timeout. */
	wait_time = WAIT_TIME_OPTIMISTIC;
again:

	manager = nm_acd_manager_new (fixture->ifindex0, fixture->hwaddr0, fixture->hwaddr0_len);
	g_assert (manager != NULL);

	for (i = 0; info->addresses[i]; i++)
		g_assert (nm_acd_manager_add_address (manager, info->addresses[i]));

	for (i = 0; info->peer_addresses[i]; i++) {
		nmtstp_ip4_address_add (NULL, FALSE, fixture->ifindex1, info->peer_addresses[i],
		                        24, 0, 3600, 1800, 0, NULL);
	}

	loop = g_main_loop_new (NULL, FALSE);
	signal_id = g_signal_connect (manager, NM_ACD_MANAGER_PROBE_TERMINATED,
	                              G_CALLBACK (acd_manager_probe_terminated), loop);
	g_assert (nm_acd_manager_start_probe (manager, wait_time));
	g_assert (nmtst_main_loop_run (loop, 2000));
	g_signal_handler_disconnect (manager, signal_id);
	g_main_loop_unref (loop);

	for (i = 0; info->addresses[i]; i++) {
		gboolean val;

		val = nm_acd_manager_check_address (manager, info->addresses[i]);
		if (val == info->expected_result[i])
			continue;

		if (wait_time == WAIT_TIME_OPTIMISTIC) {
			/* probably we just had a glitch and the system took longer than
			 * expected. Re-verify with a large timeout this time. */
			wait_time = 1000;
			g_clear_object (&manager);
			goto again;
		}

		g_error ("expected check for address #%d (%s) to %s, but it didn't",
		         i, nm_utils_inet4_ntop (info->addresses[i], NULL),
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
	gs_unref_object NMAcdManager *manager = NULL;
	GMainLoop *loop;

	manager = nm_acd_manager_new (fixture->ifindex0, fixture->hwaddr0, fixture->hwaddr0_len);
	g_assert (manager != NULL);

	g_assert (nm_acd_manager_add_address (manager, ADDR1));
	g_assert (nm_acd_manager_add_address (manager, ADDR2));

	loop = g_main_loop_new (NULL, FALSE);
	nm_acd_manager_announce_addresses (manager);
	g_assert (!nmtst_main_loop_run (loop, 200));
	g_main_loop_unref (loop);
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
