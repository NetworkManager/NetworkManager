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

#include "devices/nm-arping-manager.h"
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
} test_fixture;

static void
fixture_setup (test_fixture *fixture, gconstpointer user_data)
{
	/* create veth pair. */
	fixture->ifindex0 = nmtstp_link_veth_add (NM_PLATFORM_GET, -1, IFACE_VETH0, IFACE_VETH1)->ifindex;
	fixture->ifindex1 = nmtstp_link_get_typed (NM_PLATFORM_GET, -1, IFACE_VETH1, NM_LINK_TYPE_VETH)->ifindex;

	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, fixture->ifindex0, NULL));
	g_assert (nm_platform_link_set_up (NM_PLATFORM_GET, fixture->ifindex1, NULL));
}

typedef struct {
	in_addr_t addresses[8];
	in_addr_t peer_addresses[8];
	gboolean expected_result[8];
} TestInfo;

static void
arping_manager_probe_terminated (NMArpingManager *arping_manager, GMainLoop *loop)
{
	g_main_loop_quit (loop);
}

static void
test_arping_common (test_fixture *fixture, TestInfo *info)
{
	gs_unref_object NMArpingManager *manager = NULL;
	GMainLoop *loop;
	int i;

	if (!nm_utils_find_helper ("arping", NULL, NULL)) {
		g_test_skip ("arping binary is missing");
		return;
	}

	manager = nm_arping_manager_new (fixture->ifindex0);
	g_assert (manager != NULL);

	for (i = 0; info->addresses[i]; i++)
		g_assert (nm_arping_manager_add_address (manager, info->addresses[i]));

	for (i = 0; info->peer_addresses[i]; i++) {
		nmtstp_ip4_address_add (NULL, FALSE, fixture->ifindex1, info->peer_addresses[i],
		                        24, 0, 3600, 1800, 0, NULL);
	}

	loop = g_main_loop_new (NULL, FALSE);
	g_signal_connect (manager, NM_ARPING_MANAGER_PROBE_TERMINATED,
	                  G_CALLBACK (arping_manager_probe_terminated), loop);
	g_assert (nm_arping_manager_start_probe (manager, 250, NULL));
	g_assert (nmtst_main_loop_run (loop, 2000));

	for (i = 0; info->addresses[i]; i++) {
		g_assert_cmpint (nm_arping_manager_check_address (manager, info->addresses[i]),
		                 ==,
		                 info->expected_result[i]);
	}

	g_main_loop_unref (loop);
}

static void
test_arping_1 (test_fixture *fixture, gconstpointer user_data)
{
	TestInfo info = { .addresses       = { ADDR1, ADDR2, ADDR3 },
	                  .peer_addresses  = { ADDR4 },
	                  .expected_result = { TRUE, TRUE, TRUE } };

	test_arping_common (fixture, &info);
}

static void
test_arping_2 (test_fixture *fixture, gconstpointer user_data)
{
	TestInfo info = { .addresses       = { ADDR1, ADDR2, ADDR3, ADDR4 },
	                  .peer_addresses  = { ADDR3, ADDR2 },
	                  .expected_result = { TRUE, FALSE, FALSE, TRUE } };

	test_arping_common (fixture, &info);
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
	g_test_add ("/arping/1", test_fixture, NULL, fixture_setup, test_arping_1, fixture_teardown);
	g_test_add ("/arping/2", test_fixture, NULL, fixture_setup, test_arping_2, fixture_teardown);
}
