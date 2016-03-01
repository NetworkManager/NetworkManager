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
 * Copyright (C) 2016 Red Hat, Inc.
 */

#include "nm-default.h"

#include "sd-dhcp-client.h"
#include "sd-lldp.h"

#include "nm-test-utils.h"

/*****************************************************************************/

static void
test_dhcp_create (void)
{
	sd_dhcp_client *client4 = NULL;
	int r;

	r = sd_dhcp_client_new (&client4);
	g_assert (r == 0);
	g_assert (client4);

	sd_dhcp_client_unref (client4);
}

/*****************************************************************************/

static void
test_lldp_create (void)
{
	sd_lldp *lldp = NULL;
	int ifindex = 1;
	int r;

	r = sd_lldp_new (ifindex, "lo", (struct ether_addr *) ((guint8[]) { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }), &lldp);
	g_assert (r == 0);
	g_assert (lldp);

	sd_lldp_unref (lldp);
}

/*****************************************************************************/

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	nmtst_init_assert_logging (&argc, &argv, "INFO", "ALL");

	g_test_add_func ("/systemd/dhcp/create", test_dhcp_create);
	g_test_add_func ("/systemd/lldp/create", test_lldp_create);

	return g_test_run ();
}
