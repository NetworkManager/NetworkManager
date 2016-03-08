/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* rdisc.c - test program
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
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <syslog.h>

#include "nm-rdisc.h"
#include "nm-lndp-rdisc.h"

#include "nm-linux-platform.h"

#include "nm-test-utils.h"

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	NMRDisc *rdisc;
	int ifindex = 1;
	const char *ifname;
	NMUtilsIPv6IfaceId iid = { };
	GError *error = NULL;

	nmtst_init_with_logging (&argc, &argv, NULL, "DEFAULT");

	if (getuid () != 0) {
		g_print ("Missing permission: must run as root\n");
		return EXIT_FAILURE;
	}

	loop = g_main_loop_new (NULL, FALSE);

	nm_linux_platform_setup ();

	if (argv[1]) {
		ifname = argv[1];
		ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, ifname);
	} else {
		g_print ("Missing command line argument \"interface-name\"\n");
		return EXIT_FAILURE;
	}

	rdisc = nm_lndp_rdisc_new (NM_PLATFORM_GET,
	                           ifindex,
	                           ifname,
	                           "8ce666e8-d34d-4fb1-b858-f15a7al28086",
	                           NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	                           &error);
	if (!rdisc) {
		g_print ("Failed to create NMRDisc instance: %s\n", error->message);
		g_error_free (error);
		return EXIT_FAILURE;
	}

	iid.id_u8[7] = 1;
	nm_rdisc_set_iid (rdisc, iid);
	nm_rdisc_start (rdisc);
	g_main_loop_run (loop);

	g_clear_object (&rdisc);

	return EXIT_SUCCESS;
}
