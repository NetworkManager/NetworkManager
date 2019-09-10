// SPDX-License-Identifier: GPL-2.0+
/* ndisc.c - test program
 *
 * Copyright (C) 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <syslog.h>

#include "ndisc/nm-ndisc.h"
#include "ndisc/nm-lndp-ndisc.h"

#include "platform/nm-linux-platform.h"

#include "nm-test-utils-core.h"

NMTST_DEFINE ();

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	NMNDisc *ndisc;
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

	ndisc = nm_lndp_ndisc_new (NM_PLATFORM_GET,
	                           ifindex,
	                           ifname,
	                           NM_UTILS_STABLE_TYPE_UUID,
	                           "8ce666e8-d34d-4fb1-b858-f15a7al28086",
	                           NM_SETTING_IP6_CONFIG_ADDR_GEN_MODE_EUI64,
	                           NM_NDISC_NODE_TYPE_HOST,
	                           &error);
	if (!ndisc) {
		g_print ("Failed to create NMNDisc instance: %s\n", error->message);
		g_error_free (error);
		return EXIT_FAILURE;
	}

	iid.id_u8[7] = 1;
	nm_ndisc_set_iid (ndisc, iid);
	nm_ndisc_start (ndisc);
	g_main_loop_run (loop);

	g_clear_object (&ndisc);

	return EXIT_SUCCESS;
}
