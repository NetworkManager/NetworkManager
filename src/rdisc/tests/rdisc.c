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

#include <string.h>
#include <syslog.h>

#include "nm-rdisc.h"
#include "nm-fake-rdisc.h"
#include "nm-lndp-rdisc.h"
#include "nm-logging.h"

#include "nm-fake-platform.h"
#include "nm-linux-platform.h"

int
main (int argc, char **argv)
{
	GMainLoop *loop;
	NMRDisc *rdisc;
	NMRDisc *(*new) (int ifindex, const char *ifname);
	int ifindex = 1;
	const char *ifname;
	char mac[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

#if !GLIB_CHECK_VERSION (2, 35, 0)
	g_type_init ();
#endif

	loop = g_main_loop_new (NULL, FALSE);
	nm_logging_setup ("debug", "ip6", NULL, NULL);
	openlog (G_LOG_DOMAIN, LOG_CONS | LOG_PERROR, LOG_DAEMON);

	argv++;
	if (!g_strcmp0 (argv[0], "--fake")) {
		new = nm_fake_rdisc_new;
		nm_fake_platform_setup ();
		argv++;
	} else {
		new = nm_lndp_rdisc_new;
		nm_linux_platform_setup ();
	}

	if (argv[0]) {
		ifname = argv[0];
		ifindex = nm_platform_link_get_ifindex (ifname);
	} else {
		ifindex = 1;
		ifname = nm_platform_link_get_name (ifindex);
	}

	rdisc = new (ifindex, ifname);
	if (!rdisc)
		return EXIT_FAILURE;

	nm_rdisc_set_lladdr (rdisc, mac, 6);

	nm_rdisc_start (rdisc);
	g_main_loop_run (loop);

	g_clear_object (&rdisc);

	return EXIT_SUCCESS;
}
