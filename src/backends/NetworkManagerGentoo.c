/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 * Dan Willemsen <dan@willemsen.us>
 * Robert Paskowitz
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * (C) Copyright 2004 Red Hat, Inc.
 * (C) Copyright 2004 Dan Willemsen
 * (C) Copyright 2004 Robert Paskowitz
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gio/gio.h>

#include "NetworkManagerGeneric.h"
#include "nm-system.h"
#include "NetworkManagerUtils.h"
#include "nm-logging.h"

#define BUFFER_SIZE 512

static void openrc_start_lo_if_necessary() 
{
	/* No need to run net.lo if it is already running */
        if (nm_spawn_process ("/etc/init.d/net.lo status") != 0)
                nm_spawn_process ("/etc/init.d/net.lo start");
}

/*
 * nm_system_enable_loopback
 *
 * Bring up the loopback interface
 *
 */
void nm_system_enable_loopback (void)
{
	gchar *comm;

	/* If anything goes wrong trying to open /proc/1/comm, we will assume
	   OpenRC. */
	if (!g_file_get_contents ("/proc/1/comm", &comm, NULL, NULL)) {
		nm_log_info (LOGD_CORE, "NetworkManager is running with OpenRC...");
		openrc_start_lo_if_necessary ();
		return;
	}

	if (g_strstr_len (comm, -1, "systemd")) {
		/* We use the generic loopback enabler if using systemd. */
		nm_log_info (LOGD_CORE, "NetworkManager is running with systemd...");
		nm_generic_enable_loopback ();
	} else {
		/* OpenRC otherwise. */
		nm_log_info (LOGD_CORE, "NetworkManager is running with OpenRC...");
		openrc_start_lo_if_necessary();
	}

	g_free (comm);
}

/*
 * nm_system_update_dns
 *
 * Make glibc/nscd aware of any changes to the resolv.conf file by
 * restarting nscd. Only restart if already running.
 *
 */
void nm_system_update_dns (void)
{
	if (g_file_test ("/usr/sbin/nscd", G_FILE_TEST_IS_EXECUTABLE)) {
		nm_log_info (LOGD_DNS, "Clearing nscd hosts cache.");
		nm_spawn_process ("/usr/sbin/nscd -i hosts");
	}
}

