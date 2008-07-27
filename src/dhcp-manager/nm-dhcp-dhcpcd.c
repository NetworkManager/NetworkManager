/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* nm-dhcp-dhcpcd.c - dhcpcd specific hooks for NetworkManager
 *
 * Copyright (C) 2008 Roy Marples
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
 */


#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>

#include "nm-dhcp-manager.h"
#include "nm-utils.h"

#define NM_DHCP_MANAGER_PID_FILENAME	"dhcpcd"
#define NM_DHCP_MANAGER_PID_FILE_EXT	"pid"

#define ACTION_SCRIPT_PATH	LIBEXECDIR "/nm-dhcp-client.action"


static char *
get_pidfile_for_iface (const char * iface)
{
	return g_strdup_printf ("/var/run/%s-%s.%s",
	                        NM_DHCP_MANAGER_PID_FILENAME,
	                        iface,
	                        NM_DHCP_MANAGER_PID_FILE_EXT);
}


static void
dhcpcd_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}


gboolean
nm_dhcp_client_start (NMDHCPDevice *device, NMSettingIP4Config *s_ip4)
{
	GPtrArray *		argv = NULL;
	GPid			pid;
	GError *		error = NULL;
	gboolean		success = FALSE;
	char *			pid_contents = NULL;

	if (!g_file_test (DHCP_CLIENT_PATH, G_FILE_TEST_EXISTS)) {
		nm_warning (DHCP_CLIENT_PATH " does not exist.");
		goto out;
	}

	device->pid_file = get_pidfile_for_iface (device->iface);
	if (!device->pid_file) {
		nm_warning ("%s: not enough memory for dhcpcd options.", device->iface);
		goto out;
	}

	/* Kill any existing dhcpcd bound to this interface */
	if (g_file_get_contents (device->pid_file, &pid_contents, NULL, NULL)) {
		unsigned long int tmp = strtoul (pid_contents, NULL, 10);

		if (!((tmp == ULONG_MAX) && (errno == ERANGE)))
			nm_dhcp_client_stop (device->iface, (pid_t) tmp, TRUE);
		remove (device->pid_file);
	}

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) DHCP_CLIENT_PATH);

	g_ptr_array_add (argv, (gpointer) "-B");	/* Don't background on lease (disable fork()) */

	g_ptr_array_add (argv, (gpointer) "-K");	/* Disable built-in carrier detection */

	g_ptr_array_add (argv, (gpointer) "-L");	/* Disable built-in IPv4LL since we use avahi-autoipd */

	g_ptr_array_add (argv, (gpointer) "-c");	/* Set script file */
	g_ptr_array_add (argv, (gpointer) ACTION_SCRIPT_PATH );

	g_ptr_array_add (argv, (gpointer) device->iface);
	g_ptr_array_add (argv, NULL);

	if (!g_spawn_async (NULL, (char **) argv->pdata, NULL, 0,
	                    &dhcpcd_child_setup, NULL, &pid, &error)) {
		nm_warning ("dhcpcd failed to start.  error: '%s'", error->message);
		g_error_free (error);
		goto out;
	}

	nm_info ("dhcpcd started with pid %d", pid);

	device->pid = pid;
	success = TRUE;

out:
	g_free (pid_contents);
	g_ptr_array_free (argv, TRUE);
	return success;
}
