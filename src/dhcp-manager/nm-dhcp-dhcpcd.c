/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
#include <netinet/in.h>
#include <arpa/inet.h>

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


GPid
nm_dhcp_client_start (NMDHCPDevice *device,
                      const char *uuid,
                      NMSettingIP4Config *s_ip4,
                      guint8 *dhcp_anycast_addr)
{
	GPtrArray *argv = NULL;
	GPid pid = 0;
	GError *error = NULL;
	char *pid_contents = NULL;

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
			nm_dhcp_client_stop (device, (pid_t) tmp);
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

	if (!g_spawn_async (NULL, (char **) argv->pdata, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                    &dhcpcd_child_setup, NULL, &pid, &error)) {
		nm_warning ("dhcpcd failed to start.  error: '%s'", error->message);
		g_error_free (error);
		goto out;
	}

	nm_info ("dhcpcd started with pid %d", pid);

out:
	g_free (pid_contents);
	g_ptr_array_free (argv, TRUE);
	return pid;
}

gboolean
nm_dhcp_client_process_classless_routes (GHashTable *options,
                                         NMIP4Config *ip4_config,
                                         guint32 *gwaddr)
{
	const char *str;
	char **routes, **r;
	gboolean have_routes = FALSE;

	/* Classless static routes over-ride any static routes and routers
	 * provided. We should also check for MS classless static routes as
	 * they implemented the draft RFC using their own code.
	 */
	str = g_hash_table_lookup (options, "new_classless_static_routes");
	if (!str)
		str = g_hash_table_lookup (options, "new_ms_classless_static_routes");

	if (!str || !strlen (str))
		return FALSE;

	routes = g_strsplit (str, " ", 0);
	if (g_strv_length (routes) == 0)
		goto out;

	if ((g_strv_length (routes) % 2) != 0) {
		nm_info ("  classless static routes provided, but invalid");
		goto out;
	}

	for (r = routes; *r; r += 2) {
		char *slash;
		NMIP4Route *route;
		int rt_cidr = 32;
		struct in_addr rt_addr;
		struct in_addr rt_route;

		slash = strchr(*r, '/');
		if (slash) {
			*slash = '\0';
			errno = 0;
			rt_cidr = strtol (slash + 1, NULL, 10);
			if ((errno == EINVAL) || (errno == ERANGE)) {
				nm_warning ("DHCP provided invalid classless static route cidr: '%s'", slash + 1);
				continue;
			}
		}
		if (inet_pton (AF_INET, *r, &rt_addr) <= 0) {
			nm_warning ("DHCP provided invalid classless static route address: '%s'", *r);
			continue;
		}
		if (inet_pton (AF_INET, *(r + 1), &rt_route) <= 0) {
			nm_warning ("DHCP provided invalid classless static route gateway: '%s'", *(r + 1));
			continue;
		}

		have_routes = TRUE;
		if (rt_cidr == 0 && rt_addr.s_addr == 0) {
			/* FIXME: how to handle multiple routers? */
			*gwaddr = rt_addr.s_addr;
		} else {
			route = nm_ip4_route_new ();
			nm_ip4_route_set_dest (route, (guint32) rt_addr.s_addr);
			nm_ip4_route_set_prefix (route, rt_cidr);
			nm_ip4_route_set_next_hop (route, (guint32) rt_route.s_addr);


			nm_ip4_config_take_route (ip4_config, route);
			nm_info ("  classless static route %s/%d gw %s", *r, rt_cidr, *(r + 1));
		}
	}

out:
	g_strfreev (routes);
	return have_routes;
}

