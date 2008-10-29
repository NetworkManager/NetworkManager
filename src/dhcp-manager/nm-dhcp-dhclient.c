/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* nm-dhcp-dhclient.c - dhclient specific hooks for NetworkManager
 *
 * Copyright (C) 2005 Dan Williams
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

#include <config.h>

#include "nm-dhcp-manager.h"
#include "nm-utils.h"


#define NM_DHCP_MANAGER_PID_FILENAME	"dhclient"
#define NM_DHCP_MANAGER_PID_FILE_EXT	"pid"

#define NM_DHCP_MANAGER_LEASE_FILENAME	"dhclient"
#define NM_DHCP_MANAGER_LEASE_FILE_EXT	"lease"

#define ACTION_SCRIPT_PATH	LIBEXECDIR "/nm-dhcp-client.action"


static char *
get_pidfile_for_iface (const char * iface)
{
	return g_strdup_printf ("%s/%s-%s.%s",
	                        NM_DHCP_MANAGER_RUN_DIR,
	                        NM_DHCP_MANAGER_PID_FILENAME,
	                        iface,
	                        NM_DHCP_MANAGER_PID_FILE_EXT);
}


static char *
get_leasefile_for_iface (const char * iface)
{
	return g_strdup_printf ("%s/%s-%s.%s",
	                        NM_DHCP_MANAGER_RUN_DIR,
	                        NM_DHCP_MANAGER_LEASE_FILENAME,
	                        iface,
	                        NM_DHCP_MANAGER_LEASE_FILE_EXT);
}



#define DHCP_CLIENT_ID_TAG "send dhcp-client-identifier"
#define DHCP_CLIENT_ID_FORMAT DHCP_CLIENT_ID_TAG " \"%s\"; # added by NetworkManager"

#define DHCP_HOSTNAME_TAG "send host-name"
#define DHCP_HOSTNAME_FORMAT DHCP_HOSTNAME_TAG " \"%s\"; # added by NetworkManager"

static gboolean
merge_dhclient_config (NMDHCPDevice *device,
                       NMSettingIP4Config *s_ip4,
                       const char *contents,
                       const char *orig,
                       GError **error)
{
	GString *new_contents;
	gboolean success = FALSE;

	g_return_val_if_fail (device != NULL, FALSE);
	g_return_val_if_fail (device->iface != NULL, FALSE);
	
	new_contents = g_string_new (_("# Created by NetworkManager\n"));

	/* Add existing options, if any, but ignore stuff NM will replace. */
	if (contents) {
		char **lines = NULL, **line;

		g_string_append_printf (new_contents, _("# Merged from %s\n\n"), orig);

		lines = g_strsplit_set (contents, "\n\r", 0);
		for (line = lines; lines && *line; line++) {
			gboolean ignore = FALSE;

			if (!strlen (g_strstrip (*line)))
				continue;

			if (   s_ip4
			    && nm_setting_ip4_config_get_dhcp_client_id (s_ip4)
			    && !strncmp (*line, DHCP_CLIENT_ID_TAG, strlen (DHCP_CLIENT_ID_TAG)))
				ignore = TRUE;

			if (   s_ip4
			    && nm_setting_ip4_config_get_dhcp_hostname (s_ip4)
			    && !strncmp (*line, DHCP_HOSTNAME_TAG, strlen (DHCP_HOSTNAME_TAG)))
				ignore = TRUE;

			if (!ignore) {
				g_string_append (new_contents, *line);
				g_string_append_c (new_contents, '\n');
			}
		}

		if (lines)
			g_strfreev (lines);
	} else
		g_string_append_c (new_contents, '\n');

	/* Add NM options from connection */
	if (s_ip4) {
		const char *tmp;

		tmp = nm_setting_ip4_config_get_dhcp_client_id (s_ip4);
		if (tmp)
			g_string_append_printf (new_contents, DHCP_CLIENT_ID_FORMAT "\n", tmp);

		tmp = nm_setting_ip4_config_get_dhcp_hostname (s_ip4);
		if (tmp)
			g_string_append_printf (new_contents, DHCP_HOSTNAME_FORMAT "\n", tmp);
	}

	if (g_file_set_contents (device->conf_file, new_contents->str, -1, error))
		success = TRUE;

	g_string_free (new_contents, TRUE);
	return success;
}

/* NM provides interface-specific options; thus the same dhclient config
 * file cannot be used since DHCP transactions can happen in parallel.
 * Since some distros don't have default per-interface dhclient config files,
 * read their single config file and merge that into a custom per-interface
 * config file along with the NM options.
 */
static gboolean
create_dhclient_config (NMDHCPDevice *device, NMSettingIP4Config *s_ip4)
{
	char *orig = NULL, *contents = NULL;
	GError *error = NULL;
	gboolean success = FALSE;
	char *tmp;

	g_return_val_if_fail (device != NULL, FALSE);

#if defined(TARGET_SUSE)
	orig = g_strdup (SYSCONFDIR "/dhclient.conf");
#elif defined(TARGET_DEBIAN)
	orig = g_strdup (SYSCONFDIR "/dhcp3/dhclient.conf");
#else
	orig = g_strdup_printf (SYSCONFDIR "/dhclient-%s.conf", device->iface);
#endif

	if (!orig) {
		nm_warning ("%s: not enough memory for dhclient options.", device->iface);
		return FALSE;
	}

	tmp = g_strdup_printf ("nm-dhclient-%s.conf", device->iface);
	device->conf_file = g_build_filename ("/var", "run", tmp, NULL);
	g_free (tmp);

	if (!g_file_test (orig, G_FILE_TEST_EXISTS))
		goto out;

	if (!g_file_get_contents (orig, &contents, NULL, &error)) {
		nm_warning ("%s: error reading dhclient configuration %s: %s",
		            device->iface, orig, error->message);
		g_error_free (error);
		goto out;
	}

out:
	error = NULL;
	if (merge_dhclient_config (device, s_ip4, contents, orig, &error))
		success = TRUE;
	else {
		nm_warning ("%s: error creating dhclient configuration: %s",
		            device->iface, error->message);
		g_error_free (error);
	}

	g_free (contents);
	g_free (orig);
	return success;
}


static void
dhclient_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}


gboolean
nm_dhcp_client_start (NMDHCPDevice *device, NMSettingIP4Config *s_ip4)
{
	GPtrArray *		dhclient_argv = NULL;
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
		nm_warning ("%s: not enough memory for dhclient options.", device->iface);
		goto out;
	}

	device->lease_file = get_leasefile_for_iface (device->iface);
	if (!device->lease_file) {
		nm_warning ("%s: not enough memory for dhclient options.", device->iface);
		goto out;
	}

	if (!create_dhclient_config (device, s_ip4))
		goto out;

	/* Kill any existing dhclient bound to this interface */
	if (g_file_get_contents (device->pid_file, &pid_contents, NULL, NULL)) {
		unsigned long int tmp = strtoul (pid_contents, NULL, 10);

		if (!((tmp == ULONG_MAX) && (errno == ERANGE)))
			nm_dhcp_client_stop (device->iface, (pid_t) tmp);
		remove (device->pid_file);
	}

	dhclient_argv = g_ptr_array_new ();
	g_ptr_array_add (dhclient_argv, (gpointer) DHCP_CLIENT_PATH);

	g_ptr_array_add (dhclient_argv, (gpointer) "-d");

	g_ptr_array_add (dhclient_argv, (gpointer) "-sf");	/* Set script file */
	g_ptr_array_add (dhclient_argv, (gpointer) ACTION_SCRIPT_PATH );

	g_ptr_array_add (dhclient_argv, (gpointer) "-pf");	/* Set pid file */
	g_ptr_array_add (dhclient_argv, (gpointer) device->pid_file);

	g_ptr_array_add (dhclient_argv, (gpointer) "-lf");	/* Set lease file */
	g_ptr_array_add (dhclient_argv, (gpointer) device->lease_file);

	g_ptr_array_add (dhclient_argv, (gpointer) "-cf");	/* Set interface config file */
	g_ptr_array_add (dhclient_argv, (gpointer) device->conf_file);

	g_ptr_array_add (dhclient_argv, (gpointer) device->iface);
	g_ptr_array_add (dhclient_argv, NULL);

	if (!g_spawn_async (NULL, (char **) dhclient_argv->pdata, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                    &dhclient_child_setup, NULL, &pid, &error)) {
		nm_warning ("dhclient failed to start.  error: '%s'", error->message);
		g_error_free (error);
		goto out;
	}

	nm_info ("dhclient started with pid %d", pid);

	device->pid = pid;
	success = TRUE;

out:
	g_free (pid_contents);
	g_ptr_array_free (dhclient_argv, TRUE);
	return success;
}
